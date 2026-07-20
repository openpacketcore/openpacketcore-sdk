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
//! - Load/attach: Linux >= 5.4 with kernel BTF (`/sys/kernel/btf/vmlinux`),
//!   XDP, bpffs map pinning, per-CPU arrays, `bpf_redirect`,
//!   `bpf_xdp_load_bytes`, plus effective `CAP_NET_ADMIN` and
//!   `CAP_BPF`/`CAP_SYS_ADMIN`.
//! - Graceful program replacement: Linux >= 5.7 (netlink
//!   `XDP_FLAGS_REPLACE` + `IFLA_XDP_EXPECTED_FD`) or >= 5.9 (XDP `bpf_link`
//!   update). Replacement attaches the new program atomically while adopting
//!   the pinned maps, so there is no window of dropped or mis-verdicted
//!   traffic; a schema-incompatible pinned map fails the replacement load
//!   before anything is detached.
//!
//! Owner-map updates write the whole 16-byte value with one
//! `bpf_map_update_elem` call. On the kernels within the floor that
//! replacement is atomic in practice, but the ABI does not rely on it: the
//! strict value decode rejects non-zero flags/reserved bytes and zero
//! generations, so a theoretically torn read fails closed to the slow path
//! with the error counter rather than steering on a corrupted pair.
//!
//! The ownership fence generation lives in its own single-slot aligned-`u64`
//! map, so fence advances are tear-free single stores. Attach adopts pinned
//! maps across process restarts but flushes the owner map and rewrites the
//! config before the program is attached; the persisted fence is honored so
//! entries installed by a crashed owner cannot be re-armed.
//!
//! A stale pinned-map schema (for example from an older SDK revision) fails
//! the object load with an `xdp_object_load` I/O error; the recovery path is
//! to remove the interface's bpffs pin directory and re-attach.

use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use opc_ipsec_lb_ebpf_common::{
    XdpDatapathConfig, XdpOwnerValue, CONFIG_VALUE_LEN, COUNTER_ERROR, COUNTER_LOCAL, COUNTER_MISS,
    COUNTER_NATT_KEEPALIVE, COUNTER_PASS_NON_SWU, COUNTER_REDIRECT, COUNTER_SLOTS, COUNTER_STALE,
    COUNTER_UNCLASSIFIABLE, MAP_CONFIG, MAP_COUNTERS, MAP_FENCE, MAP_OWNERS,
    OWNERSHIP_KEY_MAX_ENCODED_BYTES, OWNER_KEY_LEN, OWNER_VALUE_LEN, PROG_SWU_XDP,
    XDP_MIN_KERNEL_RELEASE, XDP_MIN_KERNEL_REPLACE_RELEASE,
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
    /// bpffs is available for map pinning.
    pub bpffs_present: bool,
    /// Kernel BTF is exposed at `/sys/kernel/btf/vmlinux`.
    pub btf_present: bool,
    /// `CAP_NET_ADMIN` is effective.
    pub net_admin_capable: bool,
    /// `CAP_BPF` or `CAP_SYS_ADMIN` is effective.
    pub bpf_capable: bool,
    /// Running kernel release (major, minor), when it can be determined.
    pub kernel_release: Option<(u16, u16)>,
}

/// Narrow synchronous port to the kernel XDP machinery.
pub(crate) trait HostXdpRuntime: Send + Sync + fmt::Debug {
    /// Resolve an interface index by name in the current netns.
    fn ifindex_by_name(&self, name: &str) -> Result<u32, IpsecLbError>;

    /// Report whether `ifindex` names an existing interface that is
    /// administratively up in the current netns.
    fn link_is_up(&self, ifindex: u32) -> Result<bool, IpsecLbError>;

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
    ) -> Result<(), IpsecLbError>;

    /// Atomically replace the attached XDP program, adopting the pinned maps.
    ///
    /// On failure the implementation drops its device record so a later
    /// attach re-establishes the datapath instead of early-Ok-ing on a wedged
    /// program.
    fn replace(
        &self,
        interface: &str,
        ifindex: u32,
        pin_dir: &Path,
        config: [u8; CONFIG_VALUE_LEN],
    ) -> Result<(), IpsecLbError>;

    /// Detach the XDP program and remove pins owned by this backend.
    fn detach(&self, interface: &str, ifindex: u32, pin_dir: &Path) -> Result<(), IpsecLbError>;

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
    fn probe_environment(&self) -> HostXdpEnvironment;
}

/// Explicit channel for packets owned by a remote shard.
///
/// The authenticated steering encapsulation cannot be built in the kernel
/// (AEAD crypto is a userspace concern), so the only fast-path channel is an
/// observable hand-off to the userspace redirector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostXdpRedirectHandoff {
    /// `XDP_REDIRECT` remote-owned packets into a dedicated interface whose
    /// peer is captured by the userspace redirector, which applies the
    /// authenticated steering encapsulation (`crate::redirect`) and forwards
    /// toward the owner.
    ///
    /// Deployment note: when the program is attached in native (driver) mode
    /// and the hand-off interface is a veth, the kernel only delivers
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
            Self::UserspaceRedirector { ifindex } => ifindex.get(),
        }
    }
}

/// XDP attach mode for the datapath program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostXdpAttachMode {
    /// Ask the kernel for native (driver) mode. The kernel falls back to
    /// generic mode only when the device lacks XDP support entirely; devices
    /// that support native mode — including veth — are attached natively.
    /// Native mode is the line-rate tier but only delivers `XDP_REDIRECT`
    /// frames into a veth when the peer runs an XDP consumer, so a veth
    /// hand-off interface without a peer program needs
    /// [`HostXdpAttachMode::Generic`]. No automatic mode downgrade happens
    /// after attach.
    #[default]
    Native,
    /// Generic (SKB) mode, executed by the kernel network stack. Redirect
    /// into a veth hand-off delivers to the peer stack without a peer
    /// program. This is the interoperable choice for veth topologies.
    Generic,
}

/// Host-XDP backend configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostXdpSteeringBackendConfig {
    /// bpffs directory under which per-interface pin directories are created.
    pub bpffs_pin_root: PathBuf,
    /// Shard identity of this node; entries owned by it pass locally.
    pub self_shard: ShardId,
    /// Routing-domain tag mixed into every ownership key. Installed owner
    /// records must carry the same tag.
    pub routing_domain: RoutingDomainTag,
    /// Channel for remote-owned packets.
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
            redirect_handoff: HostXdpRedirectHandoff::UserspaceRedirector {
                ifindex: NonZeroU32::MIN,
            },
            attach_mode: HostXdpAttachMode::default(),
        }
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
    state: Mutex<HostXdpState>,
}

#[derive(Debug, Default)]
struct HostXdpState {
    attached_ifindex: Option<u32>,
    attached_mode: Option<HostXdpAttachMode>,
    current_fence: u64,
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
            .field("interface", &self.inner.interface)
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

    /// Gracefully replace the attached XDP program with the committed object.
    ///
    /// The new program adopts the pinned maps and is swapped onto the hook
    /// atomically (netlink compare-and-replace or `bpf_link` update), so there
    /// is no window of dropped or mis-verdicted traffic. Requires the
    /// documented replacement kernel floor; a schema-incompatible pinned map
    /// fails before anything is detached.
    pub async fn replace(&self) -> Result<(), IpsecLbError> {
        self.run_blocking("host_xdp_replace", |backend| backend.replace_sync())
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
        validate_interface_name(&self.inner.interface)?;
        if let Some(ifindex) = self.state()?.attached_ifindex {
            return Ok(ifindex);
        }
        enforce_kernel_floor(&self.inner.runtime.probe_environment())?;
        let ifindex = self.inner.runtime.ifindex_by_name(&self.inner.interface)?;
        if ifindex == 0 {
            return Err(IpsecLbError::invalid_config(
                "interface.ifindex",
                "ifindex must be nonzero",
            ));
        }
        self.validate_handoff_ifindex(ifindex)?;
        // The runtime flushes adopted owner pins and writes the config before
        // attaching the program, so the datapath never verdicts with a
        // previous process's state. The fence map is deliberately not
        // rewritten: a persisted fence survives process restarts.
        self.inner.runtime.attach(
            &self.inner.interface,
            ifindex,
            &self.pin_dir(),
            self.inner.config.attach_mode,
            self.datapath_config(),
        )?;
        let persisted_fence = self.inner.runtime.fence_read(ifindex)?;
        let mut state = self.state()?;
        if persisted_fence > state.current_fence {
            state.current_fence = persisted_fence;
        }
        state.attached_ifindex = Some(ifindex);
        state.attached_mode = Some(self.inner.config.attach_mode);
        Ok(ifindex)
    }

    fn detach_sync(&self) -> Result<(), IpsecLbError> {
        validate_interface_name(&self.inner.interface)?;
        let Some(ifindex) = self.state()?.attached_ifindex else {
            return Ok(());
        };
        self.inner
            .runtime
            .detach(&self.inner.interface, ifindex, &self.pin_dir())?;
        let mut state = self.state()?;
        state.attached_ifindex = None;
        state.attached_mode = None;
        Ok(())
    }

    fn replace_sync(&self) -> Result<(), IpsecLbError> {
        validate_interface_name(&self.inner.interface)?;
        let Some(ifindex) = self.state()?.attached_ifindex else {
            return Err(IpsecLbError::NotFound);
        };
        let environment = self.inner.runtime.probe_environment();
        enforce_kernel_floor(&environment)?;
        if !kernel_release_at_least(environment.kernel_release, XDP_MIN_KERNEL_REPLACE_RELEASE) {
            return Err(IpsecLbError::xdp_kernel_floor(
                "kernel >= 5.7 for atomic XDP program replacement",
            ));
        }
        let result = self.inner.runtime.replace(
            &self.inner.interface,
            ifindex,
            &self.pin_dir(),
            self.datapath_config(),
        );
        if result.is_err() {
            // The runtime dropped its device record; clear our attach state so
            // a later attach() re-establishes the datapath instead of
            // early-Ok-ing on a wedged program.
            let mut state = self.state()?;
            state.attached_ifindex = None;
            state.attached_mode = None;
        }
        result
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
        let ifindex = self.ensure_attached_sync()?;
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
        let ifindex = self.ensure_attached_sync()?;
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
        let map_key = owner_map_key(key);
        let Some(ifindex) = self.state()?.attached_ifindex else {
            return Err(IpsecLbError::NotFound);
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
        let ifindex = self.ensure_attached_sync()?;
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
        let Some(ifindex) = self.state()?.attached_ifindex else {
            return Err(IpsecLbError::NotFound);
        };
        let slots = self.inner.runtime.counters_read(ifindex)?;
        Ok(XdpVerdictCounters::from_slots(&slots))
    }

    fn probe_sync(&self) -> SteeringProbe {
        let env = self.inner.runtime.probe_environment();
        let floor_met = kernel_release_at_least(env.kernel_release, XDP_MIN_KERNEL_RELEASE);
        let mutation_ready = env.platform_supported
            && env.bpffs_present
            && env.btf_present
            && env.net_admin_capable
            && env.bpf_capable
            && floor_met;
        let details = if !env.platform_supported {
            Some("Host-XDP steering unsupported on this platform")
        } else if !floor_met {
            Some("kernel release is below the Host-XDP feature floor")
        } else if !env.bpffs_present {
            Some("bpffs is not available for map pinning")
        } else if !env.btf_present {
            Some("kernel BTF is not present")
        } else if !env.net_admin_capable {
            Some("CAP_NET_ADMIN is not effective")
        } else if !env.bpf_capable {
            Some("CAP_BPF or CAP_SYS_ADMIN is not effective")
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
            "kernel >= 5.4 with XDP, pinned maps, per-CPU arrays, and bpf_redirect",
        ));
    }
    if !environment.btf_present {
        return Err(IpsecLbError::xdp_kernel_floor(
            "kernel BTF exposed at /sys/kernel/btf/vmlinux",
        ));
    }
    if !environment.bpffs_present {
        return Err(IpsecLbError::xdp_kernel_floor(
            "bpffs mounted for pinned maps",
        ));
    }
    if !environment.net_admin_capable || !environment.bpf_capable {
        return Err(IpsecLbError::xdp_kernel_floor(
            "effective CAP_NET_ADMIN and CAP_BPF or CAP_SYS_ADMIN",
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
    fn ifindex_by_name(&self, _name: &str) -> Result<u32, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn link_is_up(&self, _ifindex: u32) -> Result<bool, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn attach(
        &self,
        _interface: &str,
        _ifindex: u32,
        _pin_dir: &Path,
        _mode: HostXdpAttachMode,
        _config: [u8; CONFIG_VALUE_LEN],
    ) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn replace(
        &self,
        _interface: &str,
        _ifindex: u32,
        _pin_dir: &Path,
        _config: [u8; CONFIG_VALUE_LEN],
    ) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn detach(&self, _interface: &str, _ifindex: u32, _pin_dir: &Path) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
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

    fn probe_environment(&self) -> HostXdpEnvironment {
        HostXdpEnvironment::default()
    }
}

#[cfg(target_os = "linux")]
mod aya_runtime {
    //! aya-based Host-XDP runtime.

    use std::collections::BTreeMap;
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::sync::Mutex;

    use aya::maps::{Array, HashMap as BpfHashMap, MapError, PerCpuArray};
    use aya::programs::xdp::XdpLinkId;
    use aya::programs::{ProgramError, Xdp, XdpMode};
    use aya::{Ebpf, EbpfLoader};
    use opc_linux_gtpu_sys as sys;

    use super::{
        HostXdpAttachMode, HostXdpEnvironment, HostXdpRuntime, CONFIG_VALUE_LEN, COUNTER_SLOTS,
        MAP_CONFIG, MAP_COUNTERS, MAP_FENCE, MAP_OWNERS, OWNER_KEY_LEN, OWNER_VALUE_LEN,
        PROG_SWU_XDP,
    };
    use crate::IpsecLbError;

    const DATAPATH_OBJECT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf/opc-ipsec-lb-xdp.bpf.o"
    ));

    const CAP_NET_ADMIN: u32 = 12;
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_BPF: u32 = 39;

    #[derive(Debug, Default)]
    pub(super) struct AyaHostXdpRuntime {
        devices: Mutex<BTreeMap<u32, LoadedDevice>>,
    }

    #[derive(Debug)]
    struct LoadedDevice {
        ebpf: Ebpf,
        link_id: Option<XdpLinkId>,
        mode: HostXdpAttachMode,
    }

    impl AyaHostXdpRuntime {
        pub(super) fn new() -> Self {
            Self::default()
        }

        fn load_pinned(pin_dir: &Path) -> Result<Ebpf, IpsecLbError> {
            fs::create_dir_all(pin_dir)
                .map_err(|error| IpsecLbError::io("xdp_pin_dir_create", error))?;
            EbpfLoader::new()
                .default_map_pin_directory(pin_dir)
                .load(DATAPATH_OBJECT)
                .map_err(|_| {
                    IpsecLbError::io(
                        "xdp_object_load",
                        invalid_data(
                            "XDP object load failed; a stale pinned-map schema requires removing the interface's bpffs pin directory",
                        ),
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
            Ok(())
        }

        fn config_write_map(
            ebpf: &mut Ebpf,
            value: [u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let map = ebpf
                .map_mut(MAP_CONFIG)
                .ok_or_else(|| IpsecLbError::io("xdp_config_map", invalid_data("map missing")))?;
            let mut array = Array::<_, [u8; CONFIG_VALUE_LEN]>::try_from(map)
                .map_err(|error| map_error("xdp_config_map", error))?;
            array
                .set(0, value, 0)
                .map_err(|error| map_error("xdp_config_write", error))
        }

        fn fence_array(
            ebpf: &mut Ebpf,
        ) -> Result<Array<&mut aya::maps::MapData, u64>, IpsecLbError> {
            let map = ebpf
                .map_mut(MAP_FENCE)
                .ok_or_else(|| IpsecLbError::io("xdp_fence_map", invalid_data("map missing")))?;
            Array::<_, u64>::try_from(map).map_err(|error| map_error("xdp_fence_map", error))
        }

        fn unpin(pin_dir: &Path) -> Result<(), IpsecLbError> {
            for map_name in [MAP_OWNERS, MAP_CONFIG, MAP_FENCE, MAP_COUNTERS] {
                match fs::remove_file(pin_dir.join(map_name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(IpsecLbError::io("xdp_map_unpin", error)),
                }
            }
            match fs::remove_dir(pin_dir) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(IpsecLbError::io("xdp_pin_dir_remove", error)),
            }
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
            f(device)
        }
    }

    impl HostXdpRuntime for AyaHostXdpRuntime {
        fn ifindex_by_name(&self, name: &str) -> Result<u32, IpsecLbError> {
            sys::ifindex_by_name(name).map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => IpsecLbError::NotFound,
                _ => IpsecLbError::io("ifindex_lookup", error),
            })
        }

        fn link_is_up(&self, ifindex: u32) -> Result<bool, IpsecLbError> {
            link_is_up(ifindex)
        }

        fn attach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            mode: HostXdpAttachMode,
            config: [u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            if let Some(device) = self
                .devices
                .lock()
                .map_err(|_| IpsecLbError::io("xdp_attach", super::poisoned_lock()))?
                .get(&ifindex)
            {
                return if device.mode == mode {
                    Ok(())
                } else {
                    Err(IpsecLbError::invalid_config(
                        "interface.attach_mode",
                        "interface is already attached with a different XDP mode",
                    ))
                };
            }
            let pins_preexisted = pin_dir.is_dir();
            let mut ebpf = Self::load_pinned(pin_dir)?;
            let attach_result = (|| {
                if pins_preexisted {
                    // Never re-arm a previous process's owners: the fenced
                    // ownership authority re-installs fresh records.
                    Self::owners_flush_map(&mut ebpf)?;
                }
                // Write the config before the program sees traffic.
                Self::config_write_map(&mut ebpf, config)?;
                let program = Self::xdp_program(&mut ebpf)?;
                program
                    .load()
                    .map_err(|error| program_error("xdp_program_load", &error))?;
                let xdp_mode = match mode {
                    HostXdpAttachMode::Native => XdpMode::default(),
                    HostXdpAttachMode::Generic => XdpMode::Skb,
                };
                program
                    .attach(interface, xdp_mode)
                    .map_err(|error| program_error("xdp_program_attach", &error))
            })();
            let link_id = match attach_result {
                Ok(link_id) => link_id,
                Err(error) => {
                    drop(ebpf);
                    if !pins_preexisted {
                        let _ = Self::unpin(pin_dir);
                    }
                    return Err(error);
                }
            };
            self.devices
                .lock()
                .map_err(|_| IpsecLbError::io("xdp_attach", super::poisoned_lock()))?
                .insert(
                    ifindex,
                    LoadedDevice {
                        ebpf,
                        link_id: Some(link_id),
                        mode,
                    },
                );
            Ok(())
        }

        fn replace(
            &self,
            _interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            config: [u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let mut new_ebpf = Self::load_pinned(pin_dir)?;
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| IpsecLbError::io("xdp_replace", super::poisoned_lock()))?;
            let device = devices.get_mut(&ifindex).ok_or(IpsecLbError::NotFound)?;
            let replace_result = (|| {
                let new_program = Self::xdp_program(&mut new_ebpf)?;
                new_program
                    .load()
                    .map_err(|error| program_error("xdp_program_load", &error))?;
                let old_program = Self::xdp_program(&mut device.ebpf)?;
                let link_id = device
                    .link_id
                    .take()
                    .ok_or_else(|| IpsecLbError::io("xdp_replace", invalid_data("link missing")))?;
                // On any failure after this point the device record is
                // dropped below, so the taken link id needs no restoration.
                let link = old_program
                    .take_link(link_id)
                    .map_err(|error| program_error("xdp_link_take", &error))?;
                match new_program.attach_to_link(link) {
                    Ok(new_link_id) => {
                        device.link_id = Some(new_link_id);
                        Ok(())
                    }
                    Err(error) => Err(program_error("xdp_program_replace", &error)),
                }
            })();
            match replace_result {
                Ok(()) => {
                    Self::config_write_map(&mut new_ebpf, config)?;
                    device.ebpf = new_ebpf;
                    Ok(())
                }
                Err(error) => {
                    // Never wedge on a failed replacement: drop the device
                    // record so a later attach re-establishes the datapath.
                    devices.remove(&ifindex);
                    Err(error)
                }
            }
        }

        fn detach(
            &self,
            _interface: &str,
            ifindex: u32,
            pin_dir: &Path,
        ) -> Result<(), IpsecLbError> {
            let held = self
                .devices
                .lock()
                .map_err(|_| IpsecLbError::io("xdp_detach", super::poisoned_lock()))?
                .remove(&ifindex);
            drop(held);
            Self::unpin(pin_dir)
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
                let array = Self::fence_array(&mut device.ebpf)?;
                array
                    .get(&0, 0)
                    .map_err(|error| map_error("xdp_fence_read", error))
            })
        }

        fn fence_write(&self, ifindex: u32, generation: u64) -> Result<(), IpsecLbError> {
            self.with_device(ifindex, "xdp_fence_write", |device| {
                let mut array = Self::fence_array(&mut device.ebpf)?;
                array
                    .set(0, generation, 0)
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

        fn probe_environment(&self) -> HostXdpEnvironment {
            HostXdpEnvironment {
                platform_supported: true,
                bpffs_present: Path::new("/sys/fs/bpf").is_dir(),
                btf_present: Path::new("/sys/kernel/btf/vmlinux").exists(),
                net_admin_capable: effective_capability(CAP_NET_ADMIN).unwrap_or(false),
                bpf_capable: effective_capability(CAP_BPF).unwrap_or(false)
                    || effective_capability(CAP_SYS_ADMIN).unwrap_or(false),
                kernel_release: kernel_release(),
            }
        }
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
    const NLMSG_DONE: u16 = 3;
    const NLMSG_ERROR: u16 = 2;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    const IFF_UP: u32 = 0x1;
    const NLMSG_HDR_LEN: usize = 16;
    const IFINFOMSG_LEN: usize = 16;

    /// Report whether `ifindex` names an existing interface that is
    /// administratively up, via an `RTM_GETLINK` dump in the current netns.
    fn link_is_up(ifindex: u32) -> Result<bool, IpsecLbError> {
        let socket = sys::open_route_netlink_socket()
            .map_err(|error| IpsecLbError::io("xdp_link_query_open", error))?;
        let mut request = [0_u8; NLMSG_HDR_LEN + IFINFOMSG_LEN];
        let request_len = request.len() as u32;
        request[0..4].copy_from_slice(&request_len.to_ne_bytes());
        request[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
        request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        sys::send_message(&socket, &request)
            .map_err(|error| IpsecLbError::io("xdp_link_query_send", error))?;

        let mut buffer = [0_u8; 65_536];
        let mut attempts = 0_u32;
        loop {
            match sys::receive_message(&socket, &mut buffer) {
                Ok(length) => {
                    let mut cursor = 0_usize;
                    while cursor + NLMSG_HDR_LEN <= length {
                        let header: [u8; NLMSG_HDR_LEN] = buffer[cursor..cursor + NLMSG_HDR_LEN]
                            .try_into()
                            .map_err(|_| {
                                IpsecLbError::io("xdp_link_query", invalid_data("short header"))
                            })?;
                        let msg_len =
                            u32::from_ne_bytes(header[0..4].try_into().unwrap_or([0; 4])) as usize;
                        let msg_type =
                            u16::from_ne_bytes(header[4..6].try_into().unwrap_or([0; 2]));
                        if msg_len < NLMSG_HDR_LEN || cursor + msg_len > length {
                            return Err(IpsecLbError::io(
                                "xdp_link_query",
                                invalid_data("malformed netlink message"),
                            ));
                        }
                        match msg_type {
                            NLMSG_DONE => return Ok(false),
                            NLMSG_ERROR => {
                                return Err(IpsecLbError::io(
                                    "xdp_link_query",
                                    invalid_data("netlink link dump failed"),
                                ));
                            }
                            RTM_NEWLINK if msg_len >= NLMSG_HDR_LEN + IFINFOMSG_LEN => {
                                let body = &buffer[cursor + NLMSG_HDR_LEN..];
                                let index =
                                    i32::from_ne_bytes(body[4..8].try_into().unwrap_or([0; 4]));
                                let flags =
                                    u32::from_ne_bytes(body[8..12].try_into().unwrap_or([0; 4]));
                                if index > 0 && index as u32 == ifindex {
                                    return Ok(flags & IFF_UP != 0);
                                }
                            }
                            _ => {}
                        }
                        cursor += msg_len.div_ceil(4) * 4;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    attempts += 1;
                    if attempts > 50 {
                        return Err(IpsecLbError::io("xdp_link_query_recv", error));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(error) => return Err(IpsecLbError::io("xdp_link_query_recv", error)),
            }
        }
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
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::NonZeroU32;

    use super::*;
    use crate::model::IpAddress;
    use crate::ownership::{
        DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi,
        EstablishedIkeOwnershipKey, IkeSpi,
    };

    #[derive(Debug, Default)]
    struct TestRuntime {
        state: Mutex<TestState>,
    }

    #[derive(Debug)]
    struct TestState {
        ifindex: u32,
        env: HostXdpEnvironment,
        attached: Vec<(String, u32, PathBuf)>,
        replaced: Vec<(String, u32, PathBuf)>,
        detached: Vec<(String, u32, PathBuf)>,
        config: Option<[u8; CONFIG_VALUE_LEN]>,
        owners: HashMap<(u32, [u8; OWNER_KEY_LEN]), [u8; OWNER_VALUE_LEN]>,
        fences: HashMap<u32, u64>,
        fence_writes: Vec<u64>,
        link_up: bool,
        replace_error: Option<&'static str>,
        counters: [u64; COUNTER_SLOTS as usize],
    }

    impl Default for TestState {
        fn default() -> Self {
            Self {
                ifindex: 7,
                env: HostXdpEnvironment {
                    platform_supported: true,
                    bpffs_present: true,
                    btf_present: true,
                    net_admin_capable: true,
                    bpf_capable: true,
                    kernel_release: Some((6, 1)),
                },
                attached: Vec::new(),
                replaced: Vec::new(),
                detached: Vec::new(),
                config: None,
                owners: HashMap::new(),
                fences: HashMap::new(),
                fence_writes: Vec::new(),
                link_up: true,
                replace_error: None,
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
            }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, TestState> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }
    }

    impl HostXdpRuntime for TestRuntime {
        fn ifindex_by_name(&self, _name: &str) -> Result<u32, IpsecLbError> {
            Ok(self.state().ifindex)
        }

        fn link_is_up(&self, _ifindex: u32) -> Result<bool, IpsecLbError> {
            Ok(self.state().link_up)
        }

        fn attach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            _mode: HostXdpAttachMode,
            config: [u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let mut state = self.state();
            state
                .attached
                .push((interface.to_owned(), ifindex, pin_dir.to_path_buf()));
            state.config = Some(config);
            Ok(())
        }

        fn replace(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            config: [u8; CONFIG_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            let mut state = self.state();
            if let Some(operation) = state.replace_error {
                return Err(IpsecLbError::io(
                    operation,
                    io::Error::new(io::ErrorKind::InvalidData, "injected replace failure"),
                ));
            }
            state
                .replaced
                .push((interface.to_owned(), ifindex, pin_dir.to_path_buf()));
            state.config = Some(config);
            Ok(())
        }

        fn detach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
        ) -> Result<(), IpsecLbError> {
            self.state()
                .detached
                .push((interface.to_owned(), ifindex, pin_dir.to_path_buf()));
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
            Ok(self.state().fences.get(&ifindex).copied().unwrap_or(0))
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

        fn probe_environment(&self) -> HostXdpEnvironment {
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
    async fn kernel_floor_is_enforced_with_typed_errors() {
        let mut env = TestState::default().env;

        env.kernel_release = Some((5, 3));
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
        env.bpffs_present = false;
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
    async fn failed_replace_clears_state_so_attach_recovers() {
        let runtime = Arc::new(TestRuntime::default());
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.attach().await.expect("attach");
        assert_eq!(runtime.state().attached.len(), 1);

        runtime.state().replace_error = Some("xdp_program_replace");
        let error = backend.replace().await.expect_err("injected failure");
        assert_eq!(error.raw_os_error(), None);

        // The backend must not early-Ok on the wedged state: attach
        // re-establishes the datapath and a retry succeeds.
        backend.attach().await.expect("re-attach");
        assert_eq!(runtime.state().attached.len(), 2);
        runtime.state().replace_error = None;
        backend.replace().await.expect("replace retry");
        assert_eq!(runtime.state().replaced.len(), 1);
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
    async fn replace_requires_attach_and_replacement_floor() {
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            Arc::new(TestRuntime::default()),
            config(),
        );
        assert_eq!(backend.replace().await, Err(IpsecLbError::NotFound));

        let mut env = TestState::default().env;
        env.kernel_release = Some((5, 6));
        let runtime = Arc::new(TestRuntime::with_env(env));
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.attach().await.expect("attach");
        assert!(matches!(
            backend.replace().await,
            Err(IpsecLbError::XdpKernelFloorNotMet { .. })
        ));

        let runtime = Arc::new(TestRuntime::default());
        let backend =
            HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime.clone(), config());
        backend.attach().await.expect("attach");
        backend.replace().await.expect("replace");
        assert_eq!(runtime.state().replaced.len(), 1);
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
