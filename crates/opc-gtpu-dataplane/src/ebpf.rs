//! eBPF tc GTP-U datapath backend for access-gateway (ePDG/UPF-style) roles.
//!
//! The mainline `gtp` netdevice only encapsulates toward a subscriber whose
//! address matches the packet's *destination* (the GGSN/PGW downlink model).
//! An access gateway must encapsulate the subscriber's *uplink* (inner source
//! = UE PAA, destination = arbitrary host), which that module cannot do. This
//! backend instead drives a pair of tc `clsact` eBPF programs on the PGW-facing
//! (S2b-U) interface:
//!
//! - **egress** (`opc_gtpu_uplink`): looks up the uplink FAR by the inner IPv4
//!   source and prepends `[outer IPv4][UDP][GTPv1-U]` toward the PGW peer.
//! - **ingress** (`opc_gtpu_downlink`): matches GTPv1-U G-PDUs on UDP/2152,
//!   looks up the downlink PDR by TEID, strips the outer headers, and lets the
//!   inner packet continue up the stack (through XFRM policy toward the UE).
//!
//! `create_device` does **not** create a netdevice: it attaches the programs
//! to the existing interface named in the request and pins the session maps
//! under a bpffs directory so state survives process restarts.
//! `resolve_device` adopts a previously provisioned interface (HA restore).
//! PDP-context installs/removals are pure BPF map upserts/deletes and are
//! idempotent.
//!
//! Only IPv4 is supported for the outer transport and the UE PAA; IPv6
//! requests are rejected as invalid configuration.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use opc_gtpu_ebpf_common::{
    DownlinkEndpointBinding, DownlinkPdr, GtpuEndpointAddress, GtpuUplinkMtuPolicy,
    MarkedBearerOwner, MarkedBearerOwnerPhase, MarkedDownlinkPdr, PdpContextCommit, UplinkFar,
    UplinkFarKey, UplinkMtuMapState, DOWNLINK_ENDPOINT_BINDING_VALUE_LEN, DOWNLINK_PDR_VALUE_LEN,
    MARKED_BEARER_OWNER_VALUE_LEN, MARKED_DOWNLINK_PDR_VALUE_LEN, UPLINK_DSCP_VALUE_LEN,
    UPLINK_FAR_VALUE_LEN, UPLINK_MARK_KEY_LEN, UPLINK_PMTU_VALUE_LEN, UPLINK_SOURCE_PORT_VALUE_LEN,
};

use crate::backend::error_proves_no_requested_mutation;
use crate::model::{classify_dual_selector_state, DualSelectorState};
use crate::{
    CreateGtpDeviceRequest, DrainedV2TeardownOutcome, DrainedV2TeardownRefusal,
    DrainedV2TeardownRequest, GtpAddressFamily, GtpBearerMark, GtpDevice, GtpPdpContext,
    GtpVersion, GtpuBackendKind, GtpuCapability, GtpuDataplaneBackend, GtpuDownlinkEndpoint,
    GtpuDownlinkFragmentContract, GtpuError, GtpuProbe, PdpContextIndeterminateReason,
    PdpContextInstallOutcome, PdpContextLocalTeidSelector, PdpContextReadback,
    PdpContextReconciliationCapabilities, PdpContextRemovalOutcome, PdpContextSelector,
    PdpContextUplinkSelector, RemovePdpContextRequest, Teid,
};

/// Default bpffs directory under which per-interface map pins are created.
pub const DEFAULT_BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/opc-gtpu";
/// Default tc filter priority for the datapath programs.
pub const DEFAULT_TC_PRIORITY: u16 = 50;

/// Redaction-safe aggregate of one eBPF GTP-U datapath counter map.
///
/// Each value is the saturating sum of every per-CPU slot in the exact map
/// held by the backend. The counters contain no addresses, TEIDs, marks, or
/// packet contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EbpfGtpuDatapathCounters {
    /// Uplink packets successfully GTP-U encapsulated.
    pub uplink_encapsulated: u64,
    /// Uplink packets for which no usable FAR was found.
    pub uplink_far_misses: u64,
    /// Downlink G-PDUs successfully decapsulated.
    pub downlink_decapsulated: u64,
    /// Downlink G-PDUs dropped because their TEID was unknown.
    pub downlink_unknown_teid: u64,
    /// Downlink GTP-U packets dropped as malformed.
    pub downlink_malformed: u64,
    /// Downlink G-PDUs dropped because the inner destination did not match
    /// the PDR's UE address.
    pub downlink_destination_mismatches: u64,
    /// Downlink G-PDUs dropped because binding state was missing or corrupt.
    pub downlink_binding_invalid: u64,
    /// Downlink G-PDUs dropped for an outer address-family mismatch.
    pub downlink_binding_family_mismatches: u64,
    /// Downlink G-PDUs dropped for an unauthorized outer peer.
    pub downlink_binding_peer_mismatches: u64,
    /// Downlink G-PDUs dropped for an unauthorized local outer destination.
    pub downlink_binding_local_mismatches: u64,
    /// Downlink G-PDUs dropped on the wrong ingress attachment.
    pub downlink_binding_ingress_mismatches: u64,
    /// Downlink G-PDUs dropped by the explicit UDP source-port policy.
    pub downlink_binding_source_port_mismatches: u64,
    /// Uplink packets rejected fail closed by the effective-MTU policy
    /// (over-MTU without outer-fragment permission).
    pub uplink_mtu_rejected: u64,
    /// Uplink packets dropped because the persisted MTU policy bytes were
    /// corrupt. A canary for external writers: nonzero always means non-SDK
    /// mutation of adopted state.
    pub uplink_mtu_policy_corrupt: u64,
}

/// Identity-bound diagnostic snapshot for one live eBPF GTP-U datapath.
///
/// Under the backend's exclusive-writer contract, a successful snapshot proves
/// that both tc hooks contain the exact program IDs loaded by this backend,
/// every named bpffs pin identifies the exact held map, and both programs
/// reference `counters_map_id` at both identity checks. The program and map IDs
/// are kernel-local diagnostic handles and the counters are aggregate-only, so
/// `Debug` is safe for redacted operational evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EbpfGtpuDatapathSnapshot {
    /// Kernel program ID attached at tc egress for uplink encapsulation.
    pub uplink_program_id: u32,
    /// Kernel program ID attached at tc ingress for downlink decapsulation.
    pub downlink_program_id: u32,
    /// Kernel map ID of the exact pinned per-CPU counter map.
    pub counters_map_id: u32,
    /// Kernel map ID of the exact pinned binding-drop counter map.
    pub downlink_binding_counters_map_id: u32,
    /// Per-path counters aggregated across all possible CPUs.
    pub counters: EbpfGtpuDatapathCounters,
}

/// Runtime behavior for the eBPF GTP-U backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfGtpuDataplaneBackendConfig {
    /// bpffs directory under which per-interface pin directories are created.
    pub bpffs_pin_root: PathBuf,
    /// tc filter priority used when attaching the clsact programs.
    pub tc_priority: u16,
}

impl Default for EbpfGtpuDataplaneBackendConfig {
    fn default() -> Self {
        Self {
            bpffs_pin_root: PathBuf::from(DEFAULT_BPFFS_PIN_ROOT),
            tc_priority: DEFAULT_TC_PRIORITY,
        }
    }
}

/// Environment capability report produced by the runtime for [`GtpuProbe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct EbpfEnvironment {
    /// The platform can run the eBPF datapath at all.
    pub platform_supported: bool,
    /// bpffs is available for map pinning.
    pub bpffs_present: bool,
    /// Kernel BTF is exposed at `/sys/kernel/btf/vmlinux`.
    pub btf_present: bool,
    /// `CAP_NET_ADMIN` is effective (tc attach).
    pub net_admin_capable: bool,
    /// `CAP_BPF` or `CAP_SYS_ADMIN` is effective (program/map load).
    pub bpf_capable: bool,
}

/// Narrow synchronous port to the kernel eBPF machinery.
///
/// The production implementation loads the committed CO-RE object with `aya`,
/// attaches tc clsact filters, and performs BPF map operations. Tests supply
/// a deterministic fake.
pub(crate) trait EbpfGtpuRuntime: Send + Sync + fmt::Debug {
    /// Resolve an interface index by name in the current netns.
    fn ifindex_by_name(&self, name: &str) -> Result<u32, GtpuError>;

    /// Load the datapath object, create-or-reuse pinned maps under `pin_dir`,
    /// write the local S2b-U IPv4 into the config map, ensure a clsact qdisc,
    /// and (re)attach the uplink/downlink programs.
    fn attach(
        &self,
        interface: &str,
        ifindex: u32,
        pin_dir: &Path,
        tc_priority: u16,
        local_ip: [u8; 4],
    ) -> Result<(), GtpuError>;

    /// Adopt a previously provisioned interface: reuse the pinned maps,
    /// (re)attach the programs, and return the recorded local S2b-U IPv4.
    /// Fails with [`GtpuError::NotFound`] when no prior provisioning exists.
    fn adopt(
        &self,
        interface: &str,
        ifindex: u32,
        pin_dir: &Path,
        tc_priority: u16,
    ) -> Result<[u8; 4], GtpuError>;

    /// Detach the datapath programs and remove the map pins.
    fn detach(
        &self,
        interface: &str,
        ifindex: u32,
        pin_dir: &Path,
        tc_priority: u16,
    ) -> Result<(), GtpuError>;

    /// Remove an exact, empty legacy-v2 program/map graph while retaining
    /// retry-safe identity evidence across partial cleanup.
    fn teardown_drained_v2(
        &self,
        interface: &str,
        ifindex: u32,
        pin_dir: &Path,
        tc_priority: u16,
    ) -> Result<DrainedV2TeardownOutcome, GtpuError>;

    /// Read an uplink FAR entry.
    fn far_get(
        &self,
        ifindex: u32,
        key: [u8; 4],
    ) -> Result<Option<[u8; UPLINK_FAR_VALUE_LEN]>, GtpuError>;
    /// Insert or overwrite an uplink FAR entry.
    fn far_insert(
        &self,
        ifindex: u32,
        key: [u8; 4],
        value: [u8; UPLINK_FAR_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove an uplink FAR entry; returns whether it existed.
    fn far_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError>;

    /// Read a marked uplink FAR entry.
    fn marked_far_get(
        &self,
        ifindex: u32,
        key: [u8; UPLINK_MARK_KEY_LEN],
    ) -> Result<Option<[u8; UPLINK_FAR_VALUE_LEN]>, GtpuError>;
    /// Insert or overwrite a marked uplink FAR entry.
    fn marked_far_insert(
        &self,
        ifindex: u32,
        key: [u8; UPLINK_MARK_KEY_LEN],
        value: [u8; UPLINK_FAR_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove a marked uplink FAR entry; returns whether it existed.
    fn marked_far_remove(
        &self,
        ifindex: u32,
        key: [u8; UPLINK_MARK_KEY_LEN],
    ) -> Result<bool, GtpuError>;

    /// Read an optional fixed uplink DSCP entry.
    fn dscp_get(
        &self,
        ifindex: u32,
        key: [u8; 4],
    ) -> Result<Option<[u8; UPLINK_DSCP_VALUE_LEN]>, GtpuError>;
    /// Insert or overwrite an optional fixed uplink DSCP entry.
    fn dscp_insert(
        &self,
        ifindex: u32,
        key: [u8; 4],
        value: [u8; UPLINK_DSCP_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove an optional fixed uplink DSCP entry; returns whether it existed.
    fn dscp_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError>;

    /// Read an optional fixed marked-uplink DSCP entry.
    fn marked_dscp_get(
        &self,
        ifindex: u32,
        key: [u8; UPLINK_MARK_KEY_LEN],
    ) -> Result<Option<[u8; UPLINK_DSCP_VALUE_LEN]>, GtpuError>;
    /// Insert or overwrite an optional fixed marked-uplink DSCP entry.
    fn marked_dscp_insert(
        &self,
        ifindex: u32,
        key: [u8; UPLINK_MARK_KEY_LEN],
        value: [u8; UPLINK_DSCP_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove a fixed marked-uplink DSCP entry; returns whether it existed.
    fn marked_dscp_remove(
        &self,
        ifindex: u32,
        key: [u8; UPLINK_MARK_KEY_LEN],
    ) -> Result<bool, GtpuError>;

    /// Read an explicit uplink source-port policy entry.
    fn sport_get(
        &self,
        ifindex: u32,
        key: [u8; 4],
    ) -> Result<Option<[u8; UPLINK_SOURCE_PORT_VALUE_LEN]>, GtpuError>;
    /// Insert or overwrite an explicit uplink source-port policy entry.
    fn sport_insert(
        &self,
        ifindex: u32,
        key: [u8; 4],
        value: [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove an explicit uplink source-port policy entry; returns whether it
    /// existed.
    fn sport_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError>;

    /// Read an explicit marked-uplink source-port policy entry.
    fn marked_sport_get(
        &self,
        ifindex: u32,
        key: [u8; UPLINK_MARK_KEY_LEN],
    ) -> Result<Option<[u8; UPLINK_SOURCE_PORT_VALUE_LEN]>, GtpuError>;
    /// Insert or overwrite an explicit marked-uplink source-port policy
    /// entry.
    fn marked_sport_insert(
        &self,
        ifindex: u32,
        key: [u8; UPLINK_MARK_KEY_LEN],
        value: [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove an explicit marked-uplink source-port policy entry; returns
    /// whether it existed.
    fn marked_sport_remove(
        &self,
        ifindex: u32,
        key: [u8; UPLINK_MARK_KEY_LEN],
    ) -> Result<bool, GtpuError>;

    /// Read a downlink PDR entry.
    fn pdr_get(
        &self,
        ifindex: u32,
        key: [u8; 4],
    ) -> Result<Option<[u8; DOWNLINK_PDR_VALUE_LEN]>, GtpuError>;
    /// Insert or overwrite a downlink PDR entry.
    fn pdr_insert(
        &self,
        ifindex: u32,
        key: [u8; 4],
        value: [u8; DOWNLINK_PDR_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove a downlink PDR entry; returns whether it existed.
    fn pdr_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError>;

    /// Read a marked downlink PDR entry.
    fn marked_pdr_get(
        &self,
        ifindex: u32,
        key: [u8; 4],
    ) -> Result<Option<[u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>, GtpuError>;
    /// Insert or overwrite a marked downlink PDR entry.
    fn marked_pdr_insert(
        &self,
        ifindex: u32,
        key: [u8; 4],
        value: [u8; MARKED_DOWNLINK_PDR_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove a marked downlink PDR entry; returns whether it existed.
    fn marked_pdr_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError>;

    /// Read the canonical downlink outer-endpoint binding for a local TEID.
    fn downlink_binding_get(
        &self,
        ifindex: u32,
        key: [u8; 4],
    ) -> Result<Option<[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>, GtpuError>;
    /// Atomically insert or replace one complete downlink endpoint binding.
    fn downlink_binding_insert(
        &self,
        ifindex: u32,
        key: [u8; 4],
        value: [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove a downlink endpoint binding; returns whether it existed.
    fn downlink_binding_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError>;

    /// Read a marked-bearer owner journal by `(PAA, mark)` selector.
    fn marked_owner_get(
        &self,
        ifindex: u32,
        selector: [u8; UPLINK_MARK_KEY_LEN],
    ) -> Result<Option<[u8; MARKED_BEARER_OWNER_VALUE_LEN]>, GtpuError>;
    /// Publish a canonical owner journal, enforcing local-TEID uniqueness.
    fn marked_owner_insert(
        &self,
        ifindex: u32,
        selector: [u8; UPLINK_MARK_KEY_LEN],
        value: [u8; MARKED_BEARER_OWNER_VALUE_LEN],
    ) -> Result<(), GtpuError>;
    /// Remove an exact owner journal and its in-memory TEID reservation.
    fn marked_owner_remove(
        &self,
        ifindex: u32,
        selector: [u8; UPLINK_MARK_KEY_LEN],
    ) -> Result<bool, GtpuError>;
    /// Resolve the sole journal selector reserving a local TEID.
    fn marked_owner_for_teid(
        &self,
        ifindex: u32,
        local_teid: [u8; 4],
    ) -> Result<Option<[u8; UPLINK_MARK_KEY_LEN]>, GtpuError>;

    /// Resolve the default-bearer local TEID reserved by one UE address.
    fn default_teid_for_ue(
        &self,
        ifindex: u32,
        ue_ip: [u8; 4],
    ) -> Result<Option<[u8; 4]>, GtpuError>;
    /// Resolve the sole default-bearer UE selector reserving a local TEID.
    fn default_ue_for_teid(
        &self,
        ifindex: u32,
        local_teid: [u8; 4],
    ) -> Result<Option<[u8; 4]>, GtpuError>;
    /// Reserve one exact default-bearer `(UE, local TEID)` identity.
    fn default_selector_insert(
        &self,
        ifindex: u32,
        ue_ip: [u8; 4],
        local_teid: [u8; 4],
    ) -> Result<(), GtpuError>;
    /// Release one exact default-bearer `(UE, local TEID)` identity.
    fn default_selector_remove(
        &self,
        ifindex: u32,
        ue_ip: [u8; 4],
        local_teid: [u8; 4],
    ) -> Result<bool, GtpuError>;

    /// Read counters only after proving the live hooks and exact named pins.
    fn datapath_snapshot(&self, ifindex: u32) -> Result<EbpfGtpuDatapathSnapshot, GtpuError>;

    /// Read the single-slot uplink MTU policy value for a managed device.
    fn pmtu_policy_get(&self, ifindex: u32) -> Result<[u8; UPLINK_PMTU_VALUE_LEN], GtpuError>;
    /// Write the single-slot uplink MTU policy value for a managed device.
    ///
    /// The all-zero value is the explicit unset (legacy) state; only
    /// canonical policy bytes or zeros may be written.
    fn pmtu_policy_write(
        &self,
        ifindex: u32,
        value: [u8; UPLINK_PMTU_VALUE_LEN],
    ) -> Result<(), GtpuError>;

    /// Probe the environment for eBPF datapath readiness.
    fn probe_environment(&self) -> EbpfEnvironment;

    /// Return whether the target interface's live uplink filter is the exact
    /// loaded program and references the exact pinned DSCP map.
    fn dscp_datapath_usable(&self, ifindex: u32) -> bool;

    /// Return whether the target interface's live filters are the exact
    /// loaded programs and reference the complete source-port commit graph.
    fn source_port_datapath_usable(&self, ifindex: u32) -> bool;

    /// Return whether both live filters are the exact loaded programs and
    /// reference every exact pinned per-bearer mark map.
    fn bearer_mark_datapath_usable(&self, ifindex: u32) -> bool;

    /// Return whether the exact live downlink program and both endpoint-
    /// binding maps are present for the managed attachment.
    fn downlink_endpoint_binding_datapath_usable(&self, ifindex: u32) -> bool;

    /// Return whether the exact live uplink program and both MTU policy maps
    /// are present for the managed attachment.
    fn pmtu_datapath_usable(&self, ifindex: u32) -> bool;

    /// Return whether readback can trust the exact programs, every named map,
    /// and the held reconciler lease for this managed device.
    fn pdp_readback_datapath_usable(&self, ifindex: u32) -> bool;

    /// Return whether PDP cleanup can safely mutate the held maps.
    ///
    /// Every named pin must still identify its exact held map, and each tc
    /// slot must contain either this runtime's exact program or no filter.
    /// An absent hook is safe because removal only reduces reachability; a
    /// foreign/replacement hook is not.
    fn pdp_cleanup_datapath_usable(&self, ifindex: u32) -> bool;
}

#[derive(Debug, Clone)]
struct ManagedDevice {
    name: String,
    local_ip: Ipv4Addr,
}

#[derive(Clone, Copy)]
struct MarkedPdpState {
    far_key: [u8; UPLINK_MARK_KEY_LEN],
    far_value: [u8; UPLINK_FAR_VALUE_LEN],
    pdr_key: [u8; 4],
    pdr_value: [u8; MARKED_DOWNLINK_PDR_VALUE_LEN],
    binding_value: [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
    dscp_value: Option<[u8; UPLINK_DSCP_VALUE_LEN]>,
    commit: PdpContextCommit,
}

struct EbpfGtpuDataplaneBackendInner {
    runtime: Arc<dyn EbpfGtpuRuntime>,
    /// Serializes every state-changing reconciliation performed by this
    /// backend instance. Runtime map operations are individually atomic, but
    /// a PDP context spans three maps and must be observed/reconciled as one
    /// control-plane operation.
    operation_lock: Mutex<()>,
    devices: Mutex<HashMap<u32, ManagedDevice>>,
    config: EbpfGtpuDataplaneBackendConfig,
}

/// GTP-U dataplane backend driving tc clsact eBPF programs.
///
/// See the module docs for datapath semantics and the crate README for the
/// product steering contract.
#[derive(Clone)]
pub struct EbpfGtpuDataplaneBackend {
    inner: Arc<EbpfGtpuDataplaneBackendInner>,
}

impl fmt::Debug for EbpfGtpuDataplaneBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EbpfGtpuDataplaneBackend")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl Default for EbpfGtpuDataplaneBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfGtpuDataplaneBackend {
    /// Create a backend using the aya-based kernel runtime and default config.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(EbpfGtpuDataplaneBackendConfig::default())
    }

    /// Create a backend using the aya-based kernel runtime and custom config.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn with_config(config: EbpfGtpuDataplaneBackendConfig) -> Self {
        Self::with_runtime_and_config(Arc::new(aya_runtime::AyaGtpuRuntime::new()), config)
    }

    /// Read an identity-bound, redaction-safe snapshot for a managed device.
    ///
    /// Under the backend's exclusive-writer contract, success proves at both
    /// identity checks that the live tc filters and every named bpffs pin match
    /// the exact programs and maps held by this backend. Counter values are read
    /// from that held per-CPU map and aggregated across all possible CPUs,
    /// avoiding ambiguous same-name map selection by external tooling.
    ///
    /// # Errors
    ///
    /// Returns [`GtpuError::NotFound`] when `device` is not managed by this
    /// backend. Identity loss, a replaced hook or pin, and an identity change
    /// while the snapshot is read return [`GtpuError::StateIndeterminate`].
    pub async fn datapath_snapshot(
        &self,
        device: &GtpDevice,
    ) -> Result<EbpfGtpuDatapathSnapshot, GtpuError> {
        let device = device.clone();
        self.run_blocking("ebpf_datapath_snapshot", move |backend| {
            backend.datapath_snapshot_sync(device)
        })
        .await
    }

    /// Read back the effective uplink MTU/outer-fragmentation policy of a
    /// managed device from its pinned policy map.
    ///
    /// `Ok(None)` is the explicit unset state: the datapath enforces only the
    /// legacy IPv4 total-length limit on uplink encapsulation. The returned
    /// policy carries the configured effective link MTU and the
    /// inner-facing MTU (headroom accounting for the fixed encapsulation
    /// overhead).
    ///
    /// # Errors
    ///
    /// Returns [`GtpuError::NotFound`] when `device` is not managed by this
    /// backend. A lost policy map, a replaced hook or pin, or corrupt
    /// persisted policy bytes return [`GtpuError::StateIndeterminate`] so the
    /// caller reconciles from authoritative state rather than assuming a
    /// policy.
    pub async fn effective_uplink_mtu_policy(
        &self,
        device: &GtpDevice,
    ) -> Result<Option<GtpuUplinkMtuPolicy>, GtpuError> {
        let device = device.clone();
        self.run_blocking("ebpf_pmtu_policy_readback", move |backend| {
            backend.uplink_mtu_policy_sync(device)
        })
        .await
    }

    /// Replace the uplink MTU/outer-fragmentation policy of a managed device.
    ///
    /// The single-slot policy map write is atomic at the map level and takes
    /// effect on the next uplink encapsulation. `None` restores the explicit
    /// unset (legacy total-length-only) state; it is not a deletion. This is
    /// the supported mutation path — out-of-band writes to the pinned map are
    /// outside the exclusive-writer contract.
    ///
    /// # Errors
    ///
    /// Returns [`GtpuError::NotFound`] when `device` is not managed by this
    /// backend and [`GtpuError::StateIndeterminate`] when the datapath's MTU
    /// policy maps are not provably the exact held maps.
    pub async fn set_uplink_mtu_policy(
        &self,
        device: &GtpDevice,
        policy: Option<GtpuUplinkMtuPolicy>,
    ) -> Result<(), GtpuError> {
        let device = device.clone();
        self.run_blocking("ebpf_pmtu_policy_update", move |backend| {
            backend.set_uplink_mtu_policy_sync(device, policy)
        })
        .await
    }

    pub(crate) fn with_runtime_and_config(
        runtime: Arc<dyn EbpfGtpuRuntime>,
        config: EbpfGtpuDataplaneBackendConfig,
    ) -> Self {
        Self {
            inner: Arc::new(EbpfGtpuDataplaneBackendInner {
                runtime,
                operation_lock: Mutex::new(()),
                devices: Mutex::new(HashMap::new()),
                config,
            }),
        }
    }

    #[cfg(test)]
    fn with_runtime(runtime: Arc<dyn EbpfGtpuRuntime>) -> Self {
        Self::with_runtime_and_config(runtime, EbpfGtpuDataplaneBackendConfig::default())
    }

    async fn run_blocking<T, F>(&self, operation: &'static str, f: F) -> Result<T, GtpuError>
    where
        T: Send + 'static,
        F: FnOnce(Self) -> Result<T, GtpuError> + Send + 'static,
    {
        let backend = self.clone();
        tokio::task::spawn_blocking(move || f(backend))
            .await
            .map_err(|_| {
                GtpuError::io(
                    operation,
                    io::Error::new(io::ErrorKind::Interrupted, "gtpu blocking task failed"),
                )
            })?
    }

    fn pin_dir(&self, interface: &str) -> PathBuf {
        self.inner.config.bpffs_pin_root.join(interface)
    }

    fn devices(&self) -> Result<std::sync::MutexGuard<'_, HashMap<u32, ManagedDevice>>, GtpuError> {
        self.inner
            .devices
            .lock()
            .map_err(|_| GtpuError::io("ebpf_device_state", poisoned_lock()))
    }

    fn operation_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, GtpuError> {
        self.inner
            .operation_lock
            .lock()
            .map_err(|_| GtpuError::io("ebpf_reconciliation", poisoned_lock()))
    }

    fn rollback_default_selector(
        &self,
        ifindex: u32,
        ue_ip: [u8; 4],
        local_teid: [u8; 4],
        source: GtpuError,
    ) -> Result<(), GtpuError> {
        match self
            .inner
            .runtime
            .default_selector_remove(ifindex, ue_ip, local_teid)
        {
            Ok(true) => Err(source),
            Ok(false) | Err(_) => Err(GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            }),
        }
    }

    fn install_marked_pdp_context(
        &self,
        ifindex: u32,
        state: MarkedPdpState,
    ) -> Result<(), GtpuError> {
        let MarkedPdpState {
            far_key,
            far_value,
            pdr_key,
            pdr_value,
            binding_value,
            dscp_value,
            commit,
        } = state;
        let active_commit = commit.with_phase(MarkedBearerOwnerPhase::Active);
        let pending_commit = commit.with_phase(MarkedBearerOwnerPhase::Pending);
        let selector_value = UplinkFarKey::decode(&far_key);
        let decoded_pdr = MarkedDownlinkPdr::decode(&pdr_value);
        if !active_commit.is_valid()
            || selector_value.encode() != far_key
            || decoded_pdr.encode() != pdr_value
            || decoded_pdr.ue_ip != selector_value.ue_ip
            || decoded_pdr.bearer_mark != selector_value.bearer_mark
            || active_commit.local_teid() != pdr_key
            || active_commit.uplink_far().encode() != far_value
            || active_commit.downlink_binding().encode() != binding_value
            || active_commit.downlink_binding().ingress_ifindex() != ifindex
            || active_commit.egress_dscp().map(|value| [value]) != dscp_value
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            });
        }

        // A local TEID is globally unique across default PDRs and every
        // commit phase, including a crash before owner/PDR publication.
        let default_pdr = self.inner.runtime.pdr_get(ifindex, pdr_key)?;
        if let Some(selector) = self.inner.runtime.marked_owner_for_teid(ifindex, pdr_key)? {
            if selector != far_key {
                let encoded = self
                    .inner
                    .runtime
                    .marked_owner_get(ifindex, selector)?
                    .ok_or(GtpuError::StateIndeterminate {
                        operation: "ebpf_install_pdp_context",
                    })?;
                let owner = MarkedBearerOwner::decode(&encoded);
                if !owner.is_valid() || owner.local_teid != pdr_key {
                    return Err(GtpuError::StateIndeterminate {
                        operation: "ebpf_install_pdp_context",
                    });
                }
                if owner.phase == MarkedBearerOwnerPhase::Removing {
                    let encoded_commit = self
                        .inner
                        .runtime
                        .marked_sport_get(ifindex, selector)?
                        .ok_or(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        })?;
                    let commit = PdpContextCommit::decode(&encoded_commit);
                    if !commit.is_valid()
                        || commit.phase() != MarkedBearerOwnerPhase::Removing
                        || commit.local_teid() != owner.local_teid
                    {
                        return Err(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        });
                    }
                    self.finish_marked_commit_removal(ifindex, selector, commit)?;
                    return Err(GtpuError::RetryRequired {
                        operation: "ebpf_install_after_removal",
                    });
                }
                return Err(GtpuError::AlreadyExists);
            }
        }

        let existing_far = self.inner.runtime.marked_far_get(ifindex, far_key)?;
        let existing_pdr = self.inner.runtime.marked_pdr_get(ifindex, pdr_key)?;
        let existing_binding = self.inner.runtime.downlink_binding_get(ifindex, pdr_key)?;
        let existing_dscp = self.inner.runtime.marked_dscp_get(ifindex, far_key)?;
        let existing_owner = self.inner.runtime.marked_owner_get(ifindex, far_key)?;
        let existing_commit = self.inner.runtime.marked_sport_get(ifindex, far_key)?;
        let existing_commit = existing_commit
            .map(|encoded| {
                let commit = PdpContextCommit::decode(&encoded);
                commit
                    .is_valid()
                    .then_some(commit)
                    .ok_or(GtpuError::StateIndeterminate {
                        operation: "ebpf_install_pdp_context",
                    })
            })
            .transpose()?;

        if let Some(existing_commit) = existing_commit {
            match existing_commit.phase() {
                MarkedBearerOwnerPhase::Removing => {
                    self.finish_marked_commit_removal(ifindex, far_key, existing_commit)?;
                    return Err(GtpuError::RetryRequired {
                        operation: "ebpf_install_after_removal",
                    });
                }
                MarkedBearerOwnerPhase::Pending => {
                    if default_pdr.is_some() {
                        return Err(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        });
                    }
                    if existing_commit.local_teid() != pdr_key {
                        return Err(GtpuError::AlreadyExists);
                    }
                    if existing_commit != pending_commit {
                        return Err(GtpuError::AlreadyExists);
                    }
                    return self
                        .publish_marked_commit(ifindex, far_key, pdr_value, active_commit)
                        .map_err(|_| GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        });
                }
                MarkedBearerOwnerPhase::Active => {
                    if default_pdr.is_some() {
                        return Err(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        });
                    }
                    if existing_commit.local_teid() != pdr_key {
                        return Err(GtpuError::AlreadyExists);
                    }
                    let old_owner = existing_owner
                        .map(|encoded| MarkedBearerOwner::decode(&encoded))
                        .ok_or(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        })?;
                    let old_pdr = MarkedDownlinkPdr {
                        ue_ip: selector_value.ue_ip,
                        bearer_mark: selector_value.bearer_mark,
                    }
                    .encode();
                    if !old_owner.is_valid()
                        || old_owner != existing_commit.marked_owner()
                        || existing_far != Some(existing_commit.uplink_far().encode())
                        || existing_pdr != Some(old_pdr)
                        || existing_binding != Some(existing_commit.downlink_binding().encode())
                        || existing_dscp != existing_commit.egress_dscp().map(|value| [value])
                    {
                        return Err(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        });
                    }
                    if existing_commit == active_commit {
                        return Ok(());
                    }

                    // Pending is the single cross-direction cutover gate. It
                    // is published before any component changes, so a process
                    // death can expose only a fail-closed recoverable
                    // transaction, never a mixed Active graph.
                    self.inner.runtime.marked_sport_insert(
                        ifindex,
                        far_key,
                        pending_commit.encode(),
                    )?;
                    let replace =
                        self.publish_marked_commit(ifindex, far_key, pdr_value, active_commit);
                    if let Err(source) = replace {
                        return self.restore_marked_commit(
                            ifindex,
                            far_key,
                            old_pdr,
                            existing_commit,
                            source,
                        );
                    }
                    return Ok(());
                }
            }
        }

        // Without a commit record, no component may already exist. A v4
        // writer claims the complete selector/TEID transaction by publishing
        // Pending first; exact retry or restart cleanup can then recover every
        // later mutation cut.
        if default_pdr.is_some() {
            return Err(GtpuError::AlreadyExists);
        }
        if existing_owner.is_some()
            || existing_far.is_some()
            || existing_pdr.is_some()
            || existing_binding.is_some()
            || existing_dscp.is_some()
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            });
        }
        self.inner
            .runtime
            .marked_sport_insert(ifindex, far_key, pending_commit.encode())?;
        self.publish_marked_commit(ifindex, far_key, pdr_value, active_commit)
            .map_err(|_| GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            })
    }

    fn publish_marked_commit(
        &self,
        ifindex: u32,
        selector: [u8; UPLINK_MARK_KEY_LEN],
        pdr_value: [u8; MARKED_DOWNLINK_PDR_VALUE_LEN],
        active_commit: PdpContextCommit,
    ) -> Result<(), GtpuError> {
        let local_teid = active_commit.local_teid();
        let pending_owner = active_commit
            .with_phase(MarkedBearerOwnerPhase::Pending)
            .marked_owner();
        self.inner
            .runtime
            .marked_owner_insert(ifindex, selector, pending_owner.encode())?;
        match active_commit.egress_dscp() {
            Some(value) => self
                .inner
                .runtime
                .marked_dscp_insert(ifindex, selector, [value])?,
            None => {
                self.inner.runtime.marked_dscp_remove(ifindex, selector)?;
            }
        }
        self.inner.runtime.marked_far_insert(
            ifindex,
            selector,
            active_commit.uplink_far().encode(),
        )?;
        self.inner.runtime.downlink_binding_insert(
            ifindex,
            local_teid,
            active_commit.downlink_binding().encode(),
        )?;
        self.inner
            .runtime
            .marked_pdr_insert(ifindex, local_teid, pdr_value)?;
        self.inner.runtime.marked_owner_insert(
            ifindex,
            selector,
            active_commit.marked_owner().encode(),
        )?;
        // Active is the sole forwarding commit and is always published last.
        self.inner
            .runtime
            .marked_sport_insert(ifindex, selector, active_commit.encode())
    }

    fn restore_marked_commit(
        &self,
        ifindex: u32,
        selector: [u8; UPLINK_MARK_KEY_LEN],
        pdr_value: [u8; MARKED_DOWNLINK_PDR_VALUE_LEN],
        old_commit: PdpContextCommit,
        source: GtpuError,
    ) -> Result<(), GtpuError> {
        let restored = self
            .publish_marked_commit(ifindex, selector, pdr_value, old_commit)
            .is_ok();
        if restored {
            Err(source)
        } else {
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            })
        }
    }

    fn finish_marked_commit_removal(
        &self,
        ifindex: u32,
        selector: [u8; UPLINK_MARK_KEY_LEN],
        commit: PdpContextCommit,
    ) -> Result<(), GtpuError> {
        let owner_key = UplinkFarKey::decode(&selector);
        let expected_pdr = MarkedDownlinkPdr {
            ue_ip: owner_key.ue_ip,
            bearer_mark: owner_key.bearer_mark,
        }
        .encode();
        if !commit.is_valid()
            || owner_key.ue_ip == [0; 4]
            || owner_key.bearer_mark == [0; 4]
            || commit.downlink_binding().ingress_ifindex() != ifindex
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        let local_teid = commit.local_teid();
        let legacy_pdr = self.inner.runtime.pdr_get(ifindex, local_teid)?;
        let indexed_selector = self
            .inner
            .runtime
            .marked_owner_for_teid(ifindex, local_teid)?;
        let marked_pdr = self.inner.runtime.marked_pdr_get(ifindex, local_teid)?;
        if legacy_pdr.is_some()
            || indexed_selector.is_some_and(|indexed| indexed != selector)
            || marked_pdr.is_some_and(|value| value != expected_pdr)
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        let far = self.inner.runtime.marked_far_get(ifindex, selector)?;
        let dscp = self.inner.runtime.marked_dscp_get(ifindex, selector)?;
        let owner = self.inner.runtime.marked_owner_get(ifindex, selector)?;
        let binding = self
            .inner
            .runtime
            .downlink_binding_get(ifindex, local_teid)?;
        let far_is_owned = far.is_none_or(|value| {
            let value = UplinkFar::decode(&value);
            value.peer_ip != [0; 4]
                && value.local_ip == commit.uplink_far().local_ip
                && value.o_teid != [0; 4]
        });
        let binding_is_owned = binding.is_none_or(|value| {
            let value = DownlinkEndpointBinding::decode(&value);
            value.is_valid()
                && value.ingress_ifindex() == ifindex
                && value.local_address() == commit.downlink_binding().local_address()
        });
        let owner_is_owned = owner.is_none_or(|value| {
            let value = MarkedBearerOwner::decode(&value);
            value.is_valid() && value.local_teid == local_teid
        });
        if !far_is_owned
            || dscp.is_some_and(|value| value[0] > 63)
            || !binding_is_owned
            || !owner_is_owned
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }

        let removing_commit = commit.with_phase(MarkedBearerOwnerPhase::Removing);
        if commit.phase() != MarkedBearerOwnerPhase::Removing {
            self.inner
                .runtime
                .marked_sport_insert(ifindex, selector, removing_commit.encode())?;
        }
        if owner.is_some() {
            self.inner.runtime.marked_owner_insert(
                ifindex,
                selector,
                removing_commit.marked_owner().encode(),
            )?;
        }
        if self
            .inner
            .runtime
            .marked_far_remove(ifindex, selector)
            .is_err()
            || self
                .inner
                .runtime
                .marked_dscp_remove(ifindex, selector)
                .is_err()
            || self
                .inner
                .runtime
                .downlink_binding_remove(ifindex, local_teid)
                .is_err()
            || self
                .inner
                .runtime
                .marked_pdr_remove(ifindex, local_teid)
                .is_err()
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        if self
            .inner
            .runtime
            .marked_owner_remove(ifindex, selector)
            .is_err()
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        match self.inner.runtime.marked_sport_remove(ifindex, selector) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            }),
        }
    }

    fn create_device_sync(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError> {
        let _operation = self.operation_guard()?;
        validate_interface_name(&request.name)?;
        let local_ip = require_ipv4(request.bind_address, "device.bind_address")?;
        if local_ip.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "device.bind_address",
                "eBPF backend needs the concrete S2b-U IPv4 as the outer encapsulation source",
            ));
        }
        let ifindex = self.inner.runtime.ifindex_by_name(&request.name)?;
        // Hold the registration guard across runtime publication so a second
        // poisoned-lock acquisition cannot strand an attached runtime device
        // outside the backend's managed-device index.
        let mut devices = self.devices()?;
        if devices.contains_key(&ifindex) {
            return Err(GtpuError::AlreadyExists);
        }
        self.inner.runtime.attach(
            &request.name,
            ifindex,
            &self.pin_dir(&request.name),
            self.inner.config.tc_priority,
            local_ip.octets(),
        )?;
        // Publish an explicitly requested uplink MTU policy before the device
        // becomes managed. A policy the loaded datapath cannot honor fails
        // the write closed rather than being silently ignored. `None` leaves
        // the persisted slot untouched: a fresh pin set already carries the
        // all-zero unset state, and a retained pin set must not lose its
        // configured policy to an unspecified request. The window between
        // attach and this write is safe because no PDP context exists at
        // device creation, so uplink traffic still FAR-misses on the legacy
        // path.
        if let Some(policy) = request.uplink_mtu_policy {
            if let Err(error) = self
                .inner
                .runtime
                .pmtu_policy_write(ifindex, policy.map_value())
            {
                // The device is attached but not yet managed; roll the
                // attachment back so a failed policy publication cannot
                // strand a live datapath outside the managed-device index.
                let rollback = self.inner.runtime.detach(
                    &request.name,
                    ifindex,
                    &self.pin_dir(&request.name),
                    self.inner.config.tc_priority,
                );
                return match rollback {
                    Ok(()) => Err(error),
                    Err(_) => Err(GtpuError::StateIndeterminate {
                        operation: "ebpf_create_device",
                    }),
                };
            }
        }
        devices.insert(
            ifindex,
            ManagedDevice {
                name: request.name.clone(),
                local_ip,
            },
        );
        Ok(GtpDevice {
            name: request.name,
            ifindex,
        })
    }

    fn resolve_device_sync(&self, name: String) -> Result<GtpDevice, GtpuError> {
        let _operation = self.operation_guard()?;
        validate_interface_name(&name)?;
        let ifindex = self.inner.runtime.ifindex_by_name(&name)?;
        let mut devices = self.devices()?;
        if let Some(device) = devices.get(&ifindex) {
            return Ok(GtpDevice {
                name: device.name.clone(),
                ifindex,
            });
        }
        let local_ip = self.inner.runtime.adopt(
            &name,
            ifindex,
            &self.pin_dir(&name),
            self.inner.config.tc_priority,
        )?;
        devices.insert(
            ifindex,
            ManagedDevice {
                name: name.clone(),
                local_ip: Ipv4Addr::from(local_ip),
            },
        );
        Ok(GtpDevice { name, ifindex })
    }

    fn remove_device_sync(&self, device: GtpDevice) -> Result<(), GtpuError> {
        let _operation = self.operation_guard()?;
        validate_interface_name(&device.name)?;
        let mut devices = self.devices()?;
        let is_managed = devices
            .get(&device.ifindex)
            .is_some_and(|managed| managed.name == device.name);
        if !is_managed {
            return Err(GtpuError::NotFound);
        }
        self.inner.runtime.detach(
            &device.name,
            device.ifindex,
            &self.pin_dir(&device.name),
            self.inner.config.tc_priority,
        )?;
        devices.remove(&device.ifindex);
        Ok(())
    }

    fn teardown_drained_v2_sync(
        &self,
        request: DrainedV2TeardownRequest,
    ) -> Result<DrainedV2TeardownOutcome, GtpuError> {
        let _operation = self.operation_guard()?;
        let device = request.device();
        validate_interface_name(&device.name)?;
        if device.ifindex == 0 {
            return Err(GtpuError::invalid_config(
                "device.ifindex",
                "interface index must be nonzero",
            ));
        }
        let current_ifindex = match self.inner.runtime.ifindex_by_name(&device.name) {
            Ok(ifindex) => ifindex,
            Err(GtpuError::NotFound) => {
                return Ok(DrainedV2TeardownOutcome::Refused(
                    DrainedV2TeardownRefusal::InterfaceIdentityChanged,
                ));
            }
            Err(error) => return Err(error),
        };
        if current_ifindex != device.ifindex {
            return Ok(DrainedV2TeardownOutcome::Refused(
                DrainedV2TeardownRefusal::InterfaceIdentityChanged,
            ));
        }
        if self.devices()?.contains_key(&device.ifindex) {
            return Ok(DrainedV2TeardownOutcome::Refused(
                DrainedV2TeardownRefusal::ManagedAttachment,
            ));
        }
        self.inner.runtime.teardown_drained_v2(
            &device.name,
            device.ifindex,
            &self.pin_dir(&device.name),
            self.inner.config.tc_priority,
        )
    }

    fn datapath_snapshot_sync(
        &self,
        device: GtpDevice,
    ) -> Result<EbpfGtpuDatapathSnapshot, GtpuError> {
        let _operation = self.operation_guard()?;
        validate_interface_name(&device.name)?;
        let devices = self.devices()?;
        if devices
            .get(&device.ifindex)
            .is_none_or(|managed| managed.name != device.name)
        {
            return Err(GtpuError::NotFound);
        }
        self.inner.runtime.datapath_snapshot(device.ifindex)
    }

    fn uplink_mtu_policy_sync(
        &self,
        device: GtpDevice,
    ) -> Result<Option<GtpuUplinkMtuPolicy>, GtpuError> {
        let _operation = self.operation_guard()?;
        validate_interface_name(&device.name)?;
        let devices = self.devices()?;
        if devices
            .get(&device.ifindex)
            .is_none_or(|managed| managed.name != device.name)
        {
            return Err(GtpuError::NotFound);
        }
        if !self.inner.runtime.pmtu_datapath_usable(device.ifindex) {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pmtu_policy_readback",
            });
        }
        let value = self.inner.runtime.pmtu_policy_get(device.ifindex)?;
        match GtpuUplinkMtuPolicy::decode_map_value(&value) {
            UplinkMtuMapState::Unset => Ok(None),
            UplinkMtuMapState::Configured(policy) => Ok(Some(policy)),
            // Corrupt adopted policy state fails closed.
            UplinkMtuMapState::Corrupt => Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pmtu_policy_readback",
            }),
        }
    }

    fn set_uplink_mtu_policy_sync(
        &self,
        device: GtpDevice,
        policy: Option<GtpuUplinkMtuPolicy>,
    ) -> Result<(), GtpuError> {
        let _operation = self.operation_guard()?;
        validate_interface_name(&device.name)?;
        let devices = self.devices()?;
        if devices
            .get(&device.ifindex)
            .is_none_or(|managed| managed.name != device.name)
        {
            return Err(GtpuError::NotFound);
        }
        if !self.inner.runtime.pmtu_datapath_usable(device.ifindex) {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pmtu_policy_update",
            });
        }
        // The single-slot write is atomic at the map level; `None` is the
        // explicit unset (legacy) state, not a deletion.
        let value = match policy {
            Some(policy) => policy.map_value(),
            None => [0; UPLINK_PMTU_VALUE_LEN],
        };
        self.inner.runtime.pmtu_policy_write(device.ifindex, value)
    }

    fn validate_reconciliation_context_locked(
        &self,
        context: &GtpPdpContext,
    ) -> Result<Ipv4Addr, GtpuError> {
        validate_gtp_version(context.gtp_version)?;
        let ms_address = require_ipv4(context.ms_address, "pdp.ms_address")?;
        let peer_address = require_ipv4(context.peer_address, "pdp.peer_address")?;
        if ms_address.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "pdp.ms_address",
                "MS address must not be unspecified",
            ));
        }
        if peer_address.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "pdp.peer_address",
                "peer address must not be unspecified",
            ));
        }
        let local_ip = self
            .devices()?
            .get(&context.link_ifindex)
            .map(|device| device.local_ip)
            .ok_or(GtpuError::NotFound)?;
        if ms_address == local_ip {
            return Err(GtpuError::invalid_config(
                "pdp.ms_address",
                "MS address must differ from the S2b-U local address",
            ));
        }
        GtpuDownlinkEndpoint::new(
            context.peer_address,
            IpAddr::V4(local_ip),
            context.link_ifindex,
            context.downlink_source_port_policy,
        )
        .ok_or_else(|| {
            GtpuError::invalid_config(
                "pdp.downlink_endpoint",
                "peer, local endpoint, and ingress attachment must form one canonical identity",
            )
        })?;
        Ok(local_ip)
    }

    fn managed_local_ip_locked(&self, ifindex: u32) -> Result<Ipv4Addr, GtpuError> {
        self.devices()?
            .get(&ifindex)
            .map(|device| device.local_ip)
            .ok_or(GtpuError::NotFound)
    }

    fn read_default_context_locked(
        &self,
        ifindex: u32,
        local_teid: [u8; 4],
        expected_ue: Option<[u8; 4]>,
    ) -> Result<GtpPdpContext, GtpuError> {
        let indeterminate = || GtpuError::StateIndeterminate {
            operation: "ebpf_pdp_context_readback",
        };
        let local_ip = self.managed_local_ip_locked(ifindex)?.octets();
        let encoded_pdr = self
            .inner
            .runtime
            .pdr_get(ifindex, local_teid)?
            .ok_or_else(indeterminate)?;
        let pdr = DownlinkPdr::decode(&encoded_pdr);
        if pdr.encode() != encoded_pdr
            || expected_ue.is_some_and(|expected| expected != pdr.ue_ip)
            || self.inner.runtime.default_teid_for_ue(ifindex, pdr.ue_ip)? != Some(local_teid)
            || self
                .inner
                .runtime
                .marked_owner_for_teid(ifindex, local_teid)?
                .is_some()
            || self
                .inner
                .runtime
                .marked_pdr_get(ifindex, local_teid)?
                .is_some()
        {
            return Err(indeterminate());
        }
        let encoded_far = self
            .inner
            .runtime
            .far_get(ifindex, pdr.ue_ip)?
            .ok_or_else(indeterminate)?;
        let far = UplinkFar::decode(&encoded_far);
        let encoded_binding = self
            .inner
            .runtime
            .downlink_binding_get(ifindex, local_teid)?
            .ok_or_else(indeterminate)?;
        let binding = DownlinkEndpointBinding::decode(&encoded_binding);
        if !opc_gtpu_ebpf_common::default_bearer_graph_is_valid(
            local_teid, pdr, far, binding, local_ip, ifindex,
        ) {
            return Err(indeterminate());
        }
        let egress_dscp = match self.inner.runtime.dscp_get(ifindex, pdr.ue_ip)? {
            Some([value]) => crate::DscpCodepoint::new(value)
                .map_err(|_| indeterminate())
                .map(Some)?,
            None => None,
        };
        let encoded_commit = self
            .inner
            .runtime
            .sport_get(ifindex, pdr.ue_ip)?
            .ok_or_else(indeterminate)?;
        let commit = PdpContextCommit::decode(&encoded_commit);
        if !commit.authorizes_graph(
            local_teid,
            &far,
            egress_dscp.map(crate::DscpCodepoint::get),
            &binding,
        ) {
            return Err(indeterminate());
        }
        let uplink_source_port_policy = commit.uplink_source_port_policy();
        let local_teid = Teid::new(u32::from_be_bytes(local_teid)).ok_or_else(indeterminate)?;
        let peer_teid = Teid::new(u32::from_be_bytes(far.o_teid)).ok_or_else(indeterminate)?;
        Ok(GtpPdpContext {
            local_teid,
            peer_teid,
            ms_address: IpAddr::V4(Ipv4Addr::from(pdr.ue_ip)),
            peer_address: IpAddr::V4(Ipv4Addr::from(far.peer_ip)),
            link_ifindex: ifindex,
            downlink_source_port_policy: binding.source_port_policy(),
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp,
            uplink_source_port_policy,
        })
    }

    fn read_marked_context_locked(
        &self,
        ifindex: u32,
        selector: [u8; UPLINK_MARK_KEY_LEN],
        expected_local_teid: Option<[u8; 4]>,
    ) -> Result<GtpPdpContext, GtpuError> {
        let indeterminate = || GtpuError::StateIndeterminate {
            operation: "ebpf_pdp_context_readback",
        };
        let local_ip = self.managed_local_ip_locked(ifindex)?.octets();
        let key = UplinkFarKey::decode(&selector);
        let encoded_owner = self
            .inner
            .runtime
            .marked_owner_get(ifindex, selector)?
            .ok_or_else(indeterminate)?;
        let owner = MarkedBearerOwner::decode(&encoded_owner);
        if key.ue_ip == [0; 4]
            || key.ue_ip == local_ip
            || key.bearer_mark == [0; 4]
            || !owner.is_valid()
            || owner.phase != MarkedBearerOwnerPhase::Active
            || owner.uplink_far.local_ip != local_ip
            || owner.downlink_binding.ingress_ifindex() != ifindex
            || expected_local_teid.is_some_and(|expected| expected != owner.local_teid)
            || self
                .inner
                .runtime
                .marked_owner_for_teid(ifindex, owner.local_teid)?
                != Some(selector)
            || self
                .inner
                .runtime
                .pdr_get(ifindex, owner.local_teid)?
                .is_some()
        {
            return Err(indeterminate());
        }
        let expected_pdr = MarkedDownlinkPdr {
            ue_ip: key.ue_ip,
            bearer_mark: key.bearer_mark,
        }
        .encode();
        let expected_far = owner.uplink_far.encode();
        let expected_dscp = owner.egress_dscp().map(|value| [value]);
        let expected_binding = owner.downlink_binding.encode();
        if self
            .inner
            .runtime
            .marked_pdr_get(ifindex, owner.local_teid)?
            != Some(expected_pdr)
            || self.inner.runtime.marked_far_get(ifindex, selector)? != Some(expected_far)
            || self.inner.runtime.marked_dscp_get(ifindex, selector)? != expected_dscp
            || self
                .inner
                .runtime
                .downlink_binding_get(ifindex, owner.local_teid)?
                != Some(expected_binding)
        {
            return Err(indeterminate());
        }
        let local_teid =
            Teid::new(u32::from_be_bytes(owner.local_teid)).ok_or_else(indeterminate)?;
        let peer_teid =
            Teid::new(u32::from_be_bytes(owner.uplink_far.o_teid)).ok_or_else(indeterminate)?;
        let bearer_mark =
            GtpBearerMark::new(u32::from_be_bytes(key.bearer_mark)).ok_or_else(indeterminate)?;
        let egress_dscp = match owner.egress_dscp() {
            Some(value) => Some(crate::DscpCodepoint::new(value).map_err(|_| indeterminate())?),
            None => None,
        };
        let encoded_commit = self
            .inner
            .runtime
            .marked_sport_get(ifindex, selector)?
            .ok_or_else(indeterminate)?;
        let commit = PdpContextCommit::decode(&encoded_commit);
        if !commit.is_valid()
            || commit.phase() != MarkedBearerOwnerPhase::Active
            || commit.marked_owner() != owner
        {
            return Err(indeterminate());
        }
        let uplink_source_port_policy = commit.uplink_source_port_policy();
        Ok(GtpPdpContext {
            local_teid,
            peer_teid,
            ms_address: IpAddr::V4(Ipv4Addr::from(key.ue_ip)),
            peer_address: IpAddr::V4(Ipv4Addr::from(owner.uplink_far.peer_ip)),
            link_ifindex: ifindex,
            downlink_source_port_policy: owner.downlink_binding.source_port_policy(),
            gtp_version: GtpVersion::V1,
            bearer_mark: Some(bearer_mark),
            egress_dscp,
            uplink_source_port_policy,
        })
    }

    fn inspect_local_selector_locked(
        &self,
        selector: &PdpContextLocalTeidSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        validate_gtp_version(selector.gtp_version())?;
        if selector.link_ifindex() == 0 {
            return Err(GtpuError::invalid_config(
                "pdp.selector.link_ifindex",
                "ifindex must be nonzero",
            ));
        }
        if selector.address_family() != GtpAddressFamily::Ipv4 {
            return Err(GtpuError::UnsupportedFeature {
                feature: "ebpf_ipv6_pdp_readback",
            });
        }
        self.managed_local_ip_locked(selector.link_ifindex())?;
        let local_teid = selector.local_teid().get().to_be_bytes();
        let default_pdr = self
            .inner
            .runtime
            .pdr_get(selector.link_ifindex(), local_teid)?;
        let marked_pdr = self
            .inner
            .runtime
            .marked_pdr_get(selector.link_ifindex(), local_teid)?;
        let owner_selector = self
            .inner
            .runtime
            .marked_owner_for_teid(selector.link_ifindex(), local_teid)?;
        let binding = self
            .inner
            .runtime
            .downlink_binding_get(selector.link_ifindex(), local_teid)?;
        match (default_pdr, marked_pdr, owner_selector, binding) {
            (None, None, None, None) => Ok(PdpContextReadback::Absent),
            (Some(_), None, None, Some(_)) => self
                .read_default_context_locked(selector.link_ifindex(), local_teid, None)
                .map(PdpContextReadback::Present),
            (None, Some(_), Some(owner_selector), Some(_)) => self
                .read_marked_context_locked(
                    selector.link_ifindex(),
                    owner_selector,
                    Some(local_teid),
                )
                .map(PdpContextReadback::Present),
            _ => Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pdp_context_readback",
            }),
        }
    }

    fn inspect_uplink_selector_locked(
        &self,
        selector: &PdpContextUplinkSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        validate_gtp_version(selector.gtp_version())?;
        if selector.link_ifindex() == 0 {
            return Err(GtpuError::invalid_config(
                "pdp.selector.link_ifindex",
                "ifindex must be nonzero",
            ));
        }
        self.managed_local_ip_locked(selector.link_ifindex())?;
        let ms_address = require_ipv4(selector.identity().ms_address(), "pdp.selector.ms_address")?;
        if ms_address.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "pdp.selector.ms_address",
                "MS address must not be unspecified",
            ));
        }
        let ue_ip = ms_address.octets();
        if let Some(mark) = selector.identity().bearer_mark() {
            let marked_selector = UplinkFarKey {
                ue_ip,
                bearer_mark: mark.get().to_be_bytes(),
            }
            .encode();
            let owner = self
                .inner
                .runtime
                .marked_owner_get(selector.link_ifindex(), marked_selector)?;
            let far = self
                .inner
                .runtime
                .marked_far_get(selector.link_ifindex(), marked_selector)?;
            let dscp = self
                .inner
                .runtime
                .marked_dscp_get(selector.link_ifindex(), marked_selector)?;
            let sport = self
                .inner
                .runtime
                .marked_sport_get(selector.link_ifindex(), marked_selector)?;
            return match (owner, far, dscp, sport) {
                (None, None, None, None) => Ok(PdpContextReadback::Absent),
                (Some(_), _, _, _) => self
                    .read_marked_context_locked(selector.link_ifindex(), marked_selector, None)
                    .map(PdpContextReadback::Present),
                _ => Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_pdp_context_readback",
                }),
            };
        }
        let local_teid = self
            .inner
            .runtime
            .default_teid_for_ue(selector.link_ifindex(), ue_ip)?;
        let far = self.inner.runtime.far_get(selector.link_ifindex(), ue_ip)?;
        let dscp = self
            .inner
            .runtime
            .dscp_get(selector.link_ifindex(), ue_ip)?;
        let sport = self
            .inner
            .runtime
            .sport_get(selector.link_ifindex(), ue_ip)?;
        match (local_teid, far, dscp, sport) {
            (None, None, None, None) => Ok(PdpContextReadback::Absent),
            (Some(local_teid), Some(_), _, _) => self
                .read_default_context_locked(selector.link_ifindex(), local_teid, Some(ue_ip))
                .map(PdpContextReadback::Present),
            _ => Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pdp_context_readback",
            }),
        }
    }

    fn inspect_selector_locked(
        &self,
        selector: &PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        match selector {
            PdpContextSelector::LocalTeid(selector) => self.inspect_local_selector_locked(selector),
            PdpContextSelector::Uplink(selector) => self.inspect_uplink_selector_locked(selector),
        }
    }

    fn inspect_selector_stable_locked(
        &self,
        selector: &PdpContextSelector,
    ) -> Result<Option<PdpContextReadback>, GtpuError> {
        let first = self.inspect_selector_locked(selector)?;
        let second = self.inspect_selector_locked(selector)?;
        Ok((first == second).then_some(first))
    }

    fn read_pdp_context_sync(
        &self,
        selector: PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        let _operation = self.operation_guard()?;
        let ifindex = match &selector {
            PdpContextSelector::LocalTeid(selector) => selector.link_ifindex(),
            PdpContextSelector::Uplink(selector) => selector.link_ifindex(),
        };
        if !self.inner.runtime.pdp_readback_datapath_usable(ifindex) {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pdp_context_readback",
            });
        }
        let readback = self.inspect_selector_stable_locked(&selector)?.ok_or(
            GtpuError::StateIndeterminate {
                operation: "ebpf_pdp_context_readback",
            },
        )?;
        if !self.inner.runtime.pdp_readback_datapath_usable(ifindex) {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pdp_context_readback",
            });
        }
        Ok(readback)
    }

    fn inspect_desired_axes_stable_locked(
        &self,
        desired: &GtpPdpContext,
    ) -> Result<Option<(PdpContextReadback, PdpContextReadback)>, GtpuError> {
        let local = PdpContextLocalTeidSelector::from_context(desired).ok_or_else(|| {
            GtpuError::invalid_config("pdp.link_ifindex", "ifindex must be nonzero")
        })?;
        let uplink = PdpContextUplinkSelector::from_context(desired).ok_or_else(|| {
            GtpuError::invalid_config("pdp.ms_address", "MS address must not be unspecified")
        })?;
        let first = (
            self.inspect_local_selector_locked(&local)?,
            self.inspect_uplink_selector_locked(&uplink)?,
        );
        let second = (
            self.inspect_local_selector_locked(&local)?,
            self.inspect_uplink_selector_locked(&uplink)?,
        );
        Ok((first == second).then_some(first))
    }

    fn install_pdp_context_classified_sync(
        &self,
        request: GtpPdpContext,
    ) -> Result<PdpContextInstallOutcome, GtpuError> {
        let _operation = self.operation_guard()?;
        self.validate_reconciliation_context_locked(&request)?;
        if !self
            .inner
            .runtime
            .pdp_readback_datapath_usable(request.link_ifindex)
        {
            return Ok(PdpContextInstallOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable,
            ));
        }
        let (local, uplink) = match self.inspect_desired_axes_stable_locked(&request) {
            Ok(Some(observed)) => observed,
            Ok(None) => {
                return Ok(PdpContextInstallOutcome::Indeterminate(
                    PdpContextIndeterminateReason::StateChanged,
                ));
            }
            Err(GtpuError::StateIndeterminate { .. }) => {
                return Ok(PdpContextInstallOutcome::Indeterminate(
                    PdpContextIndeterminateReason::IncompleteState,
                ));
            }
            Err(error) => return Err(error),
        };
        if !self
            .inner
            .runtime
            .pdp_readback_datapath_usable(request.link_ifindex)
        {
            return Ok(PdpContextInstallOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable,
            ));
        }
        match classify_dual_selector_state(&local, &uplink, &request) {
            DualSelectorState::Exact => Ok(PdpContextInstallOutcome::ExactAlreadyPresent),
            DualSelectorState::Conflict(conflict) => {
                Ok(PdpContextInstallOutcome::Conflict(conflict))
            }
            DualSelectorState::Indeterminate => Ok(PdpContextInstallOutcome::Indeterminate(
                PdpContextIndeterminateReason::IncompleteState,
            )),
            DualSelectorState::BothAbsent => {
                let mutation_uncertain = match self.install_pdp_context_locked(request.clone()) {
                    Ok(()) => false,
                    Err(error) if error_proves_no_requested_mutation(&error) => return Err(error),
                    Err(_error) => true,
                };
                if !self
                    .inner
                    .runtime
                    .pdp_readback_datapath_usable(request.link_ifindex)
                {
                    return Ok(PdpContextInstallOutcome::Indeterminate(
                        PdpContextIndeterminateReason::AuthorityUnavailable,
                    ));
                }
                let (local, uplink) = match self.inspect_desired_axes_stable_locked(&request) {
                    Ok(Some(observed)) => observed,
                    Err(_) => {
                        return Ok(PdpContextInstallOutcome::Indeterminate(
                            PdpContextIndeterminateReason::MutationUnconfirmed,
                        ));
                    }
                    Ok(None) => {
                        return Ok(PdpContextInstallOutcome::Indeterminate(
                            PdpContextIndeterminateReason::MutationUnconfirmed,
                        ));
                    }
                };
                if !self
                    .inner
                    .runtime
                    .pdp_readback_datapath_usable(request.link_ifindex)
                {
                    return Ok(PdpContextInstallOutcome::Indeterminate(
                        PdpContextIndeterminateReason::AuthorityUnavailable,
                    ));
                }
                match classify_dual_selector_state(&local, &uplink, &request) {
                    DualSelectorState::Exact if mutation_uncertain => {
                        Ok(PdpContextInstallOutcome::ExactAlreadyPresent)
                    }
                    DualSelectorState::Exact => Ok(PdpContextInstallOutcome::Installed),
                    DualSelectorState::Conflict(conflict) => {
                        Ok(PdpContextInstallOutcome::Conflict(conflict))
                    }
                    DualSelectorState::BothAbsent | DualSelectorState::Indeterminate => {
                        Ok(PdpContextInstallOutcome::Indeterminate(
                            PdpContextIndeterminateReason::MutationUnconfirmed,
                        ))
                    }
                }
            }
        }
    }

    fn remove_pdp_context_exact_sync(
        &self,
        expected: GtpPdpContext,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        let _operation = self.operation_guard()?;
        self.validate_reconciliation_context_locked(&expected)?;
        if !self
            .inner
            .runtime
            .pdp_readback_datapath_usable(expected.link_ifindex)
        {
            return Ok(PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable,
            ));
        }
        let (local, uplink) = match self.inspect_desired_axes_stable_locked(&expected) {
            Ok(Some(observed)) => observed,
            Ok(None) => {
                return Ok(PdpContextRemovalOutcome::Indeterminate(
                    PdpContextIndeterminateReason::StateChanged,
                ));
            }
            Err(GtpuError::StateIndeterminate { .. }) => {
                return Ok(PdpContextRemovalOutcome::Indeterminate(
                    PdpContextIndeterminateReason::IncompleteState,
                ));
            }
            Err(error) => return Err(error),
        };
        if !self
            .inner
            .runtime
            .pdp_readback_datapath_usable(expected.link_ifindex)
        {
            return Ok(PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable,
            ));
        }
        match classify_dual_selector_state(&local, &uplink, &expected) {
            DualSelectorState::BothAbsent => Ok(PdpContextRemovalOutcome::AlreadyAbsent),
            DualSelectorState::Conflict(conflict) => {
                Ok(PdpContextRemovalOutcome::Conflict(conflict))
            }
            DualSelectorState::Indeterminate => Ok(PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::IncompleteState,
            )),
            DualSelectorState::Exact => {
                let remove = RemovePdpContextRequest::from_context(&expected);
                match self.remove_pdp_context_locked(remove) {
                    Ok(()) => {}
                    Err(error) if error_proves_no_requested_mutation(&error) => return Err(error),
                    Err(_error) => {}
                }
                if !self
                    .inner
                    .runtime
                    .pdp_readback_datapath_usable(expected.link_ifindex)
                {
                    return Ok(PdpContextRemovalOutcome::Indeterminate(
                        PdpContextIndeterminateReason::AuthorityUnavailable,
                    ));
                }
                let (local, uplink) = match self.inspect_desired_axes_stable_locked(&expected) {
                    Ok(Some(observed)) => observed,
                    Err(_) => {
                        return Ok(PdpContextRemovalOutcome::Indeterminate(
                            PdpContextIndeterminateReason::MutationUnconfirmed,
                        ));
                    }
                    Ok(None) => {
                        return Ok(PdpContextRemovalOutcome::Indeterminate(
                            PdpContextIndeterminateReason::MutationUnconfirmed,
                        ));
                    }
                };
                if !self
                    .inner
                    .runtime
                    .pdp_readback_datapath_usable(expected.link_ifindex)
                {
                    return Ok(PdpContextRemovalOutcome::Indeterminate(
                        PdpContextIndeterminateReason::AuthorityUnavailable,
                    ));
                }
                match classify_dual_selector_state(&local, &uplink, &expected) {
                    DualSelectorState::BothAbsent => Ok(PdpContextRemovalOutcome::Removed),
                    DualSelectorState::Conflict(conflict) => {
                        Ok(PdpContextRemovalOutcome::Conflict(conflict))
                    }
                    DualSelectorState::Exact | DualSelectorState::Indeterminate => {
                        Ok(PdpContextRemovalOutcome::Indeterminate(
                            PdpContextIndeterminateReason::MutationUnconfirmed,
                        ))
                    }
                }
            }
        }
    }

    fn install_pdp_context_sync(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
        let _operation = self.operation_guard()?;
        self.install_pdp_context_locked(request)
    }

    fn install_pdp_context_locked(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
        validate_gtp_version(request.gtp_version)?;
        let ms_address = require_ipv4(request.ms_address, "pdp.ms_address")?;
        let peer_address = require_ipv4(request.peer_address, "pdp.peer_address")?;
        if ms_address.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "pdp.ms_address",
                "MS address must not be unspecified",
            ));
        }
        if peer_address.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "pdp.peer_address",
                "peer address must not be unspecified",
            ));
        }
        let local_ip = {
            let devices = self.devices()?;
            let device = devices
                .get(&request.link_ifindex)
                .ok_or(GtpuError::NotFound)?;
            device.local_ip
        };
        if ms_address == local_ip {
            return Err(GtpuError::invalid_config(
                "pdp.ms_address",
                "MS address must differ from the S2b-U local address",
            ));
        }
        let downlink_endpoint = GtpuDownlinkEndpoint::new(
            request.peer_address,
            IpAddr::V4(local_ip),
            request.link_ifindex,
            request.downlink_source_port_policy,
        )
        .ok_or_else(|| {
            GtpuError::invalid_config(
                "pdp.downlink_endpoint",
                "peer, local endpoint, and ingress attachment must form one canonical identity",
            )
        })?;
        let binding_value = encode_downlink_endpoint(&downlink_endpoint)?;

        if !self
            .inner
            .runtime
            .downlink_endpoint_binding_datapath_usable(request.link_ifindex)
        {
            return Err(GtpuError::io(
                "ebpf_downlink_endpoint_datapath",
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "live downlink endpoint-binding datapath identity is unavailable",
                ),
            ));
        }

        let far_value = UplinkFar {
            peer_ip: peer_address.octets(),
            local_ip: local_ip.octets(),
            o_teid: request.peer_teid.get().to_be_bytes(),
        }
        .encode();
        let pdr_key = request.local_teid.get().to_be_bytes();
        let dscp_value = request.egress_dscp.map(|value| [value.get()]);
        let commit = PdpContextCommit::new(
            pdr_key,
            UplinkFar::decode(&far_value),
            dscp_value.map(|value| value[0]),
            DownlinkEndpointBinding::decode(&binding_value),
            request.uplink_source_port_policy,
            MarkedBearerOwnerPhase::Active,
        )
        .ok_or_else(|| {
            GtpuError::invalid_config(
                "pdp.uplink_source_port_policy",
                "uplink source-port policy and PDP graph must be canonical",
            )
        })?;
        if request.bearer_mark.is_some()
            && !self
                .inner
                .runtime
                .bearer_mark_datapath_usable(request.link_ifindex)
        {
            return Err(GtpuError::io(
                "ebpf_bearer_mark_datapath",
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "live per-bearer mark datapath identity is unavailable",
                ),
            ));
        }
        if dscp_value.is_some()
            && !self
                .inner
                .runtime
                .dscp_datapath_usable(request.link_ifindex)
        {
            return Err(GtpuError::io(
                "ebpf_dscp_datapath",
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "live uplink DSCP datapath identity is unavailable",
                ),
            ));
        }
        if !self
            .inner
            .runtime
            .source_port_datapath_usable(request.link_ifindex)
        {
            return Err(GtpuError::io(
                "ebpf_source_port_datapath",
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "live uplink source-port datapath identity is unavailable",
                ),
            ));
        }
        if let Some(bearer_mark) = request.bearer_mark {
            let mark_bytes = bearer_mark.get().to_be_bytes();
            let far_key = UplinkFarKey {
                ue_ip: ms_address.octets(),
                bearer_mark: mark_bytes,
            }
            .encode();
            let pdr_value = MarkedDownlinkPdr {
                ue_ip: ms_address.octets(),
                bearer_mark: mark_bytes,
            }
            .encode();
            return self.install_marked_pdp_context(
                request.link_ifindex,
                MarkedPdpState {
                    far_key,
                    far_value,
                    pdr_key,
                    pdr_value,
                    binding_value,
                    dscp_value,
                    commit,
                },
            );
        }

        let far_key = ms_address.octets();
        let pdr_value = DownlinkPdr {
            ue_ip: ms_address.octets(),
        }
        .encode();

        // A local TEID cannot move between default and marked namespaces
        // through an install retry. Removal must linearize that transition.
        if self
            .inner
            .runtime
            .marked_owner_for_teid(request.link_ifindex, pdr_key)?
            .is_some()
            || self
                .inner
                .runtime
                .marked_pdr_get(request.link_ifindex, pdr_key)?
                .is_some()
        {
            return Err(GtpuError::AlreadyExists);
        }
        if self
            .inner
            .runtime
            .default_ue_for_teid(request.link_ifindex, pdr_key)?
            .is_some_and(|existing_ue| existing_ue != far_key)
        {
            return Err(GtpuError::AlreadyExists);
        }

        let existing_far = self.inner.runtime.far_get(request.link_ifindex, far_key)?;
        let existing_pdr = self.inner.runtime.pdr_get(request.link_ifindex, pdr_key)?;
        let existing_binding = self
            .inner
            .runtime
            .downlink_binding_get(request.link_ifindex, pdr_key)?;
        let existing_dscp = self.inner.runtime.dscp_get(request.link_ifindex, far_key)?;
        let existing_commit = self
            .inner
            .runtime
            .sport_get(request.link_ifindex, far_key)?;
        let existing_commit = existing_commit
            .map(|encoded| {
                let commit = PdpContextCommit::decode(&encoded);
                commit
                    .is_valid()
                    .then_some(commit)
                    .ok_or(GtpuError::StateIndeterminate {
                        operation: "ebpf_install_pdp_context",
                    })
            })
            .transpose()?;
        let indexed_teid = self
            .inner
            .runtime
            .default_teid_for_ue(request.link_ifindex, far_key)?;
        if indexed_teid.is_some_and(|existing| existing != pdr_key) {
            return Err(GtpuError::AlreadyExists);
        }
        if indexed_teid.is_none() && existing_commit.is_none() {
            let pdr_claims_requested_ue = existing_pdr
                .as_ref()
                .is_some_and(|encoded| DownlinkPdr::decode(encoded).ue_ip == far_key);
            if pdr_claims_requested_ue
                || existing_pdr.is_none() && (existing_far.is_some() || existing_binding.is_some())
            {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_install_pdp_context",
                });
            }
        }
        let active_commit = commit.with_phase(MarkedBearerOwnerPhase::Active);
        let pending_commit = commit.with_phase(MarkedBearerOwnerPhase::Pending);
        if let Some(existing_commit) = existing_commit {
            if existing_commit.local_teid() != pdr_key {
                return Err(GtpuError::AlreadyExists);
            }
            match existing_commit.phase() {
                MarkedBearerOwnerPhase::Removing => {
                    self.finish_default_commit_removal(
                        request.link_ifindex,
                        far_key,
                        existing_commit,
                    )?;
                    return Err(GtpuError::RetryRequired {
                        operation: "ebpf_install_after_removal",
                    });
                }
                MarkedBearerOwnerPhase::Pending => {
                    if existing_commit != pending_commit {
                        return Err(GtpuError::AlreadyExists);
                    }
                    return self
                        .publish_default_commit(
                            request.link_ifindex,
                            far_key,
                            pdr_value,
                            active_commit,
                        )
                        .map_err(|_| GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        });
                }
                MarkedBearerOwnerPhase::Active => {
                    let live_far = existing_far.map(|value| UplinkFar::decode(&value)).ok_or(
                        GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        },
                    )?;
                    let live_binding = existing_binding
                        .map(|value| DownlinkEndpointBinding::decode(&value))
                        .ok_or(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        })?;
                    if existing_pdr != Some(pdr_value)
                        || !existing_commit.authorizes_graph(
                            pdr_key,
                            &live_far,
                            existing_dscp.map(|value| value[0]),
                            &live_binding,
                        )
                    {
                        return Err(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        });
                    }
                    if existing_commit == active_commit {
                        return Ok(());
                    }
                    self.inner.runtime.sport_insert(
                        request.link_ifindex,
                        far_key,
                        pending_commit.encode(),
                    )?;
                    let replace = self.publish_default_commit(
                        request.link_ifindex,
                        far_key,
                        pdr_value,
                        active_commit,
                    );
                    if let Err(source) = replace {
                        return self.restore_default_commit(
                            request.link_ifindex,
                            far_key,
                            pdr_value,
                            existing_commit,
                            source,
                        );
                    }
                    return Ok(());
                }
            }
        }

        if existing_far.is_some() || existing_pdr.is_some() || existing_binding.is_some() {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            });
        }
        if existing_dscp.is_some_and(|value| value[0] > 63) {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            });
        }
        self.inner
            .runtime
            .default_selector_insert(request.link_ifindex, far_key, pdr_key)?;
        if let Err(error) =
            self.inner
                .runtime
                .sport_insert(request.link_ifindex, far_key, pending_commit.encode())
        {
            return self.rollback_default_selector(request.link_ifindex, far_key, pdr_key, error);
        }
        if let Err(source) =
            self.publish_default_commit(request.link_ifindex, far_key, pdr_value, active_commit)
        {
            return match self.finish_default_commit_removal(
                request.link_ifindex,
                far_key,
                pending_commit,
            ) {
                Ok(()) => Err(source),
                Err(_) => Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_install_pdp_context",
                }),
            };
        }
        Ok(())
    }

    fn publish_default_commit(
        &self,
        ifindex: u32,
        ue_ip: [u8; 4],
        pdr_value: [u8; DOWNLINK_PDR_VALUE_LEN],
        active_commit: PdpContextCommit,
    ) -> Result<(), GtpuError> {
        match active_commit.egress_dscp() {
            Some(value) => self.inner.runtime.dscp_insert(ifindex, ue_ip, [value])?,
            None => {
                self.inner.runtime.dscp_remove(ifindex, ue_ip)?;
            }
        }
        self.inner
            .runtime
            .far_insert(ifindex, ue_ip, active_commit.uplink_far().encode())?;
        self.inner.runtime.downlink_binding_insert(
            ifindex,
            active_commit.local_teid(),
            active_commit.downlink_binding().encode(),
        )?;
        self.inner
            .runtime
            .pdr_insert(ifindex, active_commit.local_teid(), pdr_value)?;
        // Active is the sole forwarding commit and is always published last.
        self.inner
            .runtime
            .sport_insert(ifindex, ue_ip, active_commit.encode())
    }

    fn restore_default_commit(
        &self,
        ifindex: u32,
        ue_ip: [u8; 4],
        pdr_value: [u8; DOWNLINK_PDR_VALUE_LEN],
        old_commit: PdpContextCommit,
        source: GtpuError,
    ) -> Result<(), GtpuError> {
        if self
            .publish_default_commit(ifindex, ue_ip, pdr_value, old_commit)
            .is_ok()
        {
            Err(source)
        } else {
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            })
        }
    }

    fn finish_default_commit_removal(
        &self,
        ifindex: u32,
        ue_ip: [u8; 4],
        commit: PdpContextCommit,
    ) -> Result<(), GtpuError> {
        if !commit.is_valid()
            || commit.downlink_binding().ingress_ifindex() != ifindex
            || ue_ip == [0; 4]
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        let local_teid = commit.local_teid();
        if self
            .inner
            .runtime
            .marked_owner_for_teid(ifindex, local_teid)?
            .is_some()
            || self
                .inner
                .runtime
                .marked_pdr_get(ifindex, local_teid)?
                .is_some()
            || self
                .inner
                .runtime
                .pdr_get(ifindex, local_teid)?
                .is_some_and(|value| DownlinkPdr::decode(&value).ue_ip != ue_ip)
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        let removing = commit.with_phase(MarkedBearerOwnerPhase::Removing);
        if commit.phase() != MarkedBearerOwnerPhase::Removing {
            self.inner
                .runtime
                .sport_insert(ifindex, ue_ip, removing.encode())?;
        }
        if self.inner.runtime.far_remove(ifindex, ue_ip).is_err()
            || self.inner.runtime.dscp_remove(ifindex, ue_ip).is_err()
            || self
                .inner
                .runtime
                .downlink_binding_remove(ifindex, local_teid)
                .is_err()
            || self.inner.runtime.pdr_remove(ifindex, local_teid).is_err()
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        match self.inner.runtime.sport_remove(ifindex, ue_ip) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            }),
        }
    }

    fn remove_pdp_context_sync(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        let _operation = self.operation_guard()?;
        self.remove_pdp_context_locked(request)
    }

    fn remove_pdp_context_locked(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        validate_gtp_version(request.gtp_version)?;
        if !self.devices()?.contains_key(&request.link_ifindex) {
            return Err(GtpuError::NotFound);
        }
        if !self
            .inner
            .runtime
            .pdp_cleanup_datapath_usable(request.link_ifindex)
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        let pdr_key = request.local_teid.get().to_be_bytes();
        let owner_selector = self
            .inner
            .runtime
            .marked_owner_for_teid(request.link_ifindex, pdr_key)?;
        let default_ue = self
            .inner
            .runtime
            .default_ue_for_teid(request.link_ifindex, pdr_key)?;
        let default_pdr = self.inner.runtime.pdr_get(request.link_ifindex, pdr_key)?;
        let marked_pdr = self
            .inner
            .runtime
            .marked_pdr_get(request.link_ifindex, pdr_key)?;
        let binding = self
            .inner
            .runtime
            .downlink_binding_get(request.link_ifindex, pdr_key)?;
        if owner_selector.is_some() && default_ue.is_some()
            || owner_selector.is_some() && default_pdr.is_some()
            || default_ue.is_some() && marked_pdr.is_some()
            || default_pdr.is_some() && marked_pdr.is_some()
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }

        if let Some(selector) = owner_selector {
            let encoded_commit = self
                .inner
                .runtime
                .marked_sport_get(request.link_ifindex, selector)?
                .ok_or(GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context",
                })?;
            let commit = PdpContextCommit::decode(&encoded_commit);
            if !commit.is_valid() || commit.local_teid() != pdr_key {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context",
                });
            }
            return self.finish_marked_commit_removal(request.link_ifindex, selector, commit);
        }

        if let Some(ue_ip) = default_ue {
            let encoded_commit = self
                .inner
                .runtime
                .sport_get(request.link_ifindex, ue_ip)?
                .ok_or(GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context",
                })?;
            let commit = PdpContextCommit::decode(&encoded_commit);
            if !commit.is_valid() || commit.local_teid() != pdr_key {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context",
                });
            }
            return self.finish_default_commit_removal(request.link_ifindex, ue_ip, commit);
        }

        // Removal is idempotent only when neither durable commit namespace
        // nor any TEID-addressed component owns the selector.
        if default_pdr.is_some() || marked_pdr.is_some() || binding.is_some() {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        Ok(())
    }

    fn probe_sync(&self) -> GtpuProbe {
        let env = self.inner.runtime.probe_environment();
        let (
            has_attached_device,
            dscp_datapath_usable,
            source_port_datapath_usable,
            bearer_mark_datapath_usable,
            endpoint_binding_datapath_usable,
            pmtu_datapath_usable,
        ) = self
            .devices()
            .map(|devices| {
                (
                    !devices.is_empty(),
                    !devices.is_empty()
                        && devices
                            .keys()
                            .all(|ifindex| self.inner.runtime.dscp_datapath_usable(*ifindex)),
                    !devices.is_empty()
                        && devices.keys().all(|ifindex| {
                            self.inner.runtime.source_port_datapath_usable(*ifindex)
                        }),
                    !devices.is_empty()
                        && devices.keys().all(|ifindex| {
                            self.inner.runtime.bearer_mark_datapath_usable(*ifindex)
                        }),
                    !devices.is_empty()
                        && devices.keys().all(|ifindex| {
                            self.inner
                                .runtime
                                .downlink_endpoint_binding_datapath_usable(*ifindex)
                        }),
                    !devices.is_empty()
                        && devices
                            .keys()
                            .all(|ifindex| self.inner.runtime.pmtu_datapath_usable(*ifindex)),
                )
            })
            .unwrap_or((false, false, false, false, false, false));
        let mutation_ready = env.platform_supported
            && env.bpffs_present
            && env.btf_present
            && env.net_admin_capable
            && env.bpf_capable;
        let details = if !env.platform_supported {
            Some("eBPF GTP-U datapath unsupported on this platform")
        } else if !env.bpffs_present {
            Some("bpffs is not available for map pinning")
        } else if !env.btf_present {
            Some("kernel BTF is not present")
        } else if !env.net_admin_capable {
            Some("CAP_NET_ADMIN is not effective")
        } else if !env.bpf_capable {
            Some("CAP_BPF or CAP_SYS_ADMIN is not effective")
        } else if !bearer_mark_datapath_usable {
            Some("eBPF GTP-U datapath ready; bearer-mark datapath awaits exact device attachment")
        } else if !dscp_datapath_usable {
            Some("eBPF GTP-U datapath ready; DSCP datapath awaits exact device attachment")
        } else if !source_port_datapath_usable {
            Some("eBPF GTP-U datapath ready; source-port datapath awaits exact device attachment")
        } else {
            Some("eBPF GTP-U datapath mutation ready")
        };
        GtpuProbe {
            kind: GtpuBackendKind::LinuxEbpf,
            platform_supported: env.platform_supported,
            kernel_reachable: env.bpffs_present,
            gtp_module_present: false,
            net_admin_capable: env.net_admin_capable,
            bpf_capable: env.bpf_capable,
            btf_present: env.btf_present,
            mutation_ready,
            egress_dscp_marking: if !env.platform_supported
                || !env.bpffs_present
                || !env.btf_present
            {
                GtpuCapability::Missing
            } else if !env.net_admin_capable || !env.bpf_capable {
                GtpuCapability::PermissionDenied
            } else if !has_attached_device {
                // The environment can provide marking, but its per-device
                // map does not exist until create/adopt provisions a device.
                GtpuCapability::Unknown
            } else if dscp_datapath_usable {
                GtpuCapability::Available
            } else {
                // A managed device lost or cannot access its required map.
                GtpuCapability::Missing
            },
            per_bearer_marking: if !env.platform_supported || !env.bpffs_present || !env.btf_present
            {
                GtpuCapability::Missing
            } else if !env.net_admin_capable || !env.bpf_capable {
                GtpuCapability::PermissionDenied
            } else if !has_attached_device {
                GtpuCapability::Unknown
            } else if bearer_mark_datapath_usable {
                GtpuCapability::Available
            } else {
                GtpuCapability::Missing
            },
            downlink_endpoint_binding: if !env.platform_supported
                || !env.bpffs_present
                || !env.btf_present
            {
                GtpuCapability::Missing
            } else if !env.net_admin_capable || !env.bpf_capable {
                GtpuCapability::PermissionDenied
            } else if !has_attached_device {
                GtpuCapability::Unknown
            } else if endpoint_binding_datapath_usable {
                GtpuCapability::Available
            } else {
                GtpuCapability::Missing
            },
            uplink_source_port_selection: if !env.platform_supported
                || !env.bpffs_present
                || !env.btf_present
            {
                GtpuCapability::Missing
            } else if !env.net_admin_capable || !env.bpf_capable {
                GtpuCapability::PermissionDenied
            } else if !has_attached_device {
                // The environment can provide source-port selection, but its
                // per-device maps do not exist until create/adopt provisions
                // a device.
                GtpuCapability::Unknown
            } else if source_port_datapath_usable {
                GtpuCapability::Available
            } else {
                // A managed device lost or cannot access its required maps.
                GtpuCapability::Missing
            },
            uplink_pmtu_enforcement: if !env.platform_supported
                || !env.bpffs_present
                || !env.btf_present
            {
                GtpuCapability::Missing
            } else if !env.net_admin_capable || !env.bpf_capable {
                GtpuCapability::PermissionDenied
            } else if !has_attached_device {
                // The environment can provide MTU enforcement, but its
                // per-device policy map does not exist until create/adopt
                // provisions a device.
                GtpuCapability::Unknown
            } else if pmtu_datapath_usable {
                GtpuCapability::Available
            } else {
                // A managed device lost or cannot access its required maps.
                GtpuCapability::Missing
            },
            // The tc downlink program is handoff-capable: it passes outer
            // fragments to the kernel stack unchanged. The contract is
            // complete only while the operator runs the SDK
            // GtpuReassemblyConsumer on the concrete S2b-U address; bounds
            // come from the live sysctls and are absent when unreadable.
            downlink_outer_fragment_handling: if endpoint_binding_datapath_usable {
                GtpuDownlinkFragmentContract::KernelReassemblyHandoff {
                    bounds: crate::reassembly::linux_reassembly_bounds(),
                }
            } else {
                GtpuDownlinkFragmentContract::Unsupported
            },
            details,
        }
    }
}

#[async_trait]
impl GtpuDataplaneBackend for EbpfGtpuDataplaneBackend {
    async fn create_device(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError> {
        self.run_blocking("ebpf_create_device", move |backend| {
            backend.create_device_sync(request)
        })
        .await
    }

    async fn resolve_device(&self, name: &str) -> Result<GtpDevice, GtpuError> {
        let name = name.to_string();
        self.run_blocking("ebpf_resolve_device", move |backend| {
            backend.resolve_device_sync(name)
        })
        .await
    }

    async fn remove_device(&self, device: &GtpDevice) -> Result<(), GtpuError> {
        let device = device.clone();
        self.run_blocking("ebpf_remove_device", move |backend| {
            backend.remove_device_sync(device)
        })
        .await
    }

    async fn teardown_drained_v2(
        &self,
        request: DrainedV2TeardownRequest,
    ) -> Result<DrainedV2TeardownOutcome, GtpuError> {
        self.run_blocking("ebpf_drained_v2_teardown", move |backend| {
            backend.teardown_drained_v2_sync(request)
        })
        .await
    }

    async fn install_pdp_context(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
        self.run_blocking("ebpf_install_pdp_context", move |backend| {
            backend.install_pdp_context_sync(request)
        })
        .await
    }

    async fn remove_pdp_context(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        self.run_blocking("ebpf_remove_pdp_context", move |backend| {
            backend.remove_pdp_context_sync(request)
        })
        .await
    }

    async fn read_pdp_context(
        &self,
        selector: PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        self.run_blocking("ebpf_pdp_context_readback", move |backend| {
            backend.read_pdp_context_sync(selector)
        })
        .await
    }

    async fn install_pdp_context_classified(
        &self,
        request: GtpPdpContext,
    ) -> Result<PdpContextInstallOutcome, GtpuError> {
        self.run_blocking("ebpf_pdp_context_classified_install", move |backend| {
            backend.install_pdp_context_classified_sync(request)
        })
        .await
    }

    async fn remove_pdp_context_exact(
        &self,
        expected: GtpPdpContext,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        self.run_blocking("ebpf_pdp_context_exact_removal", move |backend| {
            backend.remove_pdp_context_exact_sync(expected)
        })
        .await
    }

    fn pdp_context_reconciliation_capabilities(&self) -> PdpContextReconciliationCapabilities {
        let environment = self.inner.runtime.probe_environment();
        let capability = if !environment.platform_supported
            || !environment.bpffs_present
            || !environment.btf_present
        {
            GtpuCapability::Missing
        } else if !environment.net_admin_capable || !environment.bpf_capable {
            GtpuCapability::PermissionDenied
        } else if self.devices().is_ok_and(|devices| {
            !devices.is_empty()
                && devices
                    .keys()
                    .all(|ifindex| self.inner.runtime.pdp_readback_datapath_usable(*ifindex))
        }) {
            GtpuCapability::Available
        } else {
            GtpuCapability::Unknown
        };
        PdpContextReconciliationCapabilities {
            readback: capability,
            classified_install: capability,
            exact_removal: capability,
        }
    }

    async fn probe(&self) -> Result<GtpuProbe, GtpuError> {
        self.run_blocking("ebpf_probe", move |backend| Ok(backend.probe_sync()))
            .await
    }
}

const IFNAMSIZ: usize = 16;

fn validate_interface_name(name: &str) -> Result<(), GtpuError> {
    if name.is_empty() {
        return Err(GtpuError::invalid_config(
            "device.name",
            "name must be nonempty",
        ));
    }
    if name.len() >= IFNAMSIZ {
        return Err(GtpuError::invalid_config(
            "device.name",
            "name must fit Linux IFNAMSIZ",
        ));
    }
    if name.as_bytes().contains(&0) || name.contains('/') {
        return Err(GtpuError::invalid_config(
            "device.name",
            "name must not contain NUL or path separators",
        ));
    }
    Ok(())
}

fn validate_gtp_version(version: GtpVersion) -> Result<(), GtpuError> {
    match version {
        GtpVersion::V1 => Ok(()),
    }
}

fn require_ipv4(address: IpAddr, field: &'static str) -> Result<Ipv4Addr, GtpuError> {
    match address {
        IpAddr::V4(address) => Ok(address),
        IpAddr::V6(_) => Err(GtpuError::invalid_config(
            field,
            "eBPF GTP-U backend supports IPv4 only",
        )),
    }
}

fn encode_downlink_endpoint(
    endpoint: &GtpuDownlinkEndpoint,
) -> Result<[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN], GtpuError> {
    let address = |address| match address {
        IpAddr::V4(address) => GtpuEndpointAddress::Ipv4(address.octets()),
        IpAddr::V6(address) => GtpuEndpointAddress::Ipv6(address.octets()),
    };
    DownlinkEndpointBinding::new(
        address(endpoint.peer_address()),
        address(endpoint.local_address()),
        endpoint.ingress_ifindex(),
        endpoint.source_port_policy(),
    )
    .map(DownlinkEndpointBinding::encode)
    .ok_or_else(|| {
        GtpuError::invalid_config(
            "pdp.downlink_endpoint",
            "downlink endpoint identity must be canonical",
        )
    })
}

fn poisoned_lock() -> io::Error {
    io::Error::other("gtpu ebpf backend mutex poisoned")
}

#[cfg(target_os = "linux")]
mod aya_runtime {
    //! aya-based kernel runtime: loads the committed CO-RE object, attaches
    //! tc clsact filters, and performs pinned BPF map operations.

    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::io;
    use std::mem::ManuallyDrop;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    use std::path::Path;
    use std::sync::Mutex;

    use aya::maps::{
        Array, HashMap as BpfHashMap, IterableMap, Map, MapData, MapError, MapInfo, PerCpuArray,
    };
    use aya::programs::links::Link;
    use aya::programs::tc::{NlOptions, SchedClassifierLink, TcAttachOptions, TcError, TcHandle};
    use aya::programs::{
        loaded_programs, tc, ProgramError, ProgramInfo, SchedClassifier, TcAttachType,
    };
    use aya::{Ebpf, EbpfLoader};
    use aya_obj::btf::Btf;
    use aya_obj::generated::{
        bpf_insn, bpf_map_type, bpf_prog_type, BPF_DW, BPF_IMM, BPF_LD, BPF_PSEUDO_MAP_FD,
        BPF_PSEUDO_MAP_VALUE,
    };
    use aya_obj::maps::PinningType;
    use aya_obj::{Features as AyaObjectFeatures, Object as AyaObject};
    use opc_linux_gtpu_sys as sys;
    use sha1::{Digest as Sha1Digest, Sha1};
    use sha2::{Digest as Sha2Digest, Sha256};

    use opc_gtpu_ebpf_common::{
        default_bearer_graph_is_valid, DownlinkEndpointBinding, DownlinkPdr, GtpuUplinkMtuPolicy,
        GtpuUplinkSourcePortPolicy, MarkedBearerOwner, MarkedBearerOwnerPhase, MarkedDownlinkPdr,
        PdpContextCommit, UplinkFar, UplinkFarKey, UplinkMtuMapState,
        COUNTER_DL_BINDING_FAMILY_MISMATCH, COUNTER_DL_BINDING_INGRESS_MISMATCH,
        COUNTER_DL_BINDING_INVALID, COUNTER_DL_BINDING_LOCAL_MISMATCH,
        COUNTER_DL_BINDING_PEER_MISMATCH, COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH,
        COUNTER_DL_DECAP, COUNTER_DL_DST_MISMATCH, COUNTER_DL_MALFORMED, COUNTER_DL_UNKNOWN_TEID,
        COUNTER_UL_ENCAP, COUNTER_UL_FAR_MISS, COUNTER_UL_MTU_REJECT, COUNTER_UL_PMTU_CORRUPT,
        DOWNLINK_ENDPOINT_BINDING_VALUE_LEN, DOWNLINK_PDR_VALUE_LEN, MAP_CONFIG, MAP_COUNTERS,
        MAP_DOWNLINK_BINDING_COUNTERS, MAP_DOWNLINK_ENDPOINT_BINDING, MAP_DOWNLINK_MARK_PDR,
        MAP_DOWNLINK_PDR, MAP_MARKED_BEARER_OWNER, MAP_UPLINK_DSCP, MAP_UPLINK_FAR,
        MAP_UPLINK_MARK_DSCP, MAP_UPLINK_MARK_FAR, MAP_UPLINK_MARK_SOURCE_PORT, MAP_UPLINK_PMTU,
        MAP_UPLINK_PMTU_COUNTERS, MAP_UPLINK_SOURCE_PORT, MARKED_BEARER_OWNER_VALUE_LEN,
        MARKED_DOWNLINK_PDR_VALUE_LEN, PROG_DOWNLINK, PROG_UPLINK,
        UPLINK_BEARER_SCHEMA_MARKER_VALUE, UPLINK_DSCP_SCHEMA_MARKER_KEY,
        UPLINK_DSCP_SCHEMA_MARKER_VALUE, UPLINK_DSCP_VALUE_LEN,
        UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE, UPLINK_FAR_VALUE_LEN, UPLINK_MARK_KEY_LEN,
        UPLINK_PMTU_SCHEMA_MARKER_VALUE, UPLINK_PMTU_VALUE_LEN,
        UPLINK_SOURCE_PORT_SCHEMA_MARKER_VALUE, UPLINK_SOURCE_PORT_VALUE_LEN,
    };

    use super::{
        EbpfEnvironment, EbpfGtpuDatapathCounters, EbpfGtpuDatapathSnapshot, EbpfGtpuRuntime,
    };
    use crate::{
        DrainedV2TeardownOutcome, DrainedV2TeardownProgress, DrainedV2TeardownRefusal, GtpuError,
    };

    /// The committed CO-RE datapath object built by
    /// `scripts/build-gtpu-ebpf.sh` from `crates/opc-gtpu-dataplane-ebpf`.
    const DATAPATH_OBJECT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf/opc-gtpu-datapath.bpf.o"
    ));
    /// Frozen pre-bearer-mark object used only to prove exact live v1 filter
    /// ownership during the bounded empty-v1-to-endpoint-v3 pin migration.
    const LEGACY_V1_DATAPATH_OBJECT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf/opc-gtpu-datapath-v1.bpf.o"
    ));
    const LEGACY_V2_OWNER_VALUE_LEN: usize = 20;
    const LEGACY_V2_TEARDOWN_PROOF_MAP: &str = "GTPU_V2_TEARDOWN";
    const LEGACY_V2_TEARDOWN_PROOF_LEN: usize = 96;
    const LEGACY_V2_TEARDOWN_MAGIC: [u8; 8] = *b"OPCV2TD2";
    const LEGACY_V2_DATAPATH_SHA256: [u8; 32] = [
        0x7d, 0x0c, 0x1b, 0x45, 0x2a, 0xd5, 0x62, 0xd4, 0xc8, 0xc2, 0x86, 0xbf, 0x05, 0xa4, 0xc5,
        0x30, 0x8f, 0x6f, 0xd5, 0xb4, 0xc6, 0x77, 0xcc, 0x3c, 0x21, 0x25, 0xb1, 0x94, 0x86, 0x04,
        0x64, 0xa5,
    ];

    /// Parse-only authority for the frozen endpoint-unbound bearer-v2 object.
    ///
    /// The embedded bytes are private to this child module. Production callers
    /// can obtain only the derived, provenance-checked program tags, so the
    /// maintenance runtime has no raw-object value it could pass to a loader.
    mod legacy_v2_artifact {
        use super::{AyaGtpuRuntime, GtpuError, LegacyV2ProgramTags};

        const OBJECT: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/bpf/opc-gtpu-datapath-v2.bpf.o"
        ));

        pub(super) fn program_tags() -> Result<(LegacyV2ProgramTags, LegacyV2ProgramTags), GtpuError>
        {
            AyaGtpuRuntime::legacy_v2_artifact_tags_from(OBJECT)
        }

        #[cfg(test)]
        mod tests {
            use sha2::{Digest, Sha256};

            use super::super::{
                AyaGtpuRuntime, GtpuError, DATAPATH_OBJECT, LEGACY_V2_DATAPATH_SHA256,
            };
            use super::OBJECT;

            #[test]
            fn embedded_object_has_exact_provenance_and_rejects_other_bytes() {
                assert_eq!(&Sha256::digest(OBJECT)[..], &LEGACY_V2_DATAPATH_SHA256);

                let mut tampered = OBJECT.to_vec();
                tampered[0] ^= 0xff;
                assert!(matches!(
                    AyaGtpuRuntime::legacy_v2_artifact_tags_from(&tampered),
                    Err(GtpuError::StateIndeterminate {
                        operation: "ebpf_legacy_v2_object_provenance"
                    })
                ));
                assert!(matches!(
                    AyaGtpuRuntime::legacy_v2_artifact_tags_from(DATAPATH_OBJECT),
                    Err(GtpuError::StateIndeterminate {
                        operation: "ebpf_legacy_v2_object_provenance"
                    })
                ));
            }
        }
    }
    const LEGACY_V2_MAP_NAMES: [&str; 9] = [
        MAP_UPLINK_FAR,
        MAP_UPLINK_MARK_FAR,
        MAP_UPLINK_DSCP,
        MAP_UPLINK_MARK_DSCP,
        MAP_DOWNLINK_PDR,
        MAP_DOWNLINK_MARK_PDR,
        MAP_MARKED_BEARER_OWNER,
        MAP_COUNTERS,
        MAP_CONFIG,
    ];

    #[derive(Clone, Copy)]
    struct LegacyV2MapSpec {
        name: &'static str,
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    }

    const LEGACY_V2_MAP_SPECS: [LegacyV2MapSpec; 9] = [
        LegacyV2MapSpec {
            name: MAP_UPLINK_FAR,
            map_type: bpf_map_type::BPF_MAP_TYPE_HASH as u32,
            key_size: 4,
            value_size: UPLINK_FAR_VALUE_LEN as u32,
            max_entries: 65_536,
        },
        LegacyV2MapSpec {
            name: MAP_UPLINK_MARK_FAR,
            map_type: bpf_map_type::BPF_MAP_TYPE_HASH as u32,
            key_size: UPLINK_MARK_KEY_LEN as u32,
            value_size: UPLINK_FAR_VALUE_LEN as u32,
            max_entries: 65_536,
        },
        LegacyV2MapSpec {
            name: MAP_UPLINK_DSCP,
            map_type: bpf_map_type::BPF_MAP_TYPE_HASH as u32,
            key_size: 4,
            value_size: UPLINK_DSCP_VALUE_LEN as u32,
            max_entries: 65_536,
        },
        LegacyV2MapSpec {
            name: MAP_UPLINK_MARK_DSCP,
            map_type: bpf_map_type::BPF_MAP_TYPE_HASH as u32,
            key_size: UPLINK_MARK_KEY_LEN as u32,
            value_size: UPLINK_DSCP_VALUE_LEN as u32,
            max_entries: 65_536,
        },
        LegacyV2MapSpec {
            name: MAP_DOWNLINK_PDR,
            map_type: bpf_map_type::BPF_MAP_TYPE_HASH as u32,
            key_size: 4,
            value_size: DOWNLINK_PDR_VALUE_LEN as u32,
            max_entries: 65_536,
        },
        LegacyV2MapSpec {
            name: MAP_DOWNLINK_MARK_PDR,
            map_type: bpf_map_type::BPF_MAP_TYPE_HASH as u32,
            key_size: 4,
            value_size: MARKED_DOWNLINK_PDR_VALUE_LEN as u32,
            max_entries: 65_536,
        },
        LegacyV2MapSpec {
            name: MAP_MARKED_BEARER_OWNER,
            map_type: bpf_map_type::BPF_MAP_TYPE_HASH as u32,
            key_size: UPLINK_MARK_KEY_LEN as u32,
            value_size: LEGACY_V2_OWNER_VALUE_LEN as u32,
            max_entries: 65_536,
        },
        LegacyV2MapSpec {
            name: MAP_COUNTERS,
            map_type: bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as u32,
            key_size: 4,
            value_size: 8,
            max_entries: 6,
        },
        LegacyV2MapSpec {
            name: MAP_CONFIG,
            map_type: bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
            key_size: 4,
            value_size: 4,
            max_entries: 1,
        },
    ];

    const TC_HANDLE: TcHandle = TcHandle::new(0, 1);
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_BPF: u32 = 39;

    #[derive(Debug, Default)]
    pub(super) struct AyaGtpuRuntime {
        devices: Mutex<HashMap<u32, LoadedDevice>>,
    }

    struct LoadedDevice {
        ebpf: Ebpf,
        marked_owner_by_teid: HashMap<[u8; 4], [u8; UPLINK_MARK_KEY_LEN]>,
        default_teid_by_ue: HashMap<[u8; 4], [u8; 4]>,
        // Aya's netlink tc link drops by priority/handle rather than by
        // program ID. Keep the links kernel-owned and detach them only after
        // proving that both live slots still contain our exact program IDs.
        links: DatapathLinks,
        pin_dir: std::path::PathBuf,
        tc_priority: u16,
        datapath_identity: DatapathIdentity,
        // An abstract AF_UNIX address is exclusive within the current network
        // namespace and is released by the kernel on process exit. Holding
        // this socket prevents independently constructed backends/processes
        // from concurrently reconciling the same pin/interface state while
        // still permitting crash/restart adoption.
        _reconciler_ownership: UnixDatagram,
    }

    impl std::fmt::Debug for LoadedDevice {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("LoadedDevice")
                .field("marked_owner_count", &self.marked_owner_by_teid.len())
                .field("default_owner_count", &self.default_teid_by_ue.len())
                .field("tc_priority", &self.tc_priority)
                .field("datapath_identity", &self.datapath_identity)
                .finish_non_exhaustive()
        }
    }

    struct PdpHostIndexes {
        marked_owner_by_teid: HashMap<[u8; 4], [u8; UPLINK_MARK_KEY_LEN]>,
        default_teid_by_ue: HashMap<[u8; 4], [u8; 4]>,
        default_commits: Vec<([u8; 4], PdpContextCommit)>,
        marked_commits: Vec<([u8; UPLINK_MARK_KEY_LEN], PdpContextCommit)>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ProgramIdentity {
        program_id: u32,
        program_tag: u64,
        map_ids: Vec<u32>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DatapathIdentity {
        uplink: ProgramIdentity,
        downlink: ProgramIdentity,
        pins: PinnedMapIdentity,
    }

    /// Kernel map IDs keyed by their durable pin names. Keeping the mapping
    /// name-sensitive prevents cleanup from treating a swapped/replaced pin
    /// set as the maps held open by this loader.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct PinnedMapIdentity {
        uplink_far: u32,
        uplink_mark_far: u32,
        uplink_dscp: u32,
        uplink_mark_dscp: u32,
        uplink_source_port: u32,
        uplink_mark_source_port: u32,
        uplink_pmtu: u32,
        uplink_pmtu_counters: u32,
        downlink_pdr: u32,
        downlink_mark_pdr: u32,
        downlink_binding: u32,
        marked_owner: u32,
        counters: u32,
        downlink_binding_counters: u32,
        config: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct LegacyV2DatapathIdentity {
        uplink: LegacyV2ProgramIdentity,
        downlink: LegacyV2ProgramIdentity,
        map_ids: [u32; LEGACY_V2_MAP_NAMES.len()],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct LegacyV2ProgramIdentity {
        tags: LegacyV2ProgramTags,
        map_ids: Vec<u32>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct LegacyV2ProgramTags {
        sha1: u64,
        sha256: u64,
    }

    impl LegacyV2ProgramTags {
        fn contains(self, tag: u64) -> bool {
            tag == self.sha1 || tag == self.sha256
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LegacyV2IdentityError {
        Mismatch,
        Indeterminate,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LegacyV2ProofCommitError {
        /// No durable proof publication was observed after the attempted
        /// operation, so no intentional teardown mutation was committed.
        BeforePublication,
        /// Publication succeeded, or may have succeeded, but exact readback
        /// could not be completed. The proof path must remain a current-schema fence.
        PublicationIndeterminate,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum UnprovenHookAbsence {
        Absent,
        Occupied,
        Indeterminate,
    }

    fn classify_unproven_hook_absence<T, E>(
        uplink: Result<Option<T>, E>,
        downlink: Result<Option<T>, E>,
    ) -> UnprovenHookAbsence {
        match (uplink, downlink) {
            (Err(_), _) | (_, Err(_)) => UnprovenHookAbsence::Indeterminate,
            (Ok(None), Ok(None)) => UnprovenHookAbsence::Absent,
            (Ok(_), Ok(_)) => UnprovenHookAbsence::Occupied,
        }
    }

    fn classify_path_metadata<T>(
        result: io::Result<T>,
        operation: &'static str,
    ) -> Result<bool, GtpuError> {
        match result {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(GtpuError::io(operation, error)),
        }
    }

    fn legacy_v2_path_is_present(path: &Path, operation: &'static str) -> Result<bool, GtpuError> {
        classify_path_metadata(fs::symlink_metadata(path), operation)
    }

    #[derive(Debug, Default)]
    struct LegacyV2FarObservation {
        marker: Option<[u8; UPLINK_FAR_VALUE_LEN]>,
        marker_duplicate: bool,
        forwarding_state_present: bool,
    }

    impl LegacyV2FarObservation {
        fn observe(&mut self, key: [u8; 4], value: [u8; UPLINK_FAR_VALUE_LEN]) {
            if key == UPLINK_DSCP_SCHEMA_MARKER_KEY {
                // A kernel hash map cannot expose the same key twice. Preserve
                // the first observation nevertheless so an impossible duplicate
                // cannot make a corrupt marker look canonical.
                if self.marker.is_none() {
                    self.marker = Some(value);
                } else {
                    self.marker_duplicate = true;
                }
            } else {
                self.forwarding_state_present = true;
            }
        }

        fn finish(self) -> Result<bool, LegacyV2IdentityError> {
            if self.marker_duplicate {
                return Err(LegacyV2IdentityError::Mismatch);
            }
            match self.marker {
                Some(value) if value == UPLINK_BEARER_SCHEMA_MARKER_VALUE => {
                    Ok(!self.forwarding_state_present)
                }
                Some(_) => Err(LegacyV2IdentityError::Mismatch),
                None => Err(LegacyV2IdentityError::Indeterminate),
            }
        }
    }

    fn validate_legacy_v2_config_identity(local_ip: [u8; 4]) -> Result<(), LegacyV2IdentityError> {
        if local_ip == [0; 4] {
            Err(LegacyV2IdentityError::Mismatch)
        } else {
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct LegacyV2TeardownRecord {
        ifindex: u32,
        tc_priority: u16,
        uplink_program_id: u32,
        downlink_program_id: u32,
        uplink_program_tag: u64,
        downlink_program_tag: u64,
        map_ids: [u32; LEGACY_V2_MAP_NAMES.len()],
        proof_map_id: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct LegacyV2TeardownProof {
        record: LegacyV2TeardownRecord,
        map_id: u32,
    }

    impl LegacyV2TeardownRecord {
        fn from_identity(
            ifindex: u32,
            tc_priority: u16,
            identity: &LegacyV2DatapathIdentity,
            uplink_program: (u32, u64),
            downlink_program: (u32, u64),
        ) -> Self {
            Self {
                ifindex,
                tc_priority,
                uplink_program_id: uplink_program.0,
                downlink_program_id: downlink_program.0,
                uplink_program_tag: uplink_program.1,
                downlink_program_tag: downlink_program.1,
                map_ids: identity.map_ids,
                proof_map_id: 0,
            }
        }

        fn bind_to_proof_map(self, proof_map_id: u32) -> Option<Self> {
            (self.proof_map_id == 0 && proof_map_id != 0).then_some(Self {
                proof_map_id,
                ..self
            })
        }

        fn matches_unbound(self, unbound: Self) -> bool {
            unbound.proof_map_id == 0
                && self
                    == Self {
                        proof_map_id: self.proof_map_id,
                        ..unbound
                    }
        }

        fn encode(self) -> [u8; LEGACY_V2_TEARDOWN_PROOF_LEN] {
            let mut encoded = [0_u8; LEGACY_V2_TEARDOWN_PROOF_LEN];
            encoded[..8].copy_from_slice(&LEGACY_V2_TEARDOWN_MAGIC);
            encoded[8..12].copy_from_slice(&self.ifindex.to_ne_bytes());
            encoded[12..14].copy_from_slice(&self.tc_priority.to_ne_bytes());
            encoded[16..20].copy_from_slice(&self.uplink_program_id.to_ne_bytes());
            encoded[20..24].copy_from_slice(&self.downlink_program_id.to_ne_bytes());
            encoded[24..32].copy_from_slice(&self.uplink_program_tag.to_ne_bytes());
            encoded[32..40].copy_from_slice(&self.downlink_program_tag.to_ne_bytes());
            for (index, map_id) in self.map_ids.into_iter().enumerate() {
                let offset = 40 + index * 4;
                encoded[offset..offset + 4].copy_from_slice(&map_id.to_ne_bytes());
            }
            encoded[76..80].copy_from_slice(&self.proof_map_id.to_ne_bytes());
            let checksum = teardown_record_checksum(&encoded[..88]);
            encoded[88..96].copy_from_slice(&checksum.to_ne_bytes());
            encoded
        }

        fn decode(encoded: &[u8; LEGACY_V2_TEARDOWN_PROOF_LEN]) -> Option<Self> {
            let read_u32 = |offset: usize| {
                encoded
                    .get(offset..offset + 4)
                    .and_then(|value| value.try_into().ok())
                    .map(u32::from_ne_bytes)
            };
            let read_u64 = |offset: usize| {
                encoded
                    .get(offset..offset + 8)
                    .and_then(|value| value.try_into().ok())
                    .map(u64::from_ne_bytes)
            };
            if encoded[..8] != LEGACY_V2_TEARDOWN_MAGIC
                || encoded[14..16] != [0; 2]
                || encoded[80..88] != [0; 8]
                || read_u64(88)? != teardown_record_checksum(&encoded[..88])
            {
                return None;
            }
            let mut map_ids = [0_u32; LEGACY_V2_MAP_NAMES.len()];
            for (index, map_id) in map_ids.iter_mut().enumerate() {
                *map_id = read_u32(40 + index * 4)?;
            }
            let record = Self {
                ifindex: read_u32(8)?,
                tc_priority: u16::from_ne_bytes(encoded[12..14].try_into().ok()?),
                uplink_program_id: read_u32(16)?,
                downlink_program_id: read_u32(20)?,
                uplink_program_tag: read_u64(24)?,
                downlink_program_tag: read_u64(32)?,
                map_ids,
                proof_map_id: read_u32(76)?,
            };
            (record.ifindex != 0
                && record.uplink_program_id != 0
                && record.downlink_program_id != 0
                && record.uplink_program_tag != 0
                && record.downlink_program_tag != 0
                && record.proof_map_id != 0
                && record.map_ids.iter().all(|map_id| *map_id != 0))
            .then_some(record)
        }

        fn uplink_map_ids(self) -> [u32; 7] {
            [
                self.map_ids[0],
                self.map_ids[1],
                self.map_ids[2],
                self.map_ids[3],
                self.map_ids[6],
                self.map_ids[7],
                self.map_ids[8],
            ]
        }

        fn downlink_map_ids(self) -> [u32; 4] {
            [
                self.map_ids[4],
                self.map_ids[5],
                self.map_ids[6],
                self.map_ids[7],
            ]
        }
    }

    fn teardown_record_checksum(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }

    fn legacy_v2_proof_map_abi_is_exact(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> bool {
        map_type == bpf_map_type::BPF_MAP_TYPE_ARRAY as u32
            && key_size == 4
            && value_size == LEGACY_V2_TEARDOWN_PROOF_LEN as u32
            && max_entries == 1
            && map_flags == 0
    }

    fn legacy_v2_proof_record_is_authoritative(
        record: LegacyV2TeardownRecord,
        proof_map_id: u32,
        uplink_tags: LegacyV2ProgramTags,
        downlink_tags: LegacyV2ProgramTags,
    ) -> bool {
        record.proof_map_id == proof_map_id
            && proof_map_id != 0
            && uplink_tags.contains(record.uplink_program_tag)
            && downlink_tags.contains(record.downlink_program_tag)
    }

    fn legacy_v2_normalized_program_bytes(instructions: &[bpf_insn]) -> Vec<u8> {
        let mut normalized = Vec::with_capacity(instructions.len().saturating_mul(8));
        let mut prior_was_map_load = false;
        for instruction in instructions {
            let is_map_load = !prior_was_map_load
                && instruction.code == (BPF_LD | BPF_IMM | BPF_DW) as u8
                && matches!(
                    u32::from(instruction.src_reg()),
                    BPF_PSEUDO_MAP_FD | BPF_PSEUDO_MAP_VALUE
                );
            let is_map_load_tail = prior_was_map_load
                && instruction.code == 0
                && instruction.dst_reg() == 0
                && instruction.src_reg() == 0
                && instruction.off == 0;
            let immediate = if is_map_load || is_map_load_tail {
                0
            } else {
                instruction.imm
            };
            let registers = if cfg!(target_endian = "little") {
                instruction.dst_reg() | instruction.src_reg() << 4
            } else {
                instruction.src_reg() | instruction.dst_reg() << 4
            };
            normalized.extend_from_slice(&[instruction.code, registers]);
            normalized.extend_from_slice(&instruction.off.to_ne_bytes());
            normalized.extend_from_slice(&immediate.to_ne_bytes());
            prior_was_map_load = is_map_load;
        }
        normalized
    }

    fn legacy_v2_tags_from_normalized(bytes: &[u8]) -> LegacyV2ProgramTags {
        let sha1 = Sha1::digest(bytes);
        let sha256 = Sha256::digest(bytes);
        let mut sha1_tag = [0_u8; 8];
        let mut sha256_tag = [0_u8; 8];
        sha1_tag.copy_from_slice(&sha1[..8]);
        sha256_tag.copy_from_slice(&sha256[..8]);
        LegacyV2ProgramTags {
            sha1: u64::from_be_bytes(sha1_tag),
            sha256: u64::from_be_bytes(sha256_tag),
        }
    }

    fn legacy_v2_program_tags(instructions: &[bpf_insn]) -> LegacyV2ProgramTags {
        legacy_v2_tags_from_normalized(&legacy_v2_normalized_program_bytes(instructions))
    }

    fn legacy_v2_object_instructions<'a>(
        object: &'a AyaObject,
        name: &str,
    ) -> Result<&'a [bpf_insn], GtpuError> {
        let program = object
            .programs
            .get(name)
            .ok_or_else(|| state_indeterminate("ebpf_legacy_v2_object_identity"))?;
        let function = object
            .functions
            .get(&program.function_key())
            .ok_or_else(|| state_indeterminate("ebpf_legacy_v2_object_identity"))?;
        Ok(&function.instructions)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LegacyV2HookState {
        Absent,
        Exact,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum BearerSchemaState {
        /// Empty pin directory created for a new provisioning transaction.
        Fresh,
        /// Pre-DSCP retained pins with no additive map or marker.
        LegacyV0,
        /// DSCP map exists but the v1 marker commit did not complete.
        V1Uncommitted,
        /// The additive DSCP map was committed, but bearer maps were not.
        DscpV1,
        /// Every additive per-bearer map was committed.
        BearerV2,
        /// Every PDR has canonical outer-endpoint provenance state.
        EndpointV3,
        /// The additive uplink source-port maps were committed.
        SourcePortV4,
        /// The additive uplink MTU policy maps were committed.
        PmtuV5,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PinCleanupHookProof {
        /// No attach operation was reached; require both slots to be empty.
        RequireEmptySlots,
        /// The fresh-pin transaction proves no SDK hook remains. A static
        /// foreign occupant predates the newly created map IDs and cannot
        /// reference them. This does not cover concurrent external mutation,
        /// which is excluded by the documented exclusive-writer boundary.
        NoDesiredHooks,
    }

    #[derive(Debug)]
    struct DatapathLinks {
        uplink: ManuallyDrop<SchedClassifierLink>,
        downlink: ManuallyDrop<SchedClassifierLink>,
    }

    #[derive(Debug)]
    struct AttachedDatapath {
        identity: DatapathIdentity,
        links: DatapathLinks,
        replaced_existing: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FilterOwner {
        name: String,
        program_id: Option<u32>,
    }

    impl AyaGtpuRuntime {
        pub(super) fn new() -> Self {
            Self::default()
        }

        fn acquire_reconciler_ownership(
            pin_dir: &Path,
            ifindex: u32,
        ) -> Result<UnixDatagram, GtpuError> {
            // A deterministic FNV-1a digest keeps the abstract address below
            // sockaddr_un's length limit without exposing the configured
            // filesystem path in errors or process listings.
            let mut digest = 0xcbf2_9ce4_8422_2325_u64;
            for byte in pin_dir
                .as_os_str()
                .as_bytes()
                .iter()
                .copied()
                .chain(ifindex.to_ne_bytes())
            {
                digest ^= u64::from(byte);
                digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
            }
            let name = format!("opc-gtpu-reconciler-{digest:016x}");
            let address = SocketAddr::from_abstract_name(name.as_bytes())
                .map_err(|error| GtpuError::io("ebpf_reconciler_ownership", error))?;
            UnixDatagram::bind_addr(&address).map_err(|error| {
                if error.kind() == io::ErrorKind::AddrInUse {
                    GtpuError::AlreadyExists
                } else {
                    GtpuError::io("ebpf_reconciler_ownership", error)
                }
            })
        }

        fn canonical_pin_dir(pin_dir: &Path) -> Result<std::path::PathBuf, GtpuError> {
            fs::create_dir_all(pin_dir)
                .map_err(|error| GtpuError::io("ebpf_pin_dir_create", error))?;
            fs::canonicalize(pin_dir)
                .map_err(|error| GtpuError::io("ebpf_pin_dir_canonicalize", error))
        }

        /// Remove the map pins and their directory; absence is tolerated.
        fn unpin(pin_dir: &Path) -> Result<(), GtpuError> {
            for map_name in [
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
                MAP_DOWNLINK_BINDING_COUNTERS,
                MAP_CONFIG,
            ] {
                match fs::remove_file(pin_dir.join(map_name)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(GtpuError::io("ebpf_map_unpin", error)),
                }
            }
            match fs::remove_dir(pin_dir) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(GtpuError::io("ebpf_pin_dir_remove", error)),
            }
        }

        fn load_pinned(&self, pin_dir: &Path) -> Result<Ebpf, GtpuError> {
            fs::create_dir_all(pin_dir)
                .map_err(|error| GtpuError::io("ebpf_pin_dir_create", error))?;
            // Maps are declared pinned-by-name in the object; existing pins
            // under `pin_dir` are reused, so session state survives process
            // restarts.
            EbpfLoader::new()
                .default_map_pin_directory(pin_dir)
                .load(DATAPATH_OBJECT)
                .map_err(|_| {
                    GtpuError::io("ebpf_object_load", invalid_data("bpf object load failed"))
                })
        }

        fn load_legacy_v1_pinned(&self, pin_dir: &Path) -> Result<Ebpf, GtpuError> {
            EbpfLoader::new()
                .default_map_pin_directory(pin_dir)
                .load(LEGACY_V1_DATAPATH_OBJECT)
                .map_err(|_| {
                    GtpuError::io(
                        "ebpf_legacy_object_load",
                        invalid_data("legacy bpf object load failed"),
                    )
                })
        }

        fn legacy_v2_artifact_tags_from(
            bytes: &[u8],
        ) -> Result<(LegacyV2ProgramTags, LegacyV2ProgramTags), GtpuError> {
            if Sha256::digest(bytes)[..] != LEGACY_V2_DATAPATH_SHA256 {
                return Err(state_indeterminate("ebpf_legacy_v2_object_provenance"));
            }
            let object = AyaObject::parse(bytes).map_err(|_| {
                GtpuError::io(
                    "ebpf_legacy_v2_object_parse",
                    invalid_data("legacy v2 bpf object parse failed"),
                )
            })?;
            if object.maps.len() != LEGACY_V2_MAP_SPECS.len() {
                return Err(state_indeterminate("ebpf_legacy_v2_object_identity"));
            }
            for spec in LEGACY_V2_MAP_SPECS {
                let map = object
                    .maps
                    .get(spec.name)
                    .ok_or_else(|| state_indeterminate("ebpf_legacy_v2_object_identity"))?;
                if map.map_type() != spec.map_type
                    || map.key_size() != spec.key_size
                    || map.value_size() != spec.value_size
                    || map.max_entries() != spec.max_entries
                    || map.map_flags() != 0
                    || map.pinning() != PinningType::ByName
                {
                    return Err(state_indeterminate("ebpf_legacy_v2_object_identity"));
                }
            }
            Self::object_program_tags(object)
        }

        fn object_program_tags(
            mut object: AyaObject,
        ) -> Result<(LegacyV2ProgramTags, LegacyV2ProgramTags), GtpuError> {
            if object.has_btf_relocations() {
                let btf = Btf::from_sys_fs()
                    .map_err(|_| state_indeterminate("ebpf_legacy_v2_object_btf_identity"))?;
                object
                    .relocate_btf(&btf)
                    .map_err(|_| state_indeterminate("ebpf_legacy_v2_object_btf_identity"))?;
            }
            let text_sections = object
                .functions
                .keys()
                .map(|(section_index, _)| *section_index)
                .collect::<HashSet<_>>();
            let maps = object.maps.clone();
            object
                .relocate_maps(
                    maps.iter()
                        .enumerate()
                        .map(|(index, (name, map))| (name.as_str(), (index + 1) as i32, map)),
                    &text_sections,
                )
                .map_err(|_| state_indeterminate("ebpf_legacy_v2_object_map_identity"))?;
            object
                .relocate_calls(&text_sections)
                .map_err(|_| state_indeterminate("ebpf_legacy_v2_object_call_identity"))?;
            // Aya rewrites a small set of helper calls on older kernels. The
            // frozen artifact must be tag-stable across both sanitizer modes;
            // otherwise an offline tag cannot safely identify every kernel's
            // loaded representation and maintenance must fail closed.
            let mut legacy_kernel_object = object.clone();
            legacy_kernel_object.sanitize_functions(&AyaObjectFeatures::default());
            object.sanitize_functions(&AyaObjectFeatures::new(
                true, true, true, true, true, true, true, None,
            ));
            if object.programs.len() != 2 {
                return Err(state_indeterminate("ebpf_legacy_v2_object_identity"));
            }
            let tags = |name| {
                let modern = legacy_v2_object_instructions(&object, name)?;
                let legacy = legacy_v2_object_instructions(&legacy_kernel_object, name)?;
                if legacy_v2_normalized_program_bytes(modern)
                    != legacy_v2_normalized_program_bytes(legacy)
                {
                    return Err(state_indeterminate(
                        "ebpf_legacy_v2_object_kernel_portability",
                    ));
                }
                Ok(legacy_v2_program_tags(modern))
            };
            Ok((tags(PROG_UPLINK)?, tags(PROG_DOWNLINK)?))
        }

        fn legacy_v2_artifact_tags() -> Result<(LegacyV2ProgramTags, LegacyV2ProgramTags), GtpuError>
        {
            legacy_v2_artifact::program_tags()
        }

        fn legacy_v2_directory_entries(pin_dir: &Path) -> Result<HashSet<String>, GtpuError> {
            fs::read_dir(pin_dir)
                .map_err(|error| GtpuError::io("ebpf_legacy_v2_pin_inventory", error))?
                .map(|entry| {
                    let entry = entry
                        .map_err(|error| GtpuError::io("ebpf_legacy_v2_pin_inventory", error))?;
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| state_indeterminate("ebpf_legacy_v2_pin_inventory"))
                })
                .collect()
        }

        fn legacy_v2_named_map_ids(
            pin_dir: &Path,
        ) -> Result<[u32; LEGACY_V2_MAP_NAMES.len()], LegacyV2IdentityError> {
            let mut ids = [0_u32; LEGACY_V2_MAP_NAMES.len()];
            for (index, spec) in LEGACY_V2_MAP_SPECS.iter().enumerate() {
                let info = MapInfo::from_pin(pin_dir.join(spec.name))
                    .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                let map_type = info
                    .map_type()
                    .map_err(|_| LegacyV2IdentityError::Indeterminate)?
                    as u32;
                if map_type != spec.map_type
                    || info.key_size() != spec.key_size
                    || info.value_size() != spec.value_size
                    || info.max_entries() != spec.max_entries
                    || info.map_flags() != 0
                {
                    return Err(LegacyV2IdentityError::Mismatch);
                }
                ids[index] = info.id();
            }
            Ok(ids)
        }

        fn legacy_v2_recorded_pin_count(
            pin_dir: &Path,
            record: LegacyV2TeardownRecord,
        ) -> Result<usize, GtpuError> {
            let mut present = 0;
            for (index, spec) in LEGACY_V2_MAP_SPECS.iter().enumerate() {
                let path = pin_dir.join(spec.name);
                if !legacy_v2_path_is_present(&path, "ebpf_legacy_v2_pin_identity")? {
                    continue;
                }
                let info = MapInfo::from_pin(&path)
                    .map_err(|error| map_error("ebpf_legacy_v2_pin_identity", error))?;
                let map_type = info
                    .map_type()
                    .map_err(|error| map_error("ebpf_legacy_v2_pin_identity", error))?
                    as u32;
                if info.id() != record.map_ids[index]
                    || map_type != spec.map_type
                    || info.key_size() != spec.key_size
                    || info.value_size() != spec.value_size
                    || info.max_entries() != spec.max_entries
                    || info.map_flags() != 0
                {
                    return Err(state_indeterminate("ebpf_legacy_v2_pin_identity"));
                }
                present += 1;
            }
            Ok(present)
        }

        fn legacy_v2_surviving_maps_are_drained(
            pin_dir: &Path,
        ) -> Result<bool, LegacyV2IdentityError> {
            let open = |name: &str| {
                let path = pin_dir.join(name);
                if !legacy_v2_path_is_present(&path, "ebpf_legacy_v2_drain_readback")
                    .map_err(|_| LegacyV2IdentityError::Indeterminate)?
                {
                    return Ok(None);
                }
                let data =
                    MapData::from_pin(path).map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                Map::from_map_data(data)
                    .map_err(|_| LegacyV2IdentityError::Indeterminate)
                    .map(Some)
            };
            let mut forwarding_state_present = false;
            macro_rules! observe_empty {
                ($map:expr) => {
                    if $map
                        .iter()
                        .next()
                        .transpose()
                        .map_err(|_| LegacyV2IdentityError::Indeterminate)?
                        .is_some()
                    {
                        forwarding_state_present = true;
                    }
                };
            }

            if let Some(map) = open(MAP_UPLINK_FAR)? {
                let far = BpfHashMap::<MapData, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
                    .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                let mut observation = LegacyV2FarObservation::default();
                for entry in far.iter() {
                    let (key, value) = entry.map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                    observation.observe(key, value);
                }
                forwarding_state_present |= !observation.finish()?;
            }
            if let Some(map) = open(MAP_UPLINK_MARK_FAR)? {
                let marked_far = BpfHashMap::<
                    MapData,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_FAR_VALUE_LEN],
                >::try_from(map)
                .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                observe_empty!(marked_far);
            }
            if let Some(map) = open(MAP_UPLINK_DSCP)? {
                let dscp =
                    BpfHashMap::<MapData, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(map)
                        .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                observe_empty!(dscp);
            }
            if let Some(map) = open(MAP_UPLINK_MARK_DSCP)? {
                let marked_dscp = BpfHashMap::<
                    MapData,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_DSCP_VALUE_LEN],
                >::try_from(map)
                .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                observe_empty!(marked_dscp);
            }
            if let Some(map) = open(MAP_DOWNLINK_PDR)? {
                let pdr =
                    BpfHashMap::<MapData, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
                        .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                observe_empty!(pdr);
            }
            if let Some(map) = open(MAP_DOWNLINK_MARK_PDR)? {
                let marked_pdr =
                    BpfHashMap::<MapData, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(
                        map,
                    )
                    .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                observe_empty!(marked_pdr);
            }
            if let Some(map) = open(MAP_MARKED_BEARER_OWNER)? {
                let owner = BpfHashMap::<
                    MapData,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; LEGACY_V2_OWNER_VALUE_LEN],
                >::try_from(map)
                .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                observe_empty!(owner);
            }
            if let Some(map) = open(MAP_CONFIG)? {
                let config = Array::<MapData, [u8; 4]>::try_from(map)
                    .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                let local_ip = config
                    .get(&0, 0)
                    .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
                validate_legacy_v2_config_identity(local_ip)?;
            }
            Ok(!forwarding_state_present)
        }

        /// Determine which additive map schema this pin set has committed.
        /// The marker lives in the pre-existing FAR map so it remains
        /// available when a required additive pin is accidentally removed.
        /// This check must run before `load_pinned`, because Aya otherwise
        /// creates a missing pinned-by-name map and conceals durable state
        /// loss.
        fn bearer_schema_preflight(pin_dir: &Path) -> Result<BearerSchemaState, GtpuError> {
            match fs::symlink_metadata(pin_dir.join(LEGACY_V2_TEARDOWN_PROOF_MAP)) {
                Ok(_) => {
                    return Err(state_indeterminate("ebpf_legacy_v2_teardown_pending"));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err(state_indeterminate("ebpf_legacy_v2_teardown_pending"));
                }
            }
            let far_pin = pin_dir.join(MAP_UPLINK_FAR);
            if !far_pin
                .try_exists()
                .map_err(|error| GtpuError::io("ebpf_bearer_schema", error))?
            {
                for other_pin in [
                    MAP_UPLINK_DSCP,
                    MAP_UPLINK_MARK_FAR,
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
                    MAP_DOWNLINK_BINDING_COUNTERS,
                    MAP_CONFIG,
                ] {
                    if pin_dir
                        .join(other_pin)
                        .try_exists()
                        .map_err(|error| GtpuError::io("ebpf_bearer_schema", error))?
                    {
                        return Err(GtpuError::io(
                            "ebpf_bearer_schema",
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                "GTP-U schema marker carrier pin is missing",
                            ),
                        ));
                    }
                }
                return Ok(BearerSchemaState::Fresh);
            }

            let map_data = MapData::from_pin(&far_pin)
                .map_err(|error| map_error("ebpf_bearer_schema", error))?;
            let map = Map::from_map_data(map_data)
                .map_err(|error| map_error("ebpf_bearer_schema", error))?;
            let far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
                .map_err(|error| map_error("ebpf_bearer_schema", error))?;
            let state = match far.get(&UPLINK_DSCP_SCHEMA_MARKER_KEY, 0) {
                Ok(value) if value == UPLINK_DSCP_SCHEMA_MARKER_VALUE => BearerSchemaState::DscpV1,
                Ok(value) if value == UPLINK_BEARER_SCHEMA_MARKER_VALUE => {
                    BearerSchemaState::BearerV2
                }
                Ok(value) if value == UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE => {
                    BearerSchemaState::EndpointV3
                }
                Ok(value) if value == UPLINK_SOURCE_PORT_SCHEMA_MARKER_VALUE => {
                    BearerSchemaState::SourcePortV4
                }
                Ok(value) if value == UPLINK_PMTU_SCHEMA_MARKER_VALUE => BearerSchemaState::PmtuV5,
                Ok(_) => {
                    return Err(GtpuError::io(
                        "ebpf_bearer_schema",
                        invalid_data("invalid GTP-U map schema marker"),
                    ));
                }
                Err(MapError::KeyNotFound) => {
                    if pin_dir
                        .join(MAP_UPLINK_DSCP)
                        .try_exists()
                        .map_err(|error| GtpuError::io("ebpf_bearer_schema", error))?
                    {
                        BearerSchemaState::V1Uncommitted
                    } else {
                        BearerSchemaState::LegacyV0
                    }
                }
                Err(error) => return Err(map_error("ebpf_bearer_schema", error)),
            };

            let required_pins: &[&str] = match state {
                BearerSchemaState::Fresh => &[],
                BearerSchemaState::LegacyV0 => &[MAP_DOWNLINK_PDR, MAP_COUNTERS, MAP_CONFIG],
                BearerSchemaState::V1Uncommitted => {
                    &[MAP_UPLINK_DSCP, MAP_DOWNLINK_PDR, MAP_COUNTERS, MAP_CONFIG]
                }
                BearerSchemaState::DscpV1 => {
                    &[MAP_UPLINK_DSCP, MAP_DOWNLINK_PDR, MAP_COUNTERS, MAP_CONFIG]
                }
                BearerSchemaState::BearerV2 => &[
                    MAP_UPLINK_DSCP,
                    MAP_UPLINK_MARK_FAR,
                    MAP_UPLINK_MARK_DSCP,
                    MAP_DOWNLINK_PDR,
                    MAP_DOWNLINK_MARK_PDR,
                    MAP_MARKED_BEARER_OWNER,
                    MAP_COUNTERS,
                    MAP_CONFIG,
                ],
                BearerSchemaState::EndpointV3 => &[
                    MAP_UPLINK_DSCP,
                    MAP_UPLINK_MARK_FAR,
                    MAP_UPLINK_MARK_DSCP,
                    MAP_DOWNLINK_PDR,
                    MAP_DOWNLINK_MARK_PDR,
                    MAP_DOWNLINK_ENDPOINT_BINDING,
                    MAP_MARKED_BEARER_OWNER,
                    MAP_COUNTERS,
                    MAP_DOWNLINK_BINDING_COUNTERS,
                    MAP_CONFIG,
                ],
                BearerSchemaState::SourcePortV4 => &[
                    MAP_UPLINK_DSCP,
                    MAP_UPLINK_MARK_FAR,
                    MAP_UPLINK_MARK_DSCP,
                    MAP_UPLINK_SOURCE_PORT,
                    MAP_UPLINK_MARK_SOURCE_PORT,
                    MAP_DOWNLINK_PDR,
                    MAP_DOWNLINK_MARK_PDR,
                    MAP_DOWNLINK_ENDPOINT_BINDING,
                    MAP_MARKED_BEARER_OWNER,
                    MAP_COUNTERS,
                    MAP_DOWNLINK_BINDING_COUNTERS,
                    MAP_CONFIG,
                ],
                BearerSchemaState::PmtuV5 => &[
                    MAP_UPLINK_DSCP,
                    MAP_UPLINK_MARK_FAR,
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
                    MAP_DOWNLINK_BINDING_COUNTERS,
                    MAP_CONFIG,
                ],
            };
            for required_pin in required_pins {
                if !pin_dir
                    .join(required_pin)
                    .try_exists()
                    .map_err(|error| GtpuError::io("ebpf_bearer_schema", error))?
                {
                    return Err(GtpuError::io(
                        "ebpf_bearer_schema",
                        io::Error::new(io::ErrorKind::NotFound, "adopted GTP-U map pin is missing"),
                    ));
                }
            }
            if state == BearerSchemaState::BearerV2 {
                return Err(GtpuError::io(
                    "ebpf_endpoint_schema",
                    invalid_data("endpoint-unbound GTP-U schema requires drained reprovisioning"),
                ));
            }
            Ok(state)
        }

        fn write_bearer_schema_marker(ebpf: &mut Ebpf) -> Result<(), GtpuError> {
            let map = ebpf
                .map_mut(MAP_UPLINK_FAR)
                .ok_or_else(|| GtpuError::io("ebpf_bearer_schema", invalid_data("map missing")))?;
            let mut far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
                .map_err(|error| map_error("ebpf_bearer_schema", error))?;
            far.insert(
                UPLINK_DSCP_SCHEMA_MARKER_KEY,
                UPLINK_PMTU_SCHEMA_MARKER_VALUE,
                0,
            )
            .map_err(|error| map_error("ebpf_bearer_schema", error))
        }

        /// Materialize a complete commit record for every validated pre-v4
        /// transaction.
        ///
        /// Callers first validate the complete pre-v4 graph and any partial
        /// migration entries, then invoke this before attaching the v4
        /// program. A retry after interruption overwrites only the same
        /// canonical record, so the migration is deterministic.
        fn materialize_legacy_source_port_policies(
            ebpf: &mut Ebpf,
            indexes: &PdpHostIndexes,
        ) -> Result<(), GtpuError> {
            let missing = || GtpuError::io("ebpf_source_port_schema", invalid_data("map missing"));
            {
                let map = ebpf.map_mut(MAP_UPLINK_SOURCE_PORT).ok_or_else(missing)?;
                let mut source_ports =
                    BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_source_port_schema", error))?;
                for (ue_ip, commit) in &indexes.default_commits {
                    source_ports
                        .insert(*ue_ip, commit.encode(), 0)
                        .map_err(|error| map_error("ebpf_source_port_schema", error))?;
                }
            }
            let map = ebpf
                .map_mut(MAP_UPLINK_MARK_SOURCE_PORT)
                .ok_or_else(missing)?;
            let mut marked_source_ports = BpfHashMap::<
                _,
                [u8; UPLINK_MARK_KEY_LEN],
                [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
            >::try_from(map)
            .map_err(|error| map_error("ebpf_source_port_schema", error))?;
            for (selector, commit) in &indexes.marked_commits {
                marked_source_ports
                    .insert(*selector, commit.encode(), 0)
                    .map_err(|error| map_error("ebpf_source_port_schema", error))?;
            }
            Ok(())
        }

        /// Resume any interrupted v4 transaction by cleaning its complete
        /// selector graph to absence. Pending/Removing records gate both tc
        /// directions; deleting the record last makes every crash cut
        /// retryable without ever accepting a mixed graph as Active.
        fn recover_incomplete_pdp_commits(
            ebpf: &mut Ebpf,
            local_ip: [u8; 4],
            ifindex: u32,
        ) -> Result<(), GtpuError> {
            let missing = || GtpuError::io("ebpf_pdp_recovery", invalid_data("map missing"));
            let invalid = || state_indeterminate("ebpf_pdp_recovery");
            let default_incomplete = {
                let commits =
                    BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(
                        ebpf.map(MAP_UPLINK_SOURCE_PORT).ok_or_else(missing)?,
                    )
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let mut found = false;
                for entry in commits.iter() {
                    let (_, encoded) =
                        entry.map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                    let commit = PdpContextCommit::decode(&encoded);
                    if !commit.is_valid() {
                        return Err(invalid());
                    }
                    found |= commit.phase() != MarkedBearerOwnerPhase::Active;
                }
                found
            };
            let marked_incomplete = {
                let commits = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
                >::try_from(
                    ebpf.map(MAP_UPLINK_MARK_SOURCE_PORT).ok_or_else(missing)?
                )
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let mut found = false;
                for entry in commits.iter() {
                    let (_, encoded) =
                        entry.map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                    let commit = PdpContextCommit::decode(&encoded);
                    if !commit.is_valid() {
                        return Err(invalid());
                    }
                    found |= commit.phase() != MarkedBearerOwnerPhase::Active;
                }
                found
            };
            if !default_incomplete && !marked_incomplete {
                return Ok(());
            }
            let (default_transactions, marked_transactions) = {
                let default_commits =
                    BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(
                        ebpf.map(MAP_UPLINK_SOURCE_PORT).ok_or_else(missing)?,
                    )
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let marked_commits = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
                >::try_from(
                    ebpf.map(MAP_UPLINK_MARK_SOURCE_PORT).ok_or_else(missing)?
                )
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_UPLINK_FAR).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let marked_far = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_FAR_VALUE_LEN],
                >::try_from(
                    ebpf.map(MAP_UPLINK_MARK_FAR).ok_or_else(missing)?
                )
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let dscp = BpfHashMap::<_, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_UPLINK_DSCP).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let marked_dscp = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_DSCP_VALUE_LEN],
                >::try_from(
                    ebpf.map(MAP_UPLINK_MARK_DSCP).ok_or_else(missing)?
                )
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let pdr = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_DOWNLINK_PDR).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let marked_pdr =
                    BpfHashMap::<_, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(
                        ebpf.map(MAP_DOWNLINK_MARK_PDR).ok_or_else(missing)?,
                    )
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let bindings =
                    BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(
                        ebpf.map(MAP_DOWNLINK_ENDPOINT_BINDING)
                            .ok_or_else(missing)?,
                    )
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                let owners = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; MARKED_BEARER_OWNER_VALUE_LEN],
                >::try_from(
                    ebpf.map(MAP_MARKED_BEARER_OWNER).ok_or_else(missing)?
                )
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;

                let mut claimed_teids = HashSet::new();
                let mut owner_teids = HashMap::new();
                for entry in owners.iter() {
                    let (selector, encoded) =
                        entry.map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                    let owner = MarkedBearerOwner::decode(&encoded);
                    if !owner.is_valid() || owner_teids.insert(owner.local_teid, selector).is_some()
                    {
                        return Err(invalid());
                    }
                }

                let mut default_transactions = Vec::new();
                for entry in default_commits.iter() {
                    let (ue_ip, encoded) =
                        entry.map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                    let commit = PdpContextCommit::decode(&encoded);
                    if ue_ip == [0; 4]
                        || !commit.is_valid()
                        || commit.uplink_far().local_ip != local_ip
                        || commit.downlink_binding().ingress_ifindex() != ifindex
                        || !claimed_teids.insert(commit.local_teid())
                    {
                        return Err(invalid());
                    }
                    if commit.phase() == MarkedBearerOwnerPhase::Active {
                        continue;
                    }
                    if owner_teids.contains_key(&commit.local_teid())
                        || marked_pdr.get(&commit.local_teid(), 0).is_ok()
                    {
                        return Err(invalid());
                    }
                    match pdr.get(&commit.local_teid(), 0) {
                        Ok(value) if DownlinkPdr::decode(&value).ue_ip == ue_ip => {}
                        Ok(_) => return Err(invalid()),
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => return Err(map_error("ebpf_pdp_recovery", error)),
                    }
                    match far.get(&ue_ip, 0) {
                        Ok(value) => {
                            let value = UplinkFar::decode(&value);
                            if value.local_ip != local_ip
                                || value.peer_ip == [0; 4]
                                || value.o_teid == [0; 4]
                            {
                                return Err(invalid());
                            }
                        }
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => return Err(map_error("ebpf_pdp_recovery", error)),
                    }
                    match dscp.get(&ue_ip, 0) {
                        Ok(value) if value[0] <= 63 => {}
                        Ok(_) => return Err(invalid()),
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => return Err(map_error("ebpf_pdp_recovery", error)),
                    }
                    match bindings.get(&commit.local_teid(), 0) {
                        Ok(value) => {
                            let value = DownlinkEndpointBinding::decode(&value);
                            if !value.is_valid()
                                || value.ingress_ifindex() != ifindex
                                || value.local_address()
                                    != commit.downlink_binding().local_address()
                            {
                                return Err(invalid());
                            }
                        }
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => return Err(map_error("ebpf_pdp_recovery", error)),
                    }
                    default_transactions.push((ue_ip, commit.local_teid()));
                }

                let mut marked_transactions = Vec::new();
                for entry in marked_commits.iter() {
                    let (selector, encoded) =
                        entry.map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                    let selector_value = UplinkFarKey::decode(&selector);
                    let commit = PdpContextCommit::decode(&encoded);
                    if selector_value.ue_ip == [0; 4]
                        || selector_value.ue_ip == local_ip
                        || selector_value.bearer_mark == [0; 4]
                        || !commit.is_valid()
                        || commit.uplink_far().local_ip != local_ip
                        || commit.downlink_binding().ingress_ifindex() != ifindex
                        || !claimed_teids.insert(commit.local_teid())
                    {
                        return Err(invalid());
                    }
                    if commit.phase() == MarkedBearerOwnerPhase::Active {
                        continue;
                    }
                    if pdr.get(&commit.local_teid(), 0).is_ok()
                        || owner_teids
                            .get(&commit.local_teid())
                            .is_some_and(|owner_selector| *owner_selector != selector)
                    {
                        return Err(invalid());
                    }
                    let expected_pdr = MarkedDownlinkPdr {
                        ue_ip: selector_value.ue_ip,
                        bearer_mark: selector_value.bearer_mark,
                    };
                    match marked_pdr.get(&commit.local_teid(), 0) {
                        Ok(value) if MarkedDownlinkPdr::decode(&value) == expected_pdr => {}
                        Ok(_) => return Err(invalid()),
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => return Err(map_error("ebpf_pdp_recovery", error)),
                    }
                    match marked_far.get(&selector, 0) {
                        Ok(value) => {
                            let value = UplinkFar::decode(&value);
                            if value.local_ip != local_ip
                                || value.peer_ip == [0; 4]
                                || value.o_teid == [0; 4]
                            {
                                return Err(invalid());
                            }
                        }
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => return Err(map_error("ebpf_pdp_recovery", error)),
                    }
                    match marked_dscp.get(&selector, 0) {
                        Ok(value) if value[0] <= 63 => {}
                        Ok(_) => return Err(invalid()),
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => return Err(map_error("ebpf_pdp_recovery", error)),
                    }
                    match bindings.get(&commit.local_teid(), 0) {
                        Ok(value) => {
                            let value = DownlinkEndpointBinding::decode(&value);
                            if !value.is_valid()
                                || value.ingress_ifindex() != ifindex
                                || value.local_address()
                                    != commit.downlink_binding().local_address()
                            {
                                return Err(invalid());
                            }
                        }
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => return Err(map_error("ebpf_pdp_recovery", error)),
                    }
                    match owners.get(&selector, 0) {
                        Ok(encoded_owner) => {
                            let owner = MarkedBearerOwner::decode(&encoded_owner);
                            if owner.local_teid != commit.local_teid()
                                || owner.uplink_far.local_ip != local_ip
                                || owner.downlink_binding.ingress_ifindex() != ifindex
                            {
                                return Err(invalid());
                            }
                        }
                        Err(MapError::KeyNotFound) => {}
                        Err(error) => return Err(map_error("ebpf_pdp_recovery", error)),
                    }
                    marked_transactions.push((selector, commit.local_teid()));
                }
                (default_transactions, marked_transactions)
            };

            for (ue_ip, local_teid) in default_transactions {
                let map = ebpf.map_mut(MAP_UPLINK_FAR).ok_or_else(missing)?;
                let mut map = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map_delete_result("ebpf_pdp_recovery", map.remove(&ue_ip))?;
                let map = ebpf.map_mut(MAP_UPLINK_DSCP).ok_or_else(missing)?;
                let mut map = BpfHashMap::<_, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map_delete_result("ebpf_pdp_recovery", map.remove(&ue_ip))?;
                let map = ebpf
                    .map_mut(MAP_DOWNLINK_ENDPOINT_BINDING)
                    .ok_or_else(missing)?;
                let mut map =
                    BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(
                        map,
                    )
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map_delete_result("ebpf_pdp_recovery", map.remove(&local_teid))?;
                let map = ebpf.map_mut(MAP_DOWNLINK_PDR).ok_or_else(missing)?;
                let mut map = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map_delete_result("ebpf_pdp_recovery", map.remove(&local_teid))?;
                let map = ebpf.map_mut(MAP_UPLINK_SOURCE_PORT).ok_or_else(missing)?;
                let mut map =
                    BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map.remove(&ue_ip)
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
            }

            for (selector, local_teid) in marked_transactions {
                let map = ebpf.map_mut(MAP_UPLINK_MARK_FAR).ok_or_else(missing)?;
                let mut map = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_FAR_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map_delete_result("ebpf_pdp_recovery", map.remove(&selector))?;
                let map = ebpf.map_mut(MAP_UPLINK_MARK_DSCP).ok_or_else(missing)?;
                let mut map = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_DSCP_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map_delete_result("ebpf_pdp_recovery", map.remove(&selector))?;
                let map = ebpf
                    .map_mut(MAP_DOWNLINK_ENDPOINT_BINDING)
                    .ok_or_else(missing)?;
                let mut map =
                    BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(
                        map,
                    )
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map_delete_result("ebpf_pdp_recovery", map.remove(&local_teid))?;
                let map = ebpf.map_mut(MAP_DOWNLINK_MARK_PDR).ok_or_else(missing)?;
                let mut map =
                    BpfHashMap::<_, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map_delete_result("ebpf_pdp_recovery", map.remove(&local_teid))?;
                let map = ebpf.map_mut(MAP_MARKED_BEARER_OWNER).ok_or_else(missing)?;
                let mut map = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; MARKED_BEARER_OWNER_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map_delete_result("ebpf_pdp_recovery", map.remove(&selector))?;
                let map = ebpf
                    .map_mut(MAP_UPLINK_MARK_SOURCE_PORT)
                    .ok_or_else(missing)?;
                let mut map = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
                map.remove(&selector)
                    .map_err(|error| map_error("ebpf_pdp_recovery", error))?;
            }
            Ok(())
        }

        /// Validate the durable marked-bearer journal and build its bounded
        /// local-TEID uniqueness index before either tc hook can be changed.
        ///
        /// With `source_port_committed`, every active graph must own exactly
        /// one canonical explicit policy. Before the v4 commit, entries may be
        /// absent but any partial migration entry must be the legacy value and
        /// must already belong to an active graph.
        fn pdp_host_indexes(
            ebpf: &Ebpf,
            local_ip: [u8; 4],
            ifindex: u32,
            source_port_committed: bool,
        ) -> Result<PdpHostIndexes, GtpuError> {
            let missing =
                || GtpuError::io("ebpf_marked_owner_rebuild", invalid_data("map missing"));
            let invalid = || state_indeterminate("ebpf_marked_owner_rebuild");
            let owners = BpfHashMap::<
                _,
                [u8; UPLINK_MARK_KEY_LEN],
                [u8; MARKED_BEARER_OWNER_VALUE_LEN],
            >::try_from(
                ebpf.map(MAP_MARKED_BEARER_OWNER).ok_or_else(missing)?
            )
            .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
            let marked_far =
                BpfHashMap::<_, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_UPLINK_MARK_FAR).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
            let marked_dscp =
                BpfHashMap::<_, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_UPLINK_MARK_DSCP).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
            let marked_pdr =
                BpfHashMap::<_, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_DOWNLINK_MARK_PDR).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
            let legacy_pdr = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(
                ebpf.map(MAP_DOWNLINK_PDR).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
            let downlink_binding =
                BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_DOWNLINK_ENDPOINT_BINDING)
                        .ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
            let legacy_far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(
                ebpf.map(MAP_UPLINK_FAR).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
            let legacy_dscp = BpfHashMap::<_, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(
                ebpf.map(MAP_UPLINK_DSCP).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
            let marked_sport = BpfHashMap::<
                _,
                [u8; UPLINK_MARK_KEY_LEN],
                [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
            >::try_from(
                ebpf.map(MAP_UPLINK_MARK_SOURCE_PORT).ok_or_else(missing)?
            )
            .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
            let legacy_sport =
                BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_UPLINK_SOURCE_PORT).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;

            let mut by_teid = HashMap::new();
            let mut marked_commits = Vec::new();
            for entry in owners.iter() {
                let (selector, encoded) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                let selector_value = UplinkFarKey::decode(&selector);
                let owner = MarkedBearerOwner::decode(&encoded);
                match legacy_pdr.get(&owner.local_teid, 0) {
                    Ok(_) => return Err(invalid()),
                    Err(MapError::KeyNotFound) => {}
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                }
                if selector_value.ue_ip == [0; 4]
                    || selector_value.ue_ip == local_ip
                    || selector_value.bearer_mark == [0; 4]
                    || !owner.is_valid()
                    || owner.uplink_far.local_ip != local_ip
                    || owner.downlink_binding.ingress_ifindex() != ifindex
                    || by_teid.insert(owner.local_teid, selector).is_some()
                    || source_port_committed && owner.phase != MarkedBearerOwnerPhase::Active
                {
                    return Err(invalid());
                }
                let migration_commit = PdpContextCommit::new(
                    owner.local_teid,
                    owner.uplink_far,
                    owner.egress_dscp(),
                    owner.downlink_binding,
                    GtpuUplinkSourcePortPolicy::LegacyServicePort,
                    owner.phase,
                )
                .ok_or_else(invalid)?;
                marked_commits.push((selector, migration_commit));

                let far = match marked_far.get(&selector, 0) {
                    Ok(value) => Some(value),
                    Err(MapError::KeyNotFound) => None,
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                };
                let dscp = match marked_dscp.get(&selector, 0) {
                    Ok(value) => Some(value),
                    Err(MapError::KeyNotFound) => None,
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                };
                let sport = match marked_sport.get(&selector, 0) {
                    Ok(value) => Some(value),
                    Err(MapError::KeyNotFound) => None,
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                };
                let pdr = match marked_pdr.get(&owner.local_teid, 0) {
                    Ok(value) => Some(value),
                    Err(MapError::KeyNotFound) => None,
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                };
                let binding = match downlink_binding.get(&owner.local_teid, 0) {
                    Ok(value) => Some(value),
                    Err(MapError::KeyNotFound) => None,
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                };
                let expected_far = owner.uplink_far.encode();
                let expected_dscp = owner.egress_dscp().map(|value| [value]);
                let expected_binding = owner.downlink_binding.encode();
                let expected_pdr = MarkedDownlinkPdr {
                    ue_ip: selector_value.ue_ip,
                    bearer_mark: selector_value.bearer_mark,
                }
                .encode();
                let sport_matches = match sport {
                    Some(value) => {
                        let commit = PdpContextCommit::decode(&value);
                        commit.is_valid()
                            && if source_port_committed {
                                commit.marked_owner() == owner
                            } else {
                                commit == migration_commit
                            }
                    }
                    None => !source_port_committed,
                };
                let transitional_resources_owned = far.is_none_or(|value| {
                    let value = UplinkFar::decode(&value);
                    value.local_ip == local_ip && value.peer_ip != [0; 4] && value.o_teid != [0; 4]
                }) && dscp.is_none_or(|value| value[0] <= 63)
                    && pdr.is_none_or(|value| value == expected_pdr)
                    && binding.is_none_or(|value| {
                        let value = DownlinkEndpointBinding::decode(&value);
                        value.is_valid()
                            && value.ingress_ifindex() == ifindex
                            && value.local_address() == owner.downlink_binding.local_address()
                    });
                let complete = far == Some(expected_far)
                    && dscp == expected_dscp
                    && pdr == Some(expected_pdr)
                    && binding == Some(expected_binding)
                    && sport_matches;
                if !sport_matches
                    || !transitional_resources_owned
                    || owner.phase == MarkedBearerOwnerPhase::Active && !complete
                {
                    return Err(invalid());
                }
            }

            // Every marked forwarding entry must have one canonical owner;
            // the journal is the sole authority for crash recovery.
            for entry in marked_far.iter() {
                let (selector, _) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                match owners.get(&selector, 0) {
                    Ok(_) => {}
                    Err(MapError::KeyNotFound) => return Err(invalid()),
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                }
            }
            for entry in marked_dscp.iter() {
                let (selector, _) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                match owners.get(&selector, 0) {
                    Ok(_) => {}
                    Err(MapError::KeyNotFound) => return Err(invalid()),
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                }
            }
            for entry in marked_sport.iter() {
                let (selector, encoded) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                match owners.get(&selector, 0) {
                    Ok(owner) => {
                        let owner = MarkedBearerOwner::decode(&owner);
                        let commit = PdpContextCommit::decode(&encoded);
                        if !commit.is_valid() || commit.local_teid() != owner.local_teid {
                            return Err(invalid());
                        }
                    }
                    Err(MapError::KeyNotFound) => return Err(invalid()),
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                }
            }
            for entry in marked_pdr.iter() {
                let (teid, encoded) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                let pdr = MarkedDownlinkPdr::decode(&encoded);
                let selector = UplinkFarKey {
                    ue_ip: pdr.ue_ip,
                    bearer_mark: pdr.bearer_mark,
                }
                .encode();
                let owner = match owners.get(&selector, 0) {
                    Ok(value) => MarkedBearerOwner::decode(&value),
                    Err(MapError::KeyNotFound) => return Err(invalid()),
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                };
                if owner.local_teid != teid {
                    return Err(invalid());
                }
            }

            let mut default_teids = HashSet::new();
            let mut default_teid_by_ue = HashMap::new();
            let mut default_commits = Vec::new();
            for entry in legacy_pdr.iter() {
                let (teid, encoded) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                let pdr = DownlinkPdr::decode(&encoded);
                let far = legacy_far
                    .get(&pdr.ue_ip, 0)
                    .map(|value| UplinkFar::decode(&value))
                    .map_err(|_| invalid())?;
                let binding = downlink_binding
                    .get(&teid, 0)
                    .map(|value| DownlinkEndpointBinding::decode(&value))
                    .map_err(|_| invalid())?;
                if !default_bearer_graph_is_valid(teid, pdr, far, binding, local_ip, ifindex)
                    || !default_teids.insert(teid)
                    || default_teid_by_ue.insert(pdr.ue_ip, teid).is_some()
                {
                    return Err(invalid());
                }
                match legacy_dscp.get(&pdr.ue_ip, 0) {
                    Ok(value) if value[0] <= 63 => {}
                    Ok(_) => return Err(invalid()),
                    Err(MapError::KeyNotFound) => {}
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                }
                let dscp = match legacy_dscp.get(&pdr.ue_ip, 0) {
                    Ok(value) => Some(value[0]),
                    Err(MapError::KeyNotFound) => None,
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                };
                let migration_commit = PdpContextCommit::new(
                    teid,
                    far,
                    dscp,
                    binding,
                    GtpuUplinkSourcePortPolicy::LegacyServicePort,
                    MarkedBearerOwnerPhase::Active,
                )
                .ok_or_else(invalid)?;
                default_commits.push((pdr.ue_ip, migration_commit));
                match legacy_sport.get(&pdr.ue_ip, 0) {
                    Ok(value) => {
                        let commit = PdpContextCommit::decode(&value);
                        if !commit.is_valid()
                            || if source_port_committed {
                                !commit.authorizes_graph(teid, &far, dscp, &binding)
                            } else {
                                commit != migration_commit
                            }
                        {
                            return Err(invalid());
                        }
                    }
                    Err(MapError::KeyNotFound) if !source_port_committed => {}
                    Err(MapError::KeyNotFound) => return Err(invalid()),
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                }
            }
            for entry in legacy_far.iter() {
                let (ue_ip, _) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                if ue_ip != UPLINK_DSCP_SCHEMA_MARKER_KEY
                    && !default_teid_by_ue.contains_key(&ue_ip)
                {
                    return Err(invalid());
                }
            }
            for entry in legacy_dscp.iter() {
                let (_, value) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                // A valid DSCP-only orphan has no forwarding reachability and
                // remains recoverable by the legacy exact retry path. The
                // strict readback contract classifies it as indeterminate.
                if value[0] > 63 {
                    return Err(invalid());
                }
            }
            for entry in legacy_sport.iter() {
                let (ue_ip, value) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                // Unlike advisory DSCP staging, source-port policy is required
                // durable state in v4. An unowned entry cannot be reconciled
                // honestly after restart and partial pre-v4 migration entries
                // are restricted to active legacy graphs.
                let commit = PdpContextCommit::decode(&value);
                if !default_teid_by_ue.contains_key(&ue_ip) || !commit.is_valid() {
                    return Err(invalid());
                }
            }
            for entry in downlink_binding.iter() {
                let (teid, encoded) =
                    entry.map_err(|error| map_error("ebpf_marked_owner_rebuild", error))?;
                let binding = DownlinkEndpointBinding::decode(&encoded);
                let has_default = default_teids.contains(&teid);
                let has_marked = by_teid.contains_key(&teid);
                if !binding.is_valid() || has_default == has_marked {
                    return Err(invalid());
                }
            }
            if default_teids.iter().any(|teid| by_teid.contains_key(teid)) {
                return Err(invalid());
            }
            Ok(PdpHostIndexes {
                marked_owner_by_teid: by_teid,
                default_teid_by_ue,
                default_commits,
                marked_commits,
            })
        }

        fn program_identity(
            ebpf: &Ebpf,
            pin_dir: &Path,
            program_name: &str,
            required_map_pins: &[&str],
        ) -> Result<ProgramIdentity, GtpuError> {
            let program: &SchedClassifier = ebpf
                .program(program_name)
                .ok_or_else(|| {
                    GtpuError::io("ebpf_program_lookup", invalid_data("program missing"))
                })?
                .try_into()
                .map_err(|_: ProgramError| {
                    GtpuError::io("ebpf_program_type", invalid_data("not a classifier"))
                })?;
            let info = program
                .info()
                .map_err(|error| program_error("ebpf_program_info", &error))?;
            if info.name() != kernel_program_name(program_name) {
                return Err(GtpuError::io(
                    "ebpf_program_info",
                    invalid_data("datapath program name mismatch"),
                ));
            }
            let mut map_ids = info
                .map_ids()
                .map_err(|error| program_error("ebpf_program_map_ids", &error))?
                .ok_or_else(|| {
                    GtpuError::io(
                        "ebpf_program_map_ids",
                        invalid_data("kernel did not report program map ids"),
                    )
                })?;
            let mut required_map_ids = required_map_pins
                .iter()
                .map(|name| {
                    MapInfo::from_pin(pin_dir.join(name))
                        .map(|info| info.id())
                        .map_err(|error| map_error("ebpf_map_pin_identity", error))
                })
                .collect::<Result<Vec<_>, _>>()?;
            map_ids.sort_unstable();
            required_map_ids.sort_unstable();
            if map_ids != required_map_ids {
                return Err(GtpuError::io(
                    "ebpf_program_map_ids",
                    invalid_data("datapath program does not reference the exact required pins"),
                ));
            }
            Ok(ProgramIdentity {
                program_id: info.id(),
                program_tag: info.tag(),
                map_ids,
            })
        }

        fn datapath_identity(ebpf: &Ebpf, pin_dir: &Path) -> Result<DatapathIdentity, GtpuError> {
            Ok(DatapathIdentity {
                uplink: Self::program_identity(
                    ebpf,
                    pin_dir,
                    PROG_UPLINK,
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
                    ],
                )?,
                downlink: Self::program_identity(
                    ebpf,
                    pin_dir,
                    PROG_DOWNLINK,
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
                        MAP_MARKED_BEARER_OWNER,
                        MAP_COUNTERS,
                        MAP_DOWNLINK_BINDING_COUNTERS,
                    ],
                )?,
                pins: Self::pinned_map_identity(pin_dir)?,
            })
        }

        fn legacy_v2_datapath_identity(
            pin_dir: &Path,
        ) -> Result<LegacyV2DatapathIdentity, LegacyV2IdentityError> {
            let named = Self::legacy_v2_named_map_ids(pin_dir)?;
            let (uplink_tags, downlink_tags) = Self::legacy_v2_artifact_tags()
                .map_err(|_| LegacyV2IdentityError::Indeterminate)?;
            Ok(LegacyV2DatapathIdentity {
                uplink: LegacyV2ProgramIdentity {
                    tags: uplink_tags,
                    map_ids: [
                        named[0], named[1], named[2], named[3], named[6], named[7], named[8],
                    ]
                    .into(),
                },
                downlink: LegacyV2ProgramIdentity {
                    tags: downlink_tags,
                    map_ids: [named[4], named[5], named[6], named[7]].into(),
                },
                map_ids: named,
            })
        }

        fn read_legacy_v2_teardown_proof(
            pin_dir: &Path,
        ) -> Result<Option<LegacyV2TeardownProof>, GtpuError> {
            let path = pin_dir.join(LEGACY_V2_TEARDOWN_PROOF_MAP);
            if !legacy_v2_path_is_present(&path, "ebpf_legacy_v2_proof_read")? {
                return Ok(None);
            }
            let data = MapData::from_pin(&path)
                .map_err(|error| map_error("ebpf_legacy_v2_proof_read", error))?;
            let info = data
                .info()
                .map_err(|error| map_error("ebpf_legacy_v2_proof_read", error))?;
            let map_type = info
                .map_type()
                .map_err(|error| map_error("ebpf_legacy_v2_proof_read", error))?
                as u32;
            if !legacy_v2_proof_map_abi_is_exact(
                map_type,
                info.key_size(),
                info.value_size(),
                info.max_entries(),
                info.map_flags(),
            ) {
                return Err(state_indeterminate("ebpf_legacy_v2_proof_read"));
            }
            let map_id = info.id();
            let proof = Array::<_, [u8; LEGACY_V2_TEARDOWN_PROOF_LEN]>::try_from(
                Map::from_map_data(data)
                    .map_err(|error| map_error("ebpf_legacy_v2_proof_read", error))?,
            )
            .map_err(|error| map_error("ebpf_legacy_v2_proof_read", error))?;
            let encoded = proof
                .get(&0, 0)
                .map_err(|error| map_error("ebpf_legacy_v2_proof_read", error))?;
            let record = LegacyV2TeardownRecord::decode(&encoded)
                .ok_or_else(|| state_indeterminate("ebpf_legacy_v2_proof_read"))?;
            let (uplink_tags, downlink_tags) = Self::legacy_v2_artifact_tags()?;
            if !legacy_v2_proof_record_is_authoritative(record, map_id, uplink_tags, downlink_tags)
            {
                return Err(state_indeterminate("ebpf_legacy_v2_proof_read"));
            }
            Ok(Some(LegacyV2TeardownProof { record, map_id }))
        }

        fn commit_legacy_v2_teardown_proof(
            pin_dir: &Path,
            record: LegacyV2TeardownRecord,
        ) -> Result<LegacyV2TeardownProof, LegacyV2ProofCommitError> {
            match Self::read_legacy_v2_teardown_proof(pin_dir) {
                Ok(Some(existing)) if existing.record.matches_unbound(record) => {
                    return Ok(existing);
                }
                Ok(Some(_)) | Err(_) => {
                    return Err(LegacyV2ProofCommitError::BeforePublication);
                }
                Ok(None) => {}
            }
            let mut proof = Array::<MapData, [u8; LEGACY_V2_TEARDOWN_PROOF_LEN]>::create(1, 0)
                .map_err(|_| LegacyV2ProofCommitError::BeforePublication)?;
            let info = proof
                .map()
                .info()
                .map_err(|_| LegacyV2ProofCommitError::BeforePublication)?;
            let map_type = info
                .map_type()
                .map_err(|_| LegacyV2ProofCommitError::BeforePublication)?
                as u32;
            if !legacy_v2_proof_map_abi_is_exact(
                map_type,
                info.key_size(),
                info.value_size(),
                info.max_entries(),
                info.map_flags(),
            ) {
                return Err(LegacyV2ProofCommitError::BeforePublication);
            }
            let record = record
                .bind_to_proof_map(info.id())
                .ok_or(LegacyV2ProofCommitError::BeforePublication)?;
            proof
                .set(0, record.encode(), 0)
                .map_err(|_| LegacyV2ProofCommitError::BeforePublication)?;
            let path = pin_dir.join(LEGACY_V2_TEARDOWN_PROOF_MAP);
            if proof.pin(&path).is_err() {
                return match Self::read_legacy_v2_teardown_proof(pin_dir) {
                    Ok(Some(existing)) if existing.record == record => Ok(existing),
                    Ok(None) => Err(LegacyV2ProofCommitError::BeforePublication),
                    Ok(Some(_)) | Err(_) => Err(LegacyV2ProofCommitError::PublicationIndeterminate),
                };
            }
            match Self::read_legacy_v2_teardown_proof(pin_dir) {
                Ok(Some(existing)) if existing.record == record => Ok(existing),
                Ok(_) | Err(_) => Err(LegacyV2ProofCommitError::PublicationIndeterminate),
            }
        }

        fn pinned_map_identity(pin_dir: &Path) -> Result<PinnedMapIdentity, GtpuError> {
            let id = |name: &str| {
                MapInfo::from_pin(pin_dir.join(name))
                    .map(|info| info.id())
                    .map_err(|error| map_error("ebpf_map_pin_identity", error))
            };
            Ok(PinnedMapIdentity {
                uplink_far: id(MAP_UPLINK_FAR)?,
                uplink_mark_far: id(MAP_UPLINK_MARK_FAR)?,
                uplink_dscp: id(MAP_UPLINK_DSCP)?,
                uplink_mark_dscp: id(MAP_UPLINK_MARK_DSCP)?,
                uplink_source_port: id(MAP_UPLINK_SOURCE_PORT)?,
                uplink_mark_source_port: id(MAP_UPLINK_MARK_SOURCE_PORT)?,
                uplink_pmtu: id(MAP_UPLINK_PMTU)?,
                uplink_pmtu_counters: id(MAP_UPLINK_PMTU_COUNTERS)?,
                downlink_pdr: id(MAP_DOWNLINK_PDR)?,
                downlink_mark_pdr: id(MAP_DOWNLINK_MARK_PDR)?,
                downlink_binding: id(MAP_DOWNLINK_ENDPOINT_BINDING)?,
                marked_owner: id(MAP_MARKED_BEARER_OWNER)?,
                counters: id(MAP_COUNTERS)?,
                downlink_binding_counters: id(MAP_DOWNLINK_BINDING_COUNTERS)?,
                config: id(MAP_CONFIG)?,
            })
        }

        fn held_map_identity(ebpf: &Ebpf) -> Result<PinnedMapIdentity, GtpuError> {
            let missing = || GtpuError::io("ebpf_map_lookup", invalid_data("map missing"));
            let info_id = |map: &MapData| {
                map.info()
                    .map(|info| info.id())
                    .map_err(|error| map_error("ebpf_map_identity", error))
            };
            let uplink_far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(
                ebpf.map(MAP_UPLINK_FAR).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let uplink_mark_far =
                BpfHashMap::<_, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_UPLINK_MARK_FAR).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_map_identity", error))?;
            let uplink_dscp = BpfHashMap::<_, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(
                ebpf.map(MAP_UPLINK_DSCP).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let uplink_mark_dscp =
                BpfHashMap::<_, [u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_UPLINK_MARK_DSCP).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_map_identity", error))?;
            let uplink_source_port =
                BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_UPLINK_SOURCE_PORT).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_map_identity", error))?;
            let uplink_mark_source_port = BpfHashMap::<
                _,
                [u8; UPLINK_MARK_KEY_LEN],
                [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
            >::try_from(
                ebpf.map(MAP_UPLINK_MARK_SOURCE_PORT).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let uplink_pmtu = Array::<_, [u8; UPLINK_PMTU_VALUE_LEN]>::try_from(
                ebpf.map(MAP_UPLINK_PMTU).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let uplink_pmtu_counters = PerCpuArray::<_, u64>::try_from(
                ebpf.map(MAP_UPLINK_PMTU_COUNTERS).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let downlink_pdr = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(
                ebpf.map(MAP_DOWNLINK_PDR).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let downlink_mark_pdr =
                BpfHashMap::<_, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_DOWNLINK_MARK_PDR).ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_map_identity", error))?;
            let downlink_binding =
                BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_DOWNLINK_ENDPOINT_BINDING)
                        .ok_or_else(missing)?,
                )
                .map_err(|error| map_error("ebpf_map_identity", error))?;
            let marked_owner = BpfHashMap::<
                _,
                [u8; UPLINK_MARK_KEY_LEN],
                [u8; MARKED_BEARER_OWNER_VALUE_LEN],
            >::try_from(
                ebpf.map(MAP_MARKED_BEARER_OWNER).ok_or_else(missing)?
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let counters =
                PerCpuArray::<_, u64>::try_from(ebpf.map(MAP_COUNTERS).ok_or_else(missing)?)
                    .map_err(|error| map_error("ebpf_map_identity", error))?;
            let downlink_binding_counters = PerCpuArray::<_, u64>::try_from(
                ebpf.map(MAP_DOWNLINK_BINDING_COUNTERS)
                    .ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let config = Array::<_, [u8; 4]>::try_from(ebpf.map(MAP_CONFIG).ok_or_else(missing)?)
                .map_err(|error| map_error("ebpf_map_identity", error))?;
            Ok(PinnedMapIdentity {
                uplink_far: info_id(uplink_far.map())?,
                uplink_mark_far: info_id(uplink_mark_far.map())?,
                uplink_dscp: info_id(uplink_dscp.map())?,
                uplink_mark_dscp: info_id(uplink_mark_dscp.map())?,
                uplink_source_port: info_id(uplink_source_port.map())?,
                uplink_mark_source_port: info_id(uplink_mark_source_port.map())?,
                uplink_pmtu: info_id(uplink_pmtu.map())?,
                uplink_pmtu_counters: info_id(uplink_pmtu_counters.map())?,
                downlink_pdr: info_id(downlink_pdr.map())?,
                downlink_mark_pdr: info_id(downlink_mark_pdr.map())?,
                downlink_binding: info_id(downlink_binding.map())?,
                marked_owner: info_id(marked_owner.map())?,
                counters: info_id(counters.map())?,
                downlink_binding_counters: info_id(downlink_binding_counters.map())?,
                config: info_id(config.map())?,
            })
        }

        fn cleanup_pin_set_if_detached(
            pin_dir: &Path,
            expected: Option<&PinnedMapIdentity>,
            ifindex: u32,
            tc_priority: u16,
            hook_proof: PinCleanupHookProof,
        ) -> Result<(), GtpuError> {
            let indeterminate = || GtpuError::StateIndeterminate {
                operation: "ebpf_map_unpin",
            };
            let hooks_safe = match hook_proof {
                PinCleanupHookProof::RequireEmptySlots => {
                    let uplink = slot_owner(ifindex, TcAttachType::Egress, tc_priority)
                        .map_err(|_| indeterminate())?;
                    let downlink = slot_owner(ifindex, TcAttachType::Ingress, tc_priority)
                        .map_err(|_| indeterminate())?;
                    uplink.is_none() && downlink.is_none()
                }
                PinCleanupHookProof::NoDesiredHooks => true,
            };
            let current = expected
                .map(|_| Self::pinned_map_identity(pin_dir).map_err(|_| indeterminate()))
                .transpose()?;
            if !pin_cleanup_preflight_matches(expected, current.as_ref(), hooks_safe) {
                return Err(indeterminate());
            }
            Self::unpin(pin_dir).map_err(|_| indeterminate())
        }

        fn finish_fresh_attach_failure(
            pin_dir: &Path,
            expected: &PinnedMapIdentity,
            pins_preexisted: bool,
            ifindex: u32,
            tc_priority: u16,
            error: GtpuError,
        ) -> GtpuError {
            if !fresh_pin_cleanup_allowed(pins_preexisted, &error) {
                return error;
            }
            match Self::cleanup_pin_set_if_detached(
                pin_dir,
                Some(expected),
                ifindex,
                tc_priority,
                PinCleanupHookProof::NoDesiredHooks,
            ) {
                Ok(()) => error,
                Err(cleanup_error) => cleanup_error,
            }
        }

        fn unpin_if_current(
            ebpf: &Ebpf,
            pin_dir: &Path,
            expected: &DatapathIdentity,
        ) -> Result<(), GtpuError> {
            // `ebpf` retains the exact map/program FDs loaded under the
            // reconciler lease. Re-open every named pin and compare its ID to
            // that held identity immediately before pathname unlink. Classic
            // bpffs unlink has no conditional-by-object-ID operation, so the
            // exclusive-writer contract remains required across this check.
            let current = Self::datapath_identity(ebpf, pin_dir).map_err(|_| {
                GtpuError::StateIndeterminate {
                    operation: "ebpf_map_unpin",
                }
            })?;
            if &current != expected {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_map_unpin",
                });
            }
            Self::unpin(pin_dir).map_err(|_| GtpuError::StateIndeterminate {
                operation: "ebpf_map_unpin",
            })
        }

        fn loaded_datapath_is_current(ifindex: u32, loaded: &LoadedDevice) -> bool {
            let Ok(identity) = Self::datapath_identity(&loaded.ebpf, &loaded.pin_dir) else {
                return false;
            };
            identity == loaded.datapath_identity
                && matches!(
                    slot_owner(ifindex, TcAttachType::Egress, loaded.tc_priority),
                    Ok(Some(owner))
                        if owner.name == PROG_UPLINK
                            && owner.program_id == Some(identity.uplink.program_id)
                )
                && matches!(
                    slot_owner(ifindex, TcAttachType::Ingress, loaded.tc_priority),
                    Ok(Some(owner))
                        if owner.name == PROG_DOWNLINK
                            && owner.program_id == Some(identity.downlink.program_id)
                )
        }

        fn loaded_datapath_cleanup_safe(ifindex: u32, loaded: &LoadedDevice) -> bool {
            let Ok(identity) = Self::datapath_identity(&loaded.ebpf, &loaded.pin_dir) else {
                return false;
            };
            if identity != loaded.datapath_identity {
                return false;
            }
            let slot_is_exact_or_absent = |attach_type, name: &str, program_id| match slot_owner(
                ifindex,
                attach_type,
                loaded.tc_priority,
            ) {
                Ok(None) => true,
                Ok(Some(owner)) => owner.name == name && owner.program_id == Some(program_id),
                Err(_) => false,
            };
            slot_is_exact_or_absent(
                TcAttachType::Egress,
                PROG_UPLINK,
                identity.uplink.program_id,
            ) && slot_is_exact_or_absent(
                TcAttachType::Ingress,
                PROG_DOWNLINK,
                identity.downlink.program_id,
            )
        }

        fn attach_programs(
            &self,
            ebpf: &mut Ebpf,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            tc_priority: u16,
            schema_state: BearerSchemaState,
        ) -> Result<AttachedDatapath, GtpuError> {
            // clsact may already exist (EEXIST); that is fine.
            if let Err(error) = tc::qdisc_add_clsact(interface) {
                if !is_qdisc_already_present(&error) {
                    return Err(tc_error("ebpf_qdisc_add_clsact", &error));
                }
            }
            let uplink_artifact = load_program(ebpf, PROG_UPLINK)?;
            let downlink_artifact = load_program(ebpf, PROG_DOWNLINK)?;
            let mut legacy = if matches!(
                schema_state,
                BearerSchemaState::V1Uncommitted | BearerSchemaState::DscpV1
            ) {
                Some(self.load_legacy_v1_pinned(pin_dir)?)
            } else {
                None
            };
            let (legacy_uplink_artifact, legacy_downlink_artifact) = match legacy.as_mut() {
                Some(legacy) => {
                    let uplink = load_program(legacy, PROG_UPLINK)?;
                    let downlink = load_program(legacy, PROG_DOWNLINK)?;
                    // The migration fixture is trusted only when it resolves
                    // to the exact retained v1 pin IDs. Extra or swapped maps
                    // make the prior-generation proof fail closed.
                    Self::program_identity(
                        legacy,
                        pin_dir,
                        PROG_UPLINK,
                        &[MAP_UPLINK_FAR, MAP_UPLINK_DSCP, MAP_COUNTERS, MAP_CONFIG],
                    )?;
                    Self::program_identity(
                        legacy,
                        pin_dir,
                        PROG_DOWNLINK,
                        &[MAP_DOWNLINK_PDR, MAP_COUNTERS],
                    )?;
                    (Some(uplink), Some(downlink))
                }
                None => (None, None),
            };
            // Also bind both freshly loaded artifacts to every exact pinned
            // map they are expected to use before examining/replacing slots.
            let identity = Self::datapath_identity(ebpf, pin_dir)?;

            // Prove both hook occupants before either one is touched. This
            // prevents a foreign second hook from causing replacement of the
            // first hook and leaving a previously healthy datapath partial.
            let uplink_slot = preflight_program_slot(
                ifindex,
                PROG_UPLINK,
                TcAttachType::Egress,
                tc_priority,
                &uplink_artifact,
                legacy_uplink_artifact.as_ref(),
            )?;
            let downlink_slot = preflight_program_slot(
                ifindex,
                PROG_DOWNLINK,
                TcAttachType::Ingress,
                tc_priority,
                &downlink_artifact,
                legacy_downlink_artifact.as_ref(),
            )?;
            let uplink = attach_loaded_program(
                ebpf,
                interface,
                ifindex,
                tc_priority,
                uplink_slot,
                ProgramHook {
                    name: PROG_UPLINK,
                    attach_type: TcAttachType::Egress,
                    program_id: identity.uplink.program_id,
                },
            )?;
            let downlink = match attach_loaded_program(
                ebpf,
                interface,
                ifindex,
                tc_priority,
                downlink_slot,
                ProgramHook {
                    name: PROG_DOWNLINK,
                    attach_type: TcAttachType::Ingress,
                    program_id: identity.downlink.program_id,
                },
            ) {
                Ok(link) => link,
                Err(error) => {
                    if uplink_slot == SlotDisposition::Empty {
                        let rollback = detach_link_if_current(
                            uplink,
                            ifindex,
                            TcAttachType::Egress,
                            tc_priority,
                            PROG_UPLINK,
                            identity.uplink.program_id,
                            "ebpf_tc_attach_rollback",
                        );
                        return Err(error_after_rollback(
                            error,
                            rollback,
                            false,
                            "ebpf_tc_attach_rollback",
                        ));
                    }
                    // The first hook is now a proven current program while
                    // the second hook's failed mutation has already been
                    // reconciled as far as the kernel permits. Keep this
                    // safe mixed/current state for an idempotent retry. In
                    // particular, never detach a previously occupied hook
                    // into a packet-leak window merely to recreate the old
                    // pair.
                    let _retained_uplink = uplink;
                    return Err(state_indeterminate("ebpf_tc_attach_pair"));
                }
            };
            Ok(AttachedDatapath {
                identity,
                links: DatapathLinks { uplink, downlink },
                replaced_existing: matches!(uplink_slot, SlotDisposition::ReplaceExact { .. })
                    || matches!(downlink_slot, SlotDisposition::ReplaceExact { .. }),
            })
        }

        fn with_device<T>(
            &self,
            ifindex: u32,
            operation: &'static str,
            f: impl FnOnce(&mut LoadedDevice) -> Result<T, GtpuError>,
        ) -> Result<T, GtpuError> {
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| GtpuError::io(operation, super::poisoned_lock()))?;
            let device = devices.get_mut(&ifindex).ok_or(GtpuError::NotFound)?;
            f(device)
        }

        fn config_read(&self, ebpf: &Ebpf) -> Result<[u8; 4], GtpuError> {
            let map = ebpf
                .map(MAP_CONFIG)
                .ok_or_else(|| GtpuError::io("ebpf_config_map", invalid_data("map missing")))?;
            let array = Array::<_, [u8; 4]>::try_from(map)
                .map_err(|error| map_error("ebpf_config_map", error))?;
            array
                .get(&0, 0)
                .map_err(|error| map_error("ebpf_config_read", error))
        }

        fn config_write(&self, ebpf: &mut Ebpf, local_ip: [u8; 4]) -> Result<(), GtpuError> {
            let map = ebpf
                .map_mut(MAP_CONFIG)
                .ok_or_else(|| GtpuError::io("ebpf_config_map", invalid_data("map missing")))?;
            let mut array = Array::<_, [u8; 4]>::try_from(map)
                .map_err(|error| map_error("ebpf_config_map", error))?;
            array
                .set(0, local_ip, 0)
                .map_err(|error| map_error("ebpf_config_write", error))
        }

        fn pmtu_policy_slot(&self, ebpf: &Ebpf) -> Result<[u8; UPLINK_PMTU_VALUE_LEN], GtpuError> {
            let map = ebpf
                .map(MAP_UPLINK_PMTU)
                .ok_or_else(|| GtpuError::io("ebpf_pmtu_map", invalid_data("map missing")))?;
            let array = Array::<_, [u8; UPLINK_PMTU_VALUE_LEN]>::try_from(map)
                .map_err(|error| map_error("ebpf_pmtu_map", error))?;
            array
                .get(&0, 0)
                .map_err(|error| map_error("ebpf_pmtu_policy_read", error))
        }

        /// Fail closed when retained pins carry corrupt uplink MTU policy
        /// bytes: adopting them would blackhole all uplink traffic while the
        /// capability probe reads Available.
        fn require_canonical_pmtu_slot(&self, ebpf: &Ebpf) -> Result<(), GtpuError> {
            if matches!(
                GtpuUplinkMtuPolicy::decode_map_value(&self.pmtu_policy_slot(ebpf)?),
                UplinkMtuMapState::Corrupt
            ) {
                return Err(state_indeterminate("ebpf_pmtu_policy_adopt"));
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SlotDisposition {
        Empty,
        ReplaceExact { current_program_id: u32 },
    }

    #[derive(Debug, Clone, Copy)]
    struct ProgramHook<'a> {
        name: &'a str,
        attach_type: TcAttachType,
        program_id: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FailedAttachReadback {
        AdoptExact,
        ProvenAbsent,
        ProvenOriginal,
        Indeterminate,
    }

    fn owner_matches_hook(owner: &FilterOwner, hook: ProgramHook<'_>) -> bool {
        owner.name == hook.name && owner.program_id == Some(hook.program_id)
    }

    fn classify_failed_attach_readback(
        slot: SlotDisposition,
        hook: ProgramHook<'_>,
        owner: &Result<Option<FilterOwner>, GtpuError>,
    ) -> FailedAttachReadback {
        match owner {
            Ok(Some(owner)) if owner_matches_hook(owner, hook) => FailedAttachReadback::AdoptExact,
            Ok(None) if slot == SlotDisposition::Empty => FailedAttachReadback::ProvenAbsent,
            Ok(Some(owner))
                if matches!(
                    slot,
                    SlotDisposition::ReplaceExact { current_program_id }
                        if owner.name == hook.name
                            && owner.program_id == Some(current_program_id)
                ) =>
            {
                FailedAttachReadback::ProvenOriginal
            }
            Ok(_) | Err(_) => FailedAttachReadback::Indeterminate,
        }
    }

    fn state_indeterminate(operation: &'static str) -> GtpuError {
        GtpuError::StateIndeterminate { operation }
    }

    fn mutation_or_indeterminate<T, E>(
        result: Result<T, E>,
        operation: &'static str,
    ) -> Result<T, GtpuError> {
        result.map_err(|_| state_indeterminate(operation))
    }

    fn error_after_rollback(
        source: GtpuError,
        rollback: Result<(), GtpuError>,
        replaced_existing: bool,
        operation: &'static str,
    ) -> GtpuError {
        if replaced_existing || rollback.is_err() {
            state_indeterminate(operation)
        } else {
            source
        }
    }

    fn fresh_pin_cleanup_allowed(pins_preexisted: bool, error: &GtpuError) -> bool {
        !pins_preexisted && !matches!(error, GtpuError::StateIndeterminate { .. })
    }

    fn pin_cleanup_preflight_matches(
        expected: Option<&PinnedMapIdentity>,
        current: Option<&PinnedMapIdentity>,
        hooks_safe: bool,
    ) -> bool {
        hooks_safe && expected.is_none_or(|expected| current == Some(expected))
    }

    fn load_program(ebpf: &mut Ebpf, name: &str) -> Result<ProgramInfo, GtpuError> {
        let program: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or_else(|| GtpuError::io("ebpf_program_lookup", invalid_data("program missing")))?
            .try_into()
            .map_err(|_: ProgramError| {
                GtpuError::io("ebpf_program_type", invalid_data("not a classifier"))
            })?;
        program
            .load()
            .map_err(|error| program_error("ebpf_program_load", &error))?;
        program
            .info()
            .map_err(|error| program_error("ebpf_artifact_program_info", &error))
    }

    fn preflight_program_slot(
        ifindex: u32,
        name: &str,
        attach_type: TcAttachType,
        tc_priority: u16,
        artifact: &ProgramInfo,
        legacy_artifact: Option<&ProgramInfo>,
    ) -> Result<SlotDisposition, GtpuError> {
        match slot_owner(ifindex, attach_type, tc_priority)? {
            None => Ok(SlotDisposition::Empty),
            Some(owner) => {
                let current_matches = owner_matches_artifact(&owner, name, artifact)?;
                let legacy_matches = match legacy_artifact {
                    Some(legacy_artifact) => owner_matches_artifact(&owner, name, legacy_artifact)?,
                    None => false,
                };
                if !current_matches && !legacy_matches {
                    return Err(GtpuError::AlreadyExists);
                }
                Ok(SlotDisposition::ReplaceExact {
                    current_program_id: owner.program_id.ok_or_else(|| {
                        GtpuError::io(
                            "ebpf_program_info",
                            invalid_data("tc filter did not report a program id"),
                        )
                    })?,
                })
            }
        }
    }

    fn attach_loaded_program(
        ebpf: &mut Ebpf,
        interface: &str,
        ifindex: u32,
        tc_priority: u16,
        slot: SlotDisposition,
        hook: ProgramHook<'_>,
    ) -> Result<ManuallyDrop<SchedClassifierLink>, GtpuError> {
        let program: &mut SchedClassifier = ebpf
            .program_mut(hook.name)
            .ok_or_else(|| GtpuError::io("ebpf_program_lookup", invalid_data("program missing")))?
            .try_into()
            .map_err(|_: ProgramError| {
                GtpuError::io("ebpf_program_type", invalid_data("not a classifier"))
            })?;
        let options = || {
            TcAttachOptions::Netlink(NlOptions {
                priority: tc_priority,
                handle: TC_HANDLE,
                classid: None,
            })
        };
        let attach_result = if let SlotDisposition::ReplaceExact { current_program_id } = slot {
            let still_current = slot_has_program(
                ifindex,
                hook.attach_type,
                tc_priority,
                hook.name,
                current_program_id,
            )
            .map_err(|_| state_indeterminate("ebpf_tc_replace"))?;
            if !still_current {
                return Err(GtpuError::AlreadyExists);
            }
            // Aya's netlink `attach_to_link` path sets create=false and
            // replaces this exact priority/handle in one RTM_NEWTFILTER
            // operation. Never detach an established datapath into a packet
            // leak window while upgrading its program generation.
            let link = SchedClassifierLink::attached(
                interface,
                hook.attach_type,
                tc_priority,
                TC_HANDLE,
                None,
            )
            .map_err(|error| GtpuError::io("ebpf_tc_replace", error))?;
            program.attach_to_link(link)
        } else {
            program.attach_with_options(interface, hook.attach_type, options())
        };
        let link_id = match attach_result {
            Ok(link_id) => link_id,
            Err(error) => {
                let owner = slot_owner(ifindex, hook.attach_type, tc_priority);
                return match classify_failed_attach_readback(slot, hook, &owner) {
                    FailedAttachReadback::AdoptExact => SchedClassifierLink::attached(
                        interface,
                        hook.attach_type,
                        tc_priority,
                        TC_HANDLE,
                        None,
                    )
                    .map(ManuallyDrop::new)
                    .map_err(|_| state_indeterminate("ebpf_tc_attach")),
                    FailedAttachReadback::ProvenAbsent => {
                        Err(program_error("ebpf_tc_attach", &error))
                    }
                    FailedAttachReadback::ProvenOriginal => {
                        Err(program_error("ebpf_tc_replace", &error))
                    }
                    FailedAttachReadback::Indeterminate => {
                        Err(state_indeterminate("ebpf_tc_attach"))
                    }
                };
            }
        };
        let link = mutation_or_indeterminate(program.take_link(link_id), "ebpf_tc_link_ownership")?;
        let link = ManuallyDrop::new(link);
        match slot_owner(ifindex, hook.attach_type, tc_priority) {
            Ok(Some(owner)) if owner_matches_hook(&owner, hook) => Ok(link),
            // `link` is already kernel-owned. Do not let a stale slot handle
            // detach an external replacement while this error unwinds, and do
            // not let the caller unlink pins beneath an unproven live hook.
            Ok(_) | Err(_) => Err(state_indeterminate("ebpf_tc_attach_readback")),
        }
    }

    fn slot_has_program(
        ifindex: u32,
        attach_type: TcAttachType,
        tc_priority: u16,
        name: &str,
        program_id: u32,
    ) -> Result<bool, GtpuError> {
        Ok(matches!(
            slot_owner(ifindex, attach_type, tc_priority)?,
            Some(owner) if owner.name == name && owner.program_id == Some(program_id)
        ))
    }

    fn detach_link_if_current(
        link: ManuallyDrop<SchedClassifierLink>,
        ifindex: u32,
        attach_type: TcAttachType,
        tc_priority: u16,
        name: &str,
        program_id: u32,
        operation: &'static str,
    ) -> Result<(), GtpuError> {
        if !slot_has_program(ifindex, attach_type, tc_priority, name, program_id)? {
            return Err(GtpuError::AlreadyExists);
        }
        ManuallyDrop::into_inner(link)
            .detach()
            .map_err(|error| program_error(operation, &error))
    }

    fn detach_datapath_if_current(
        links: DatapathLinks,
        identity: &DatapathIdentity,
        ifindex: u32,
        tc_priority: u16,
    ) -> Result<(), GtpuError> {
        // Preflight both hooks before touching either one so a replacement
        // already visible on either side fails removal without mutation. Each
        // actual detach repeats its exact-ID check as closely as the netlink
        // API permits; an uncoordinated concurrent change is unsupported and
        // may instead produce a typed indeterminate outcome.
        if !slot_has_program(
            ifindex,
            TcAttachType::Egress,
            tc_priority,
            PROG_UPLINK,
            identity.uplink.program_id,
        )? || !slot_has_program(
            ifindex,
            TcAttachType::Ingress,
            tc_priority,
            PROG_DOWNLINK,
            identity.downlink.program_id,
        )? {
            return Err(GtpuError::AlreadyExists);
        }

        if let Err(error) = detach_link_if_current(
            links.uplink,
            ifindex,
            TcAttachType::Egress,
            tc_priority,
            PROG_UPLINK,
            identity.uplink.program_id,
            "ebpf_tc_detach",
        ) {
            return Err(classify_detach_failure(error, false));
        }
        if let Err(error) = detach_link_if_current(
            links.downlink,
            ifindex,
            TcAttachType::Ingress,
            tc_priority,
            PROG_DOWNLINK,
            identity.downlink.program_id,
            "ebpf_tc_detach",
        ) {
            return Err(classify_detach_failure(error, true));
        }
        Ok(())
    }

    fn classify_detach_failure(error: GtpuError, prior_detach_confirmed: bool) -> GtpuError {
        if !prior_detach_confirmed && matches!(error, GtpuError::AlreadyExists) {
            // The immediate ID recheck failed before the first delete was
            // attempted, so no mutation was made by this cleanup call.
            GtpuError::AlreadyExists
        } else {
            // A netlink delete error can be post-mutation/ACK-loss, and every
            // second-hook failure follows a confirmed first-hook deletion.
            GtpuError::StateIndeterminate {
                operation: "ebpf_tc_detach",
            }
        }
    }

    fn owner_matches_artifact(
        owner: &FilterOwner,
        program_name: &str,
        artifact: &ProgramInfo,
    ) -> Result<bool, GtpuError> {
        let Some(program_id) = owner.program_id else {
            return Ok(false);
        };
        if owner.name != program_name {
            return Ok(false);
        }
        let occupant = loaded_programs()
            .find_map(|result| match result {
                Ok(info) if info.id() == program_id => Some(Ok(info)),
                Ok(_) => None,
                Err(error) => Some(Err(program_error("ebpf_program_info", &error))),
            })
            .transpose()?
            .ok_or_else(|| {
                GtpuError::io(
                    "ebpf_program_info",
                    io::Error::new(io::ErrorKind::NotFound, "tc program id is not loaded"),
                )
            })?;
        let mut occupant_map_ids = occupant
            .map_ids()
            .map_err(|error| program_error("ebpf_program_map_ids", &error))?
            .ok_or_else(|| {
                GtpuError::io(
                    "ebpf_program_map_ids",
                    invalid_data("kernel did not report occupant map ids"),
                )
            })?;
        let mut artifact_map_ids = artifact
            .map_ids()
            .map_err(|error| program_error("ebpf_program_map_ids", &error))?
            .ok_or_else(|| {
                GtpuError::io(
                    "ebpf_program_map_ids",
                    invalid_data("kernel did not report artifact map ids"),
                )
            })?;
        occupant_map_ids.sort_unstable();
        artifact_map_ids.sort_unstable();
        Ok(occupant.name() == artifact.name()
            && occupant.tag() == artifact.tag()
            && occupant.program_type() == artifact.program_type()
            && occupant_map_ids == artifact_map_ids)
    }

    fn owner_matches_legacy_v2_record(
        owner: &FilterOwner,
        program_name: &str,
        expected_program_id: u32,
        expected_program_tag: u64,
        expected_map_ids: &[u32],
    ) -> Result<bool, GtpuError> {
        if owner.name != program_name || owner.program_id != Some(expected_program_id) {
            return Ok(false);
        }
        let occupant = loaded_programs()
            .find_map(|result| match result {
                Ok(info) if info.id() == expected_program_id => Some(Ok(info)),
                Ok(_) => None,
                Err(error) => Some(Err(program_error("ebpf_program_info", &error))),
            })
            .transpose()?
            .ok_or_else(|| state_indeterminate("ebpf_legacy_v2_hook_identity"))?;
        let mut occupant_map_ids = occupant
            .map_ids()
            .map_err(|error| program_error("ebpf_program_map_ids", &error))?
            .ok_or_else(|| state_indeterminate("ebpf_legacy_v2_hook_identity"))?;
        let mut expected_map_ids = expected_map_ids.to_vec();
        occupant_map_ids.sort_unstable();
        expected_map_ids.sort_unstable();
        Ok(occupant.name() == kernel_program_name(program_name)
            && occupant.tag() == expected_program_tag
            && occupant.program_type() == bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS
            && occupant_map_ids == expected_map_ids)
    }

    fn legacy_v2_artifact_owner_tag(
        owner: &FilterOwner,
        program_name: &str,
        expected_tags: LegacyV2ProgramTags,
        expected_map_ids: &[u32],
    ) -> Result<Option<(u32, u64)>, GtpuError> {
        let Some(program_id) = owner.program_id else {
            return Ok(None);
        };
        if owner.name != program_name {
            return Ok(None);
        }
        let occupant = loaded_programs()
            .find_map(|result| match result {
                Ok(info) if info.id() == program_id => Some(Ok(info)),
                Ok(_) => None,
                Err(error) => Some(Err(program_error("ebpf_program_info", &error))),
            })
            .transpose()?
            .ok_or_else(|| state_indeterminate("ebpf_legacy_v2_hook_identity"))?;
        let mut occupant_map_ids = occupant
            .map_ids()
            .map_err(|error| program_error("ebpf_program_map_ids", &error))?
            .ok_or_else(|| state_indeterminate("ebpf_legacy_v2_hook_identity"))?;
        let mut expected_map_ids = expected_map_ids.to_vec();
        occupant_map_ids.sort_unstable();
        expected_map_ids.sort_unstable();
        let tag = occupant.tag();
        Ok((occupant.name() == kernel_program_name(program_name)
            && expected_tags.contains(tag)
            && occupant.program_type() == bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS
            && occupant_map_ids == expected_map_ids)
            .then_some((program_id, tag)))
    }

    fn kernel_program_name(name: &str) -> &[u8] {
        const BPF_OBJ_NAME_VISIBLE_LEN: usize = 15;
        &name.as_bytes()[..name.len().min(BPF_OBJ_NAME_VISIBLE_LEN)]
    }

    const fn clsact_parent(attach_type: TcAttachType) -> u32 {
        match attach_type {
            TcAttachType::Egress => sys::TC_H_CLSACT_EGRESS,
            _ => sys::TC_H_CLSACT_INGRESS,
        }
    }

    // `tc` stores the Ethernet protocol in network byte order in the low half
    // of `tcm_info`. Aya attaches every SDK classifier with ETH_P_ALL.
    const TC_PROTOCOL_ALL: u16 = 3_u16.to_be();

    /// Return the owner of the tc filter occupying our exact
    /// (hook, priority, handle) slot, or `None` only after a complete dump
    /// proves the slot is empty. A non-BPF filter is reported as a foreign
    /// owner rather than conflated with absence.
    ///
    /// This is the ownership check that keeps cleanup and replace operations
    /// strictly scoped to the datapath's own programs.
    fn slot_owner(
        ifindex: u32,
        attach_type: TcAttachType,
        tc_priority: u16,
    ) -> Result<Option<FilterOwner>, GtpuError> {
        filter_observation(
            ifindex,
            attach_type,
            tc_priority,
            LegacyV2ProgramScan::Disabled,
        )
        .map(|state| state.owner)
    }

    /// Read a complete, target-bound filter dump. Legacy-v2 teardown callers
    /// can additionally require every SDK-named legacy program on the hook to
    /// be absent, or allow only one expected name in the exact recorded slot.
    fn filter_observation(
        ifindex: u32,
        attach_type: TcAttachType,
        tc_priority: u16,
        legacy_v2_scan: LegacyV2ProgramScan<'_>,
    ) -> Result<TfilterDumpState, GtpuError> {
        const DUMP_SEQUENCE: u32 = 1;
        let socket = sys::open_route_netlink_socket()
            .map_err(|error| GtpuError::io("tc_filter_dump", error))?;
        let local_port_id = socket.port_id();

        // struct tcmsg (20 bytes) + netlink header, RTM_GETTFILTER dump.
        let ifindex = i32::try_from(ifindex).map_err(|_| {
            GtpuError::invalid_config("device.ifindex", "ifindex exceeds i32 range")
        })?;
        let mut request = Vec::with_capacity(36);
        request.extend_from_slice(&36_u32.to_ne_bytes()); // nlmsg_len
        request.extend_from_slice(&sys::RTM_GETTFILTER.to_ne_bytes());
        request.extend_from_slice(&(sys::NLM_F_REQUEST | sys::NLM_F_DUMP).to_ne_bytes());
        request.extend_from_slice(&DUMP_SEQUENCE.to_ne_bytes());
        request.extend_from_slice(&local_port_id.to_ne_bytes());
        request.push(0); // tcm_family = AF_UNSPEC
        request.extend_from_slice(&[0; 3]); // padding
        request.extend_from_slice(&ifindex.to_ne_bytes());
        request.extend_from_slice(&0_u32.to_ne_bytes()); // tcm_handle: all
        let parent = clsact_parent(attach_type);
        request.extend_from_slice(&parent.to_ne_bytes());
        request.extend_from_slice(&u32::from(TC_PROTOCOL_ALL).to_ne_bytes());

        sys::send_message(&socket, &request)
            .map_err(|error| GtpuError::io("tc_filter_dump", error))?;

        let mut buffer = vec![0_u8; 65536];
        let mut state = TfilterDumpState::default();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(GtpuError::io(
                    "tc_filter_dump",
                    io::Error::new(io::ErrorKind::TimedOut, "tc dump timeout"),
                ));
            }
            let length = match sys::receive_message(&socket, &mut buffer) {
                Ok(0) => continue,
                Ok(length) => length,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Err(error) => return Err(GtpuError::io("tc_filter_dump", error)),
            };
            match parse_tfilter_dump(
                &buffer[..length],
                tc_priority,
                TfilterDumpExpectation {
                    sequence: DUMP_SEQUENCE,
                    port_id: local_port_id,
                    ifindex,
                    parent,
                    protocol: TC_PROTOCOL_ALL,
                    legacy_v2_scan,
                },
                &mut state,
            )? {
                DumpOutcome::Done => return Ok(state),
                DumpOutcome::More => {}
            }
        }
    }

    fn unproven_legacy_v2_hook_occupant(
        ifindex: u32,
        attach_type: TcAttachType,
        tc_priority: u16,
    ) -> Result<Option<()>, GtpuError> {
        let observation = filter_observation(
            ifindex,
            attach_type,
            tc_priority,
            LegacyV2ProgramScan::RequireAbsent,
        )?;
        Ok(observation.unexpected_legacy_v2_program_seen.then_some(()))
    }

    #[derive(Debug)]
    enum DumpOutcome {
        Done,
        More,
    }

    #[derive(Default)]
    struct TfilterDumpState {
        owner: Option<FilterOwner>,
        unexpected_legacy_v2_program_seen: bool,
    }

    #[derive(Clone, Copy)]
    enum LegacyV2ProgramScan<'a> {
        Disabled,
        RequireAbsent,
        AllowExact(&'a str),
    }

    #[derive(Clone, Copy)]
    struct TfilterDumpExpectation<'a> {
        sequence: u32,
        port_id: u32,
        ifindex: i32,
        parent: u32,
        protocol: u16,
        legacy_v2_scan: LegacyV2ProgramScan<'a>,
    }

    impl TfilterDumpState {
        fn observe_owner(&mut self, owner: FilterOwner) -> Result<(), GtpuError> {
            if self.owner.is_some() {
                return Err(state_indeterminate("ebpf_tc_filter_dump"));
            }
            self.owner = Some(owner);
            Ok(())
        }
    }

    /// Validate one datagram from an RTM_GETTFILTER dump and accumulate the
    /// exact-slot owner as provisional evidence. Absence or ownership becomes
    /// authoritative only when the caller observes [`DumpOutcome::Done`].
    fn parse_tfilter_dump(
        datagram: &[u8],
        tc_priority: u16,
        expected: TfilterDumpExpectation<'_>,
        state: &mut TfilterDumpState,
    ) -> Result<DumpOutcome, GtpuError> {
        const NL_HDR: usize = 16;
        const TCMSG: usize = 20;
        let malformed =
            || GtpuError::io("tc_filter_dump", invalid_data("malformed tc dump response"));
        let incomplete = || state_indeterminate("ebpf_tc_filter_dump");

        let mut offset = 0;
        let mut done = false;
        while offset < datagram.len() {
            if datagram.len() - offset < NL_HDR {
                return Err(malformed());
            }
            let read_u32 = |at: usize| -> Result<u32, GtpuError> {
                datagram
                    .get(at..at + 4)
                    .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
                    .ok_or_else(malformed)
            };
            let read_u16 = |at: usize| -> Result<u16, GtpuError> {
                datagram
                    .get(at..at + 2)
                    .map(|b| u16::from_ne_bytes([b[0], b[1]]))
                    .ok_or_else(malformed)
            };
            let length = read_u32(offset)? as usize;
            if length < NL_HDR || offset + length > datagram.len() {
                return Err(malformed());
            }
            let message_type = read_u16(offset + 4)?;
            let flags = read_u16(offset + 6)?;
            let sequence = read_u32(offset + 8)?;
            let port_id = read_u32(offset + 12)?;
            if sequence != expected.sequence || port_id != expected.port_id {
                return Err(incomplete());
            }
            if flags & sys::NLM_F_DUMP_INTR != 0 {
                return Err(incomplete());
            }
            if done && message_type != sys::NLMSG_NOOP {
                return Err(malformed());
            }
            let body = &datagram[offset + NL_HDR..offset + length];
            match message_type {
                t if t == sys::NLMSG_DONE => {
                    if flags & sys::NLM_F_MULTI == 0 || body.len() != 4 {
                        return Err(malformed());
                    }
                    let status = i32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
                    if status != 0 {
                        return Err(incomplete());
                    }
                    done = true;
                }
                t if t == sys::NLMSG_ERROR => return Err(incomplete()),
                t if t == sys::NLMSG_OVERRUN => return Err(incomplete()),
                t if t == sys::NLMSG_NOOP => {}
                t if t == sys::RTM_NEWTFILTER => {
                    if done || flags & sys::NLM_F_MULTI == 0 || length < NL_HDR + TCMSG {
                        return Err(malformed());
                    }
                    let body = offset + NL_HDR;
                    let family = datagram[body];
                    let response_ifindex = i32::from_ne_bytes([
                        datagram[body + 4],
                        datagram[body + 5],
                        datagram[body + 6],
                        datagram[body + 7],
                    ]);
                    let handle = read_u32(body + 8)?;
                    let parent = read_u32(body + 12)?;
                    let info = read_u32(body + 16)?;
                    let priority = (info >> 16) as u16;
                    let protocol = info as u16;
                    if family != 0
                        || response_ifindex != expected.ifindex
                        || parent != expected.parent
                        || protocol != expected.protocol
                    {
                        return Err(incomplete());
                    }
                    let owner = bpf_filter_owner(&datagram[body + TCMSG..offset + length]);
                    if let Some(owner) = &owner {
                        let name = owner.name.as_bytes();
                        let is_legacy_v2_name = [PROG_UPLINK, PROG_DOWNLINK]
                            .into_iter()
                            .any(|candidate| name == kernel_program_name(candidate));
                        let allowed = match expected.legacy_v2_scan {
                            LegacyV2ProgramScan::Disabled => true,
                            LegacyV2ProgramScan::RequireAbsent => false,
                            LegacyV2ProgramScan::AllowExact(expected_name) => {
                                handle == u32::from(TC_HANDLE)
                                    && priority == tc_priority
                                    && name == kernel_program_name(expected_name)
                            }
                        };
                        if is_legacy_v2_name && !allowed {
                            state.unexpected_legacy_v2_program_seen = true;
                        }
                    }
                    if handle == u32::from(TC_HANDLE) && priority == tc_priority {
                        if let Some(owner) = owner {
                            state.observe_owner(owner)?;
                        } else {
                            // Occupied by a non-BPF filter: report a foreign
                            // owner so callers refuse to touch the slot.
                            state.observe_owner(FilterOwner {
                                name: String::from("<non-bpf-filter>"),
                                program_id: None,
                            })?;
                        }
                    }
                }
                _ => return Err(malformed()),
            }
            let aligned = sys::align_to_netlink(length).ok_or_else(malformed)?;
            let aligned_end = offset.checked_add(aligned).ok_or_else(malformed)?;
            if aligned_end > datagram.len() {
                return Err(malformed());
            }
            offset = aligned_end;
        }
        Ok(if done {
            DumpOutcome::Done
        } else {
            DumpOutcome::More
        })
    }

    /// Extract the BPF name and kernel program ID from a filter message.
    fn bpf_filter_owner(attributes: &[u8]) -> Option<FilterOwner> {
        let kind = find_attribute(attributes, sys::TCA_KIND)?;
        if kind != b"bpf\0" {
            return None;
        }
        let options = find_attribute(attributes, sys::TCA_OPTIONS)?;
        let name = find_attribute(options, sys::TCA_BPF_NAME)?;
        let name = name.strip_suffix(b"\0").unwrap_or(name);
        let program_id = find_attribute(options, sys::TCA_BPF_ID).and_then(|value| {
            value
                .get(..4)
                .map(|value| u32::from_ne_bytes([value[0], value[1], value[2], value[3]]))
        });
        Some(FilterOwner {
            name: String::from_utf8_lossy(name).into_owned(),
            program_id,
        })
    }

    fn find_attribute(mut attributes: &[u8], attribute_type: u16) -> Option<&[u8]> {
        const ATTR_HDR: usize = 4;
        while attributes.len() >= ATTR_HDR {
            let length = usize::from(u16::from_ne_bytes([attributes[0], attributes[1]]));
            let found = u16::from_ne_bytes([attributes[2], attributes[3]]);
            if length < ATTR_HDR || length > attributes.len() {
                return None;
            }
            // Nested attributes carry kernel flag bits in the type's high
            // bits; compare the low 14 bits.
            if found & 0x3FFF == attribute_type {
                return Some(&attributes[ATTR_HDR..length]);
            }
            attributes = &attributes[sys::align_to_netlink(length)?.min(attributes.len())..];
        }
        None
    }

    /// `qdisc_add_clsact` has no dedicated exists error over netlink; treat
    /// `EEXIST` from the kernel as already-present.
    fn is_qdisc_already_present(error: &TcError) -> bool {
        match error {
            TcError::AlreadyAttached => true,
            TcError::NetlinkError(error) => error.raw_os_error() == Some(libc_eexist()),
            _ => false,
        }
    }

    const fn libc_eexist() -> i32 {
        17 // EEXIST on Linux
    }

    /// Map aya tc errors to redaction-safe I/O errors.
    fn tc_error(operation: &'static str, error: &TcError) -> GtpuError {
        let raw = match error {
            TcError::NetlinkError(error) => error.raw_os_error(),
            TcError::IoError(error) => error.raw_os_error(),
            _ => None,
        };
        match raw {
            Some(code) => GtpuError::io(operation, io::Error::from_raw_os_error(code)),
            None => GtpuError::io(operation, invalid_data("tc operation failed")),
        }
    }

    impl EbpfGtpuRuntime for AyaGtpuRuntime {
        fn ifindex_by_name(&self, name: &str) -> Result<u32, GtpuError> {
            sys::ifindex_by_name(name).map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => GtpuError::NotFound,
                _ => GtpuError::io("ifindex_lookup", error),
            })
        }

        fn attach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            tc_priority: u16,
            local_ip: [u8; 4],
        ) -> Result<(), GtpuError> {
            let pins_preexisted = pin_dir.is_dir();
            let canonical_pin_dir = Self::canonical_pin_dir(pin_dir)?;
            let reconciler_ownership =
                Self::acquire_reconciler_ownership(&canonical_pin_dir, ifindex)?;
            let schema_state = Self::bearer_schema_preflight(&canonical_pin_dir)?;
            let mut ebpf = match self.load_pinned(&canonical_pin_dir) {
                Ok(ebpf) => ebpf,
                Err(error) if pins_preexisted => return Err(error),
                Err(error) => {
                    return match Self::cleanup_pin_set_if_detached(
                        &canonical_pin_dir,
                        None,
                        ifindex,
                        tc_priority,
                        PinCleanupHookProof::RequireEmptySlots,
                    ) {
                        Ok(()) => Err(error),
                        Err(cleanup_error) => Err(cleanup_error),
                    };
                }
            };
            let expected_pins = Self::held_map_identity(&ebpf)
                .map_err(|_| state_indeterminate("ebpf_map_identity"))?;
            let named_pins = Self::pinned_map_identity(&canonical_pin_dir)
                .map_err(|_| state_indeterminate("ebpf_map_identity"))?;
            if named_pins != expected_pins {
                return Err(state_indeterminate("ebpf_map_identity"));
            }
            let provisioned = (|| {
                if schema_state == BearerSchemaState::Fresh {
                    // A fresh pin transaction owns the new config slot and
                    // publishes it before either program can see traffic.
                    self.config_write(&mut ebpf, local_ip)?;
                } else if self.config_read(&ebpf)? != local_ip {
                    // Retained pins may still serve a live prior-generation
                    // datapath. Never mutate its shared config before hook
                    // authority is proven; create with a different local
                    // address is an ownership conflict.
                    return Err(GtpuError::AlreadyExists);
                }
                self.require_canonical_pmtu_slot(&ebpf)?;
                let indexes = if matches!(
                    schema_state,
                    BearerSchemaState::SourcePortV4 | BearerSchemaState::PmtuV5
                ) {
                    Self::recover_incomplete_pdp_commits(&mut ebpf, local_ip, ifindex)?;
                    Self::pdp_host_indexes(&ebpf, local_ip, ifindex, true)?
                } else {
                    let pre_v4_indexes = Self::pdp_host_indexes(&ebpf, local_ip, ifindex, false)?;
                    Self::materialize_legacy_source_port_policies(&mut ebpf, &pre_v4_indexes)?;
                    Self::recover_incomplete_pdp_commits(&mut ebpf, local_ip, ifindex)?;
                    Self::pdp_host_indexes(&ebpf, local_ip, ifindex, true)?
                };
                let attached = self.attach_programs(
                    &mut ebpf,
                    interface,
                    ifindex,
                    &canonical_pin_dir,
                    tc_priority,
                    schema_state,
                )?;
                if schema_state != BearerSchemaState::PmtuV5 {
                    if let Err(error) = Self::write_bearer_schema_marker(&mut ebpf) {
                        if attached.replaced_existing {
                            // Both exact current hooks remain live. Retaining them
                            // with the prior marker is a retryable,
                            // fail-closed migration state; removing them
                            // would create an outage for the displaced v1
                            // datapath.
                            return Err(state_indeterminate("ebpf_schema_marker_commit"));
                        }
                        let rollback = detach_datapath_if_current(
                            attached.links,
                            &attached.identity,
                            ifindex,
                            tc_priority,
                        );
                        return Err(error_after_rollback(
                            error,
                            rollback,
                            false,
                            "ebpf_tc_attach_rollback",
                        ));
                    }
                }
                Ok((attached, indexes))
            })();
            let (attached, indexes) = match provisioned {
                Ok(provisioned) => provisioned,
                Err(error) => {
                    let error = Self::finish_fresh_attach_failure(
                        &canonical_pin_dir,
                        &expected_pins,
                        pins_preexisted,
                        ifindex,
                        tc_priority,
                        error,
                    );
                    drop(ebpf);
                    return Err(error);
                }
            };
            let mut devices = match self.devices.lock() {
                Ok(devices) => devices,
                Err(_) => {
                    if attached.replaced_existing {
                        return Err(state_indeterminate("ebpf_device_commit"));
                    }
                    let rollback = detach_datapath_if_current(
                        attached.links,
                        &attached.identity,
                        ifindex,
                        tc_priority,
                    );
                    let error = error_after_rollback(
                        GtpuError::io("ebpf_attach", super::poisoned_lock()),
                        rollback,
                        false,
                        "ebpf_tc_attach_rollback",
                    );
                    let error = Self::finish_fresh_attach_failure(
                        &canonical_pin_dir,
                        &expected_pins,
                        pins_preexisted,
                        ifindex,
                        tc_priority,
                        error,
                    );
                    drop(ebpf);
                    return Err(error);
                }
            };
            devices.insert(
                ifindex,
                LoadedDevice {
                    ebpf,
                    marked_owner_by_teid: indexes.marked_owner_by_teid,
                    default_teid_by_ue: indexes.default_teid_by_ue,
                    links: attached.links,
                    pin_dir: canonical_pin_dir,
                    tc_priority,
                    datapath_identity: attached.identity,
                    _reconciler_ownership: reconciler_ownership,
                },
            );
            Ok(())
        }

        fn adopt(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            tc_priority: u16,
        ) -> Result<[u8; 4], GtpuError> {
            if !pin_dir.is_dir() {
                return Err(GtpuError::NotFound);
            }
            let canonical_pin_dir = fs::canonicalize(pin_dir)
                .map_err(|error| GtpuError::io("ebpf_pin_dir_canonicalize", error))?;
            let reconciler_ownership =
                Self::acquire_reconciler_ownership(&canonical_pin_dir, ifindex)?;
            let schema_state = Self::bearer_schema_preflight(&canonical_pin_dir)?;
            let mut ebpf = self.load_pinned(&canonical_pin_dir)?;
            let expected_pins = Self::held_map_identity(&ebpf)
                .map_err(|_| state_indeterminate("ebpf_map_identity"))?;
            let named_pins = Self::pinned_map_identity(&canonical_pin_dir)
                .map_err(|_| state_indeterminate("ebpf_map_identity"))?;
            if named_pins != expected_pins {
                return Err(state_indeterminate("ebpf_map_identity"));
            }
            let local_ip = self.config_read(&ebpf)?;
            if local_ip == [0, 0, 0, 0] {
                // This is an incomplete provisioning record. Remove it only
                // while every named pin still identifies the map held by this
                // loader and both tc hooks are positively absent.
                let cleanup = Self::cleanup_pin_set_if_detached(
                    &canonical_pin_dir,
                    Some(&expected_pins),
                    ifindex,
                    tc_priority,
                    PinCleanupHookProof::RequireEmptySlots,
                );
                drop(ebpf);
                return match cleanup {
                    Ok(()) => Err(GtpuError::NotFound),
                    Err(error) => Err(error),
                };
            }
            self.require_canonical_pmtu_slot(&ebpf)?;
            let indexes = if matches!(
                schema_state,
                BearerSchemaState::SourcePortV4 | BearerSchemaState::PmtuV5
            ) {
                Self::recover_incomplete_pdp_commits(&mut ebpf, local_ip, ifindex)?;
                Self::pdp_host_indexes(&ebpf, local_ip, ifindex, true)?
            } else {
                let pre_v4_indexes = Self::pdp_host_indexes(&ebpf, local_ip, ifindex, false)?;
                Self::materialize_legacy_source_port_policies(&mut ebpf, &pre_v4_indexes)?;
                Self::recover_incomplete_pdp_commits(&mut ebpf, local_ip, ifindex)?;
                Self::pdp_host_indexes(&ebpf, local_ip, ifindex, true)?
            };
            let attached = self.attach_programs(
                &mut ebpf,
                interface,
                ifindex,
                &canonical_pin_dir,
                tc_priority,
                schema_state,
            )?;
            if schema_state != BearerSchemaState::PmtuV5 {
                if let Err(error) = Self::write_bearer_schema_marker(&mut ebpf) {
                    if attached.replaced_existing {
                        return Err(state_indeterminate("ebpf_schema_marker_commit"));
                    }
                    let rollback = detach_datapath_if_current(
                        attached.links,
                        &attached.identity,
                        ifindex,
                        tc_priority,
                    );
                    return Err(error_after_rollback(
                        error,
                        rollback,
                        false,
                        "ebpf_tc_attach_rollback",
                    ));
                }
            }
            let mut devices = match self.devices.lock() {
                Ok(devices) => devices,
                Err(_) => {
                    if attached.replaced_existing {
                        return Err(state_indeterminate("ebpf_device_commit"));
                    }
                    let rollback = detach_datapath_if_current(
                        attached.links,
                        &attached.identity,
                        ifindex,
                        tc_priority,
                    );
                    return Err(error_after_rollback(
                        GtpuError::io("ebpf_adopt", super::poisoned_lock()),
                        rollback,
                        false,
                        "ebpf_tc_attach_rollback",
                    ));
                }
            };
            devices.insert(
                ifindex,
                LoadedDevice {
                    ebpf,
                    marked_owner_by_teid: indexes.marked_owner_by_teid,
                    default_teid_by_ue: indexes.default_teid_by_ue,
                    links: attached.links,
                    pin_dir: canonical_pin_dir,
                    tc_priority,
                    datapath_identity: attached.identity,
                    _reconciler_ownership: reconciler_ownership,
                },
            );
            Ok(local_ip)
        }

        fn teardown_drained_v2(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            tc_priority: u16,
        ) -> Result<DrainedV2TeardownOutcome, GtpuError> {
            let parent = pin_dir.parent().ok_or_else(|| {
                GtpuError::invalid_config("ebpf.bpffs_pin_root", "pin directory must have a parent")
            })?;
            fs::create_dir_all(parent)
                .map_err(|error| GtpuError::io("ebpf_pin_root_create", error))?;
            let canonical_parent = fs::canonicalize(parent)
                .map_err(|error| GtpuError::io("ebpf_pin_root_canonicalize", error))?;
            let name = pin_dir.file_name().ok_or_else(|| {
                GtpuError::invalid_config(
                    "device.name",
                    "interface pin directory must have a final component",
                )
            })?;
            let canonical_pin_dir = canonical_parent.join(name);
            let _reconciler_ownership =
                Self::acquire_reconciler_ownership(&canonical_pin_dir, ifindex)?;

            match fs::symlink_metadata(&canonical_pin_dir) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return match classify_unproven_hook_absence(
                        unproven_legacy_v2_hook_occupant(
                            ifindex,
                            TcAttachType::Egress,
                            tc_priority,
                        ),
                        unproven_legacy_v2_hook_occupant(
                            ifindex,
                            TcAttachType::Ingress,
                            tc_priority,
                        ),
                    ) {
                        UnprovenHookAbsence::Absent => Ok(DrainedV2TeardownOutcome::AlreadyAbsent),
                        UnprovenHookAbsence::Occupied => Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::IdentityMismatch,
                        )),
                        UnprovenHookAbsence::Indeterminate => {
                            Ok(DrainedV2TeardownOutcome::Refused(
                                DrainedV2TeardownRefusal::IndeterminateState,
                            ))
                        }
                    };
                }
                Err(_) => {
                    return Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::IndeterminateState,
                    ));
                }
                Ok(metadata)
                    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() =>
                {
                    return Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::IdentityMismatch,
                    ));
                }
                Ok(_) => {}
            }

            let entries = match Self::legacy_v2_directory_entries(&canonical_pin_dir) {
                Ok(entries) => entries,
                Err(_) => {
                    return Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::IndeterminateState,
                    ));
                }
            };
            let allowed = LEGACY_V2_MAP_NAMES
                .into_iter()
                .chain([LEGACY_V2_TEARDOWN_PROOF_MAP])
                .collect::<HashSet<_>>();
            if entries
                .iter()
                .any(|entry| !allowed.contains(entry.as_str()))
            {
                return Ok(DrainedV2TeardownOutcome::Refused(
                    DrainedV2TeardownRefusal::IdentityMismatch,
                ));
            }

            let existing_proof = match Self::read_legacy_v2_teardown_proof(&canonical_pin_dir) {
                Ok(proof) => proof,
                Err(_) => {
                    return Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::IndeterminateState,
                    ));
                }
            };
            if entries.is_empty() && existing_proof.is_none() {
                match classify_unproven_hook_absence(
                    unproven_legacy_v2_hook_occupant(ifindex, TcAttachType::Egress, tc_priority),
                    unproven_legacy_v2_hook_occupant(ifindex, TcAttachType::Ingress, tc_priority),
                ) {
                    UnprovenHookAbsence::Absent => {}
                    UnprovenHookAbsence::Occupied => {
                        return Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::IdentityMismatch,
                        ));
                    }
                    UnprovenHookAbsence::Indeterminate => {
                        return Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::IndeterminateState,
                        ));
                    }
                }
                // With no proof, pins, or SDK-named program on either hook,
                // the directory is only cosmetic. An unlink failure cannot
                // turn authoritative datapath absence into retryable state.
                let _ = fs::remove_dir(&canonical_pin_dir);
                return Ok(DrainedV2TeardownOutcome::AlreadyAbsent);
            }

            let proof = if let Some(proof) = existing_proof {
                if proof.record.ifindex != ifindex || proof.record.tc_priority != tc_priority {
                    return Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::IdentityMismatch,
                    ));
                }
                proof
            } else {
                if entries.len() != LEGACY_V2_MAP_NAMES.len()
                    || LEGACY_V2_MAP_NAMES
                        .iter()
                        .any(|name| !entries.contains(*name))
                {
                    return Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::NotLegacyV2,
                    ));
                }
                let identity = match Self::legacy_v2_datapath_identity(&canonical_pin_dir) {
                    Ok(identity) => identity,
                    Err(LegacyV2IdentityError::Mismatch) => {
                        return Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::IdentityMismatch,
                        ));
                    }
                    Err(LegacyV2IdentityError::Indeterminate) => {
                        return Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::IndeterminateState,
                        ));
                    }
                };
                let uplink_observation = filter_observation(
                    ifindex,
                    TcAttachType::Egress,
                    tc_priority,
                    LegacyV2ProgramScan::AllowExact(PROG_UPLINK),
                );
                let downlink_observation = filter_observation(
                    ifindex,
                    TcAttachType::Ingress,
                    tc_priority,
                    LegacyV2ProgramScan::AllowExact(PROG_DOWNLINK),
                );
                let (uplink_program, downlink_program) =
                    match (uplink_observation, downlink_observation) {
                        (Ok(uplink), Ok(downlink))
                            if !uplink.unexpected_legacy_v2_program_seen
                                && !downlink.unexpected_legacy_v2_program_seen =>
                        {
                            let owner_identity = |owner: Option<FilterOwner>,
                                                  name: &str,
                                                  artifact: &LegacyV2ProgramIdentity|
                             -> Result<(u32, u64), LegacyV2IdentityError> {
                                match owner {
                                    None => Err(LegacyV2IdentityError::Mismatch),
                                    Some(owner) => match legacy_v2_artifact_owner_tag(
                                        &owner,
                                        name,
                                        artifact.tags,
                                        &artifact.map_ids,
                                    ) {
                                        Ok(Some(identity)) => Ok(identity),
                                        Ok(None) => Err(LegacyV2IdentityError::Mismatch),
                                        Err(_) => Err(LegacyV2IdentityError::Indeterminate),
                                    },
                                }
                            };
                            match (
                                owner_identity(uplink.owner, PROG_UPLINK, &identity.uplink),
                                owner_identity(downlink.owner, PROG_DOWNLINK, &identity.downlink),
                            ) {
                                (Ok(uplink), Ok(downlink)) => (uplink, downlink),
                                (Err(LegacyV2IdentityError::Mismatch), _)
                                | (_, Err(LegacyV2IdentityError::Mismatch)) => {
                                    return Ok(DrainedV2TeardownOutcome::Refused(
                                        DrainedV2TeardownRefusal::IdentityMismatch,
                                    ));
                                }
                                _ => {
                                    return Ok(DrainedV2TeardownOutcome::Refused(
                                        DrainedV2TeardownRefusal::IndeterminateState,
                                    ));
                                }
                            }
                        }
                        (Ok(_), Ok(_)) => {
                            return Ok(DrainedV2TeardownOutcome::Refused(
                                DrainedV2TeardownRefusal::IdentityMismatch,
                            ));
                        }
                        _ => {
                            return Ok(DrainedV2TeardownOutcome::Refused(
                                DrainedV2TeardownRefusal::IndeterminateState,
                            ));
                        }
                    };
                match Self::legacy_v2_surviving_maps_are_drained(&canonical_pin_dir) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::PopulatedState,
                        ));
                    }
                    Err(LegacyV2IdentityError::Mismatch) => {
                        return Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::IdentityMismatch,
                        ));
                    }
                    Err(LegacyV2IdentityError::Indeterminate) => {
                        return Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::IndeterminateState,
                        ));
                    }
                }
                let record = LegacyV2TeardownRecord::from_identity(
                    ifindex,
                    tc_priority,
                    &identity,
                    uplink_program,
                    downlink_program,
                );
                match Self::commit_legacy_v2_teardown_proof(&canonical_pin_dir, record) {
                    Ok(proof) => proof,
                    Err(LegacyV2ProofCommitError::BeforePublication) => {
                        return Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::IndeterminateState,
                        ));
                    }
                    Err(LegacyV2ProofCommitError::PublicationIndeterminate) => {
                        return Ok(DrainedV2TeardownOutcome::Partial(
                            DrainedV2TeardownProgress::Indeterminate,
                        ));
                    }
                }
            };

            let recorded_hook_states =
                || -> Result<(LegacyV2HookState, LegacyV2HookState), GtpuError> {
                    let uplink = filter_observation(
                        ifindex,
                        TcAttachType::Egress,
                        tc_priority,
                        LegacyV2ProgramScan::AllowExact(PROG_UPLINK),
                    )?;
                    let downlink = filter_observation(
                        ifindex,
                        TcAttachType::Ingress,
                        tc_priority,
                        LegacyV2ProgramScan::AllowExact(PROG_DOWNLINK),
                    )?;
                    if uplink.unexpected_legacy_v2_program_seen
                        || downlink.unexpected_legacy_v2_program_seen
                    {
                        return Err(GtpuError::AlreadyExists);
                    }
                    let state = |owner: Option<FilterOwner>,
                                 name: &str,
                                 program_id: u32,
                                 tag: u64,
                                 map_ids: &[u32]|
                     -> Result<LegacyV2HookState, GtpuError> {
                        match owner {
                            None => Ok(LegacyV2HookState::Absent),
                            Some(owner)
                                if owner_matches_legacy_v2_record(
                                    &owner, name, program_id, tag, map_ids,
                                )? =>
                            {
                                Ok(LegacyV2HookState::Exact)
                            }
                            Some(_) => Err(GtpuError::AlreadyExists),
                        }
                    };
                    Ok((
                        state(
                            uplink.owner,
                            PROG_UPLINK,
                            proof.record.uplink_program_id,
                            proof.record.uplink_program_tag,
                            &proof.record.uplink_map_ids(),
                        )?,
                        state(
                            downlink.owner,
                            PROG_DOWNLINK,
                            proof.record.downlink_program_id,
                            proof.record.downlink_program_tag,
                            &proof.record.downlink_map_ids(),
                        )?,
                    ))
                };

            let (mut uplink, mut downlink) = match recorded_hook_states() {
                Ok(states) => states,
                Err(_) => {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::Indeterminate,
                    ));
                }
            };

            let present_pin_count =
                match Self::legacy_v2_recorded_pin_count(&canonical_pin_dir, proof.record) {
                    Ok(count) => count,
                    Err(_) => {
                        return Ok(DrainedV2TeardownOutcome::Partial(
                            DrainedV2TeardownProgress::Indeterminate,
                        ));
                    }
                };
            match Self::legacy_v2_surviving_maps_are_drained(&canonical_pin_dir) {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::PopulatedStateObserved,
                    ));
                }
                Err(LegacyV2IdentityError::Mismatch | LegacyV2IdentityError::Indeterminate) => {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::Indeterminate,
                    ));
                }
            }
            if present_pin_count != LEGACY_V2_MAP_NAMES.len()
                && (uplink != LegacyV2HookState::Absent || downlink != LegacyV2HookState::Absent)
            {
                // Pin cleanup is legal only after both recorded hooks are
                // absent. A missing pin while either program can still run is
                // an indeterminate partial graph and is never detached.
                return Ok(DrainedV2TeardownOutcome::Partial(
                    DrainedV2TeardownProgress::Indeterminate,
                ));
            }

            let detach = |attach_type: TcAttachType| {
                SchedClassifierLink::attached(interface, attach_type, tc_priority, TC_HANDLE, None)
                    .map_err(|error| GtpuError::io("ebpf_legacy_v2_tc_detach", error))?
                    .detach()
                    .map_err(|error| program_error("ebpf_legacy_v2_tc_detach", &error))
            };
            if uplink == LegacyV2HookState::Exact {
                let detached = detach(TcAttachType::Egress);
                (uplink, downlink) = match recorded_hook_states() {
                    Ok(states) => states,
                    Err(_) => {
                        return Ok(DrainedV2TeardownOutcome::Partial(
                            DrainedV2TeardownProgress::Indeterminate,
                        ));
                    }
                };
                if detached.is_err() && uplink == LegacyV2HookState::Exact {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        if downlink == LegacyV2HookState::Absent {
                            DrainedV2TeardownProgress::OneHookDetached
                        } else {
                            DrainedV2TeardownProgress::ProofCommitted
                        },
                    ));
                }
                if uplink != LegacyV2HookState::Absent {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::Indeterminate,
                    ));
                }
            }
            if downlink == LegacyV2HookState::Exact {
                let detached = detach(TcAttachType::Ingress);
                (uplink, downlink) = match recorded_hook_states() {
                    Ok(states) => states,
                    Err(_) => {
                        return Ok(DrainedV2TeardownOutcome::Partial(
                            DrainedV2TeardownProgress::Indeterminate,
                        ));
                    }
                };
                if detached.is_err() && downlink == LegacyV2HookState::Exact {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::OneHookDetached,
                    ));
                }
                if downlink != LegacyV2HookState::Absent {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::Indeterminate,
                    ));
                }
            }
            if uplink != LegacyV2HookState::Absent || downlink != LegacyV2HookState::Absent {
                return Ok(DrainedV2TeardownOutcome::Partial(
                    DrainedV2TeardownProgress::Indeterminate,
                ));
            }

            let mut removed_pin = present_pin_count < LEGACY_V2_MAP_NAMES.len();
            for (index, name) in LEGACY_V2_MAP_NAMES.iter().enumerate() {
                match Self::legacy_v2_surviving_maps_are_drained(&canonical_pin_dir) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Ok(DrainedV2TeardownOutcome::Partial(
                            DrainedV2TeardownProgress::PopulatedStateObserved,
                        ));
                    }
                    Err(LegacyV2IdentityError::Mismatch | LegacyV2IdentityError::Indeterminate) => {
                        return Ok(DrainedV2TeardownOutcome::Partial(
                            DrainedV2TeardownProgress::Indeterminate,
                        ));
                    }
                }
                if !matches!(
                    recorded_hook_states(),
                    Ok((LegacyV2HookState::Absent, LegacyV2HookState::Absent))
                ) {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::Indeterminate,
                    ));
                }
                let path = canonical_pin_dir.join(name);
                match legacy_v2_path_is_present(&path, "ebpf_legacy_v2_pin_identity") {
                    Ok(false) => continue,
                    Ok(true) => {}
                    Err(_) => {
                        return Ok(DrainedV2TeardownOutcome::Partial(
                            DrainedV2TeardownProgress::Indeterminate,
                        ));
                    }
                }
                let current_id = match MapInfo::from_pin(&path) {
                    Ok(info) => info.id(),
                    Err(_) => {
                        return Ok(DrainedV2TeardownOutcome::Partial(
                            DrainedV2TeardownProgress::Indeterminate,
                        ));
                    }
                };
                if current_id != proof.record.map_ids[index] {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::Indeterminate,
                    ));
                }
                if fs::remove_file(&path).is_err() {
                    match legacy_v2_path_is_present(&path, "ebpf_legacy_v2_pin_identity") {
                        Ok(false) => {}
                        Ok(true) | Err(_) => {
                            return Ok(DrainedV2TeardownOutcome::Partial(if removed_pin {
                                DrainedV2TeardownProgress::PinCleanupStarted
                            } else {
                                DrainedV2TeardownProgress::HooksDetached
                            }));
                        }
                    }
                }
                removed_pin = true;
            }

            let proof_path = canonical_pin_dir.join(LEGACY_V2_TEARDOWN_PROOF_MAP);
            let proof_only = match Self::legacy_v2_directory_entries(&canonical_pin_dir) {
                Ok(entries) => entries.len() == 1 && entries.contains(LEGACY_V2_TEARDOWN_PROOF_MAP),
                Err(_) => false,
            };
            if !proof_only {
                return Ok(DrainedV2TeardownOutcome::Partial(
                    DrainedV2TeardownProgress::Indeterminate,
                ));
            }
            let current_proof = match Self::read_legacy_v2_teardown_proof(&canonical_pin_dir) {
                Ok(Some(current)) if current == proof => current,
                _ => {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::Indeterminate,
                    ));
                }
            };
            if current_proof.map_id != proof.map_id {
                return Ok(DrainedV2TeardownOutcome::Partial(
                    DrainedV2TeardownProgress::Indeterminate,
                ));
            }
            if fs::remove_file(&proof_path).is_err() {
                match legacy_v2_path_is_present(&proof_path, "ebpf_legacy_v2_proof_remove") {
                    Ok(false) => {}
                    Ok(true) | Err(_) => {
                        return Ok(DrainedV2TeardownOutcome::Partial(
                            DrainedV2TeardownProgress::PinCleanupStarted,
                        ));
                    }
                }
            }
            match fs::remove_dir(&canonical_pin_dir) {
                Ok(()) => Ok(DrainedV2TeardownOutcome::Removed),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    Ok(DrainedV2TeardownOutcome::Removed)
                }
                // Both hooks, all recorded map pins, and the exact proof pin
                // have been authoritatively observed absent. The directory is
                // now cosmetic; reporting Partial here would discard the only
                // durable current-schema fence and let a retry misclassify the empty
                // directory as an unproven fresh state.
                Err(_) => Ok(DrainedV2TeardownOutcome::Removed),
            }
        }

        fn detach(
            &self,
            _interface: &str,
            ifindex: u32,
            _pin_dir: &Path,
            _tc_priority: u16,
        ) -> Result<(), GtpuError> {
            let held = {
                let mut devices = self
                    .devices
                    .lock()
                    .map_err(|_| GtpuError::io("ebpf_detach", super::poisoned_lock()))?;
                let loaded = devices.get(&ifindex).ok_or(GtpuError::NotFound)?;
                if !Self::loaded_datapath_is_current(ifindex, loaded) {
                    // Leave in-process ownership and pins intact. Dropping the
                    // backend is safe because its tc links are ManuallyDrop;
                    // a foreign/replacement occupant observed here is not
                    // detached.
                    return Err(GtpuError::AlreadyExists);
                }
                devices.remove(&ifindex)
            }
            .ok_or(GtpuError::NotFound)?;
            let LoadedDevice {
                ebpf,
                marked_owner_by_teid: _,
                default_teid_by_ue: _,
                links,
                pin_dir,
                tc_priority,
                datapath_identity,
                _reconciler_ownership: _ownership,
            } = held;
            detach_datapath_if_current(links, &datapath_identity, ifindex, tc_priority)?;
            // Both filters are now confirmed removed. Any pin mismatch or
            // unlink failure from this point is necessarily partial cleanup.
            Self::unpin_if_current(&ebpf, &pin_dir, &datapath_identity)
        }

        fn far_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; UPLINK_FAR_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_far_get", |device| {
                let map = device
                    .ebpf
                    .map(MAP_UPLINK_FAR)
                    .ok_or_else(|| GtpuError::io("ebpf_far_map", invalid_data("map missing")))?;
                let hash = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_far_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_far_get", error)),
                }
            })
        }

        fn far_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; UPLINK_FAR_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_far_insert", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_UPLINK_FAR)
                    .ok_or_else(|| GtpuError::io("ebpf_far_map", invalid_data("map missing")))?;
                let mut hash = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_far_map", error))?;
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("ebpf_far_insert", error))
            })
        }

        fn far_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_far_remove", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_UPLINK_FAR)
                    .ok_or_else(|| GtpuError::io("ebpf_far_map", invalid_data("map missing")))?;
                let mut hash = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_far_map", error))?;
                map_delete_result("ebpf_far_remove", hash.remove(&key))
            })
        }

        fn marked_far_get(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<Option<[u8; UPLINK_FAR_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_far_get", |device| {
                let map = device.ebpf.map(MAP_UPLINK_MARK_FAR).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_far_map", invalid_data("map missing"))
                })?;
                let hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_FAR_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_far_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_marked_far_get", error)),
                }
            })
        }

        fn marked_far_insert(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
            value: [u8; UPLINK_FAR_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_marked_far_insert", |device| {
                let map = device.ebpf.map_mut(MAP_UPLINK_MARK_FAR).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_far_map", invalid_data("map missing"))
                })?;
                let mut hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_FAR_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_far_map", error))?;
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("ebpf_marked_far_insert", error))
            })
        }

        fn marked_far_remove(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_far_remove", |device| {
                let map = device.ebpf.map_mut(MAP_UPLINK_MARK_FAR).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_far_map", invalid_data("map missing"))
                })?;
                let mut hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_FAR_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_far_map", error))?;
                map_delete_result("ebpf_marked_far_remove", hash.remove(&key))
            })
        }

        fn dscp_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; UPLINK_DSCP_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_dscp_get", |device| {
                let map = device
                    .ebpf
                    .map(MAP_UPLINK_DSCP)
                    .ok_or_else(|| GtpuError::io("ebpf_dscp_map", invalid_data("map missing")))?;
                let hash = BpfHashMap::<_, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_dscp_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_dscp_get", error)),
                }
            })
        }

        fn dscp_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; UPLINK_DSCP_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_dscp_insert", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_UPLINK_DSCP)
                    .ok_or_else(|| GtpuError::io("ebpf_dscp_map", invalid_data("map missing")))?;
                let mut hash = BpfHashMap::<_, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_dscp_map", error))?;
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("ebpf_dscp_insert", error))
            })
        }

        fn dscp_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_dscp_remove", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_UPLINK_DSCP)
                    .ok_or_else(|| GtpuError::io("ebpf_dscp_map", invalid_data("map missing")))?;
                let mut hash = BpfHashMap::<_, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_dscp_map", error))?;
                map_delete_result("ebpf_dscp_remove", hash.remove(&key))
            })
        }

        fn marked_dscp_get(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<Option<[u8; UPLINK_DSCP_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_dscp_get", |device| {
                let map = device.ebpf.map(MAP_UPLINK_MARK_DSCP).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_dscp_map", invalid_data("map missing"))
                })?;
                let hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_DSCP_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_dscp_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_marked_dscp_get", error)),
                }
            })
        }

        fn marked_dscp_insert(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
            value: [u8; UPLINK_DSCP_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_marked_dscp_insert", |device| {
                let map = device.ebpf.map_mut(MAP_UPLINK_MARK_DSCP).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_dscp_map", invalid_data("map missing"))
                })?;
                let mut hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_DSCP_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_dscp_map", error))?;
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("ebpf_marked_dscp_insert", error))
            })
        }

        fn marked_dscp_remove(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_dscp_remove", |device| {
                let map = device.ebpf.map_mut(MAP_UPLINK_MARK_DSCP).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_dscp_map", invalid_data("map missing"))
                })?;
                let mut hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_DSCP_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_dscp_map", error))?;
                map_delete_result("ebpf_marked_dscp_remove", hash.remove(&key))
            })
        }

        fn sport_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; UPLINK_SOURCE_PORT_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_sport_get", |device| {
                let map = device
                    .ebpf
                    .map(MAP_UPLINK_SOURCE_PORT)
                    .ok_or_else(|| GtpuError::io("ebpf_sport_map", invalid_data("map missing")))?;
                let hash =
                    BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_sport_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_sport_get", error)),
                }
            })
        }

        fn sport_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_sport_insert", |device| {
                let commit = PdpContextCommit::decode(&value);
                if key == [0; 4]
                    || !commit.is_valid()
                    || commit.downlink_binding().ingress_ifindex() != ifindex
                {
                    return Err(state_indeterminate("ebpf_sport_insert"));
                }
                if device
                    .default_teid_by_ue
                    .get(&key)
                    .is_some_and(|existing| *existing != commit.local_teid())
                    || device
                        .default_teid_by_ue
                        .iter()
                        .any(|(existing_ue, existing_teid)| {
                            *existing_teid == commit.local_teid() && *existing_ue != key
                        })
                    || device
                        .marked_owner_by_teid
                        .contains_key(&commit.local_teid())
                {
                    return Err(GtpuError::AlreadyExists);
                }
                let map = device
                    .ebpf
                    .map_mut(MAP_UPLINK_SOURCE_PORT)
                    .ok_or_else(|| GtpuError::io("ebpf_sport_map", invalid_data("map missing")))?;
                let mut hash =
                    BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_sport_map", error))?;
                match hash.get(&key, 0) {
                    Ok(existing) => {
                        let existing = PdpContextCommit::decode(&existing);
                        if !existing.is_valid() || existing.local_teid() != commit.local_teid() {
                            return Err(state_indeterminate("ebpf_sport_insert"));
                        }
                    }
                    Err(MapError::KeyNotFound) => {}
                    Err(error) => return Err(map_error("ebpf_sport_get", error)),
                }
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("ebpf_sport_insert", error))?;
                device.default_teid_by_ue.insert(key, commit.local_teid());
                Ok(())
            })
        }

        fn sport_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_sport_remove", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_UPLINK_SOURCE_PORT)
                    .ok_or_else(|| GtpuError::io("ebpf_sport_map", invalid_data("map missing")))?;
                let mut hash =
                    BpfHashMap::<_, [u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_sport_map", error))?;
                let encoded = match hash.get(&key, 0) {
                    Ok(value) => value,
                    Err(MapError::KeyNotFound) => return Ok(false),
                    Err(error) => return Err(map_error("ebpf_sport_get", error)),
                };
                let commit = PdpContextCommit::decode(&encoded);
                if !commit.is_valid()
                    || device.default_teid_by_ue.get(&key) != Some(&commit.local_teid())
                {
                    return Err(state_indeterminate("ebpf_sport_remove"));
                }
                hash.remove(&key)
                    .map_err(|error| map_error("ebpf_sport_remove", error))?;
                device.default_teid_by_ue.remove(&key);
                Ok(true)
            })
        }

        fn marked_sport_get(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<Option<[u8; UPLINK_SOURCE_PORT_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_sport_get", |device| {
                let map = device
                    .ebpf
                    .map(MAP_UPLINK_MARK_SOURCE_PORT)
                    .ok_or_else(|| {
                        GtpuError::io("ebpf_marked_sport_map", invalid_data("map missing"))
                    })?;
                let hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_sport_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_marked_sport_get", error)),
                }
            })
        }

        fn marked_sport_insert(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
            value: [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_marked_sport_insert", |device| {
                let selector = UplinkFarKey::decode(&key);
                let commit = PdpContextCommit::decode(&value);
                if selector.ue_ip == [0; 4]
                    || selector.bearer_mark == [0; 4]
                    || !commit.is_valid()
                    || commit.downlink_binding().ingress_ifindex() != ifindex
                {
                    return Err(state_indeterminate("ebpf_marked_sport_insert"));
                }
                if device
                    .marked_owner_by_teid
                    .get(&commit.local_teid())
                    .is_some_and(|existing| *existing != key)
                    || device
                        .default_teid_by_ue
                        .values()
                        .any(|existing| *existing == commit.local_teid())
                {
                    return Err(GtpuError::AlreadyExists);
                }
                let map = device
                    .ebpf
                    .map_mut(MAP_UPLINK_MARK_SOURCE_PORT)
                    .ok_or_else(|| {
                        GtpuError::io("ebpf_marked_sport_map", invalid_data("map missing"))
                    })?;
                let mut hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_sport_map", error))?;
                match hash.get(&key, 0) {
                    Ok(existing) => {
                        let existing = PdpContextCommit::decode(&existing);
                        if !existing.is_valid() || existing.local_teid() != commit.local_teid() {
                            return Err(state_indeterminate("ebpf_marked_sport_insert"));
                        }
                    }
                    Err(MapError::KeyNotFound) => {}
                    Err(error) => return Err(map_error("ebpf_marked_sport_get", error)),
                }
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("ebpf_marked_sport_insert", error))?;
                device.marked_owner_by_teid.insert(commit.local_teid(), key);
                Ok(())
            })
        }

        fn marked_sport_remove(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_sport_remove", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_UPLINK_MARK_SOURCE_PORT)
                    .ok_or_else(|| {
                        GtpuError::io("ebpf_marked_sport_map", invalid_data("map missing"))
                    })?;
                let mut hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_sport_map", error))?;
                let encoded = match hash.get(&key, 0) {
                    Ok(value) => value,
                    Err(MapError::KeyNotFound) => return Ok(false),
                    Err(error) => return Err(map_error("ebpf_marked_sport_get", error)),
                };
                let commit = PdpContextCommit::decode(&encoded);
                if !commit.is_valid()
                    || device.marked_owner_by_teid.get(&commit.local_teid()) != Some(&key)
                {
                    return Err(state_indeterminate("ebpf_marked_sport_remove"));
                }
                hash.remove(&key)
                    .map_err(|error| map_error("ebpf_marked_sport_remove", error))?;
                device.marked_owner_by_teid.remove(&commit.local_teid());
                Ok(true)
            })
        }

        fn pmtu_policy_get(&self, ifindex: u32) -> Result<[u8; UPLINK_PMTU_VALUE_LEN], GtpuError> {
            self.with_device(ifindex, "ebpf_pmtu_policy_get", |device| {
                let map = device
                    .ebpf
                    .map(MAP_UPLINK_PMTU)
                    .ok_or_else(|| GtpuError::io("ebpf_pmtu_map", invalid_data("map missing")))?;
                let array = Array::<_, [u8; UPLINK_PMTU_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_pmtu_map", error))?;
                array
                    .get(&0, 0)
                    .map_err(|error| map_error("ebpf_pmtu_policy_get", error))
            })
        }

        fn pmtu_policy_write(
            &self,
            ifindex: u32,
            value: [u8; UPLINK_PMTU_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_pmtu_policy_write", |device| {
                if matches!(
                    GtpuUplinkMtuPolicy::decode_map_value(&value),
                    UplinkMtuMapState::Corrupt
                ) {
                    // Only canonical policy bytes (or the all-zero unset
                    // state) may cross the userspace map boundary; a corrupt
                    // caller-supplied value is an invalid argument, not an
                    // indeterminate datapath state.
                    return Err(GtpuError::invalid_config(
                        "device.uplink_mtu_policy",
                        "non-canonical MTU policy bytes",
                    ));
                }
                let map = device
                    .ebpf
                    .map_mut(MAP_UPLINK_PMTU)
                    .ok_or_else(|| GtpuError::io("ebpf_pmtu_map", invalid_data("map missing")))?;
                let mut array = Array::<_, [u8; UPLINK_PMTU_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_pmtu_map", error))?;
                array
                    .set(0, value, 0)
                    .map_err(|error| map_error("ebpf_pmtu_policy_write", error))
            })
        }

        fn pdr_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; DOWNLINK_PDR_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_pdr_get", |device| {
                let map = device
                    .ebpf
                    .map(MAP_DOWNLINK_PDR)
                    .ok_or_else(|| GtpuError::io("ebpf_pdr_map", invalid_data("map missing")))?;
                let hash = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
                    .map_err(|error| map_error("ebpf_pdr_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_pdr_get", error)),
                }
            })
        }

        fn pdr_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; DOWNLINK_PDR_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_pdr_insert", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_DOWNLINK_PDR)
                    .ok_or_else(|| GtpuError::io("ebpf_pdr_map", invalid_data("map missing")))?;
                let mut hash =
                    BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_pdr_map", error))?;
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("ebpf_pdr_insert", error))
            })
        }

        fn pdr_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_pdr_remove", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_DOWNLINK_PDR)
                    .ok_or_else(|| GtpuError::io("ebpf_pdr_map", invalid_data("map missing")))?;
                let mut hash =
                    BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_pdr_map", error))?;
                map_delete_result("ebpf_pdr_remove", hash.remove(&key))
            })
        }

        fn marked_pdr_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_pdr_get", |device| {
                let map = device.ebpf.map(MAP_DOWNLINK_MARK_PDR).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_pdr_map", invalid_data("map missing"))
                })?;
                let hash =
                    BpfHashMap::<_, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_marked_pdr_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_marked_pdr_get", error)),
                }
            })
        }

        fn marked_pdr_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; MARKED_DOWNLINK_PDR_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_marked_pdr_insert", |device| {
                let map = device.ebpf.map_mut(MAP_DOWNLINK_MARK_PDR).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_pdr_map", invalid_data("map missing"))
                })?;
                let mut hash =
                    BpfHashMap::<_, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_marked_pdr_map", error))?;
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("ebpf_marked_pdr_insert", error))
            })
        }

        fn marked_pdr_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_pdr_remove", |device| {
                let map = device.ebpf.map_mut(MAP_DOWNLINK_MARK_PDR).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_pdr_map", invalid_data("map missing"))
                })?;
                let mut hash =
                    BpfHashMap::<_, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(map)
                        .map_err(|error| map_error("ebpf_marked_pdr_map", error))?;
                map_delete_result("ebpf_marked_pdr_remove", hash.remove(&key))
            })
        }

        fn downlink_binding_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_downlink_binding_get", |device| {
                let map = device
                    .ebpf
                    .map(MAP_DOWNLINK_ENDPOINT_BINDING)
                    .ok_or_else(|| {
                        GtpuError::io("ebpf_downlink_binding_map", invalid_data("map missing"))
                    })?;
                let hash =
                    BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(
                        map,
                    )
                    .map_err(|error| map_error("ebpf_downlink_binding_map", error))?;
                match hash.get(&key, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_downlink_binding_get", error)),
                }
            })
        }

        fn downlink_binding_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_downlink_binding_insert", |device| {
                let binding = DownlinkEndpointBinding::decode(&value);
                if !binding.is_valid() || binding.ingress_ifindex() != ifindex {
                    return Err(state_indeterminate("ebpf_downlink_binding_insert"));
                }
                let map = device
                    .ebpf
                    .map_mut(MAP_DOWNLINK_ENDPOINT_BINDING)
                    .ok_or_else(|| {
                        GtpuError::io("ebpf_downlink_binding_map", invalid_data("map missing"))
                    })?;
                let mut hash =
                    BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(
                        map,
                    )
                    .map_err(|error| map_error("ebpf_downlink_binding_map", error))?;
                hash.insert(key, value, 0)
                    .map_err(|error| map_error("ebpf_downlink_binding_insert", error))
            })
        }

        fn downlink_binding_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_downlink_binding_remove", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_DOWNLINK_ENDPOINT_BINDING)
                    .ok_or_else(|| {
                        GtpuError::io("ebpf_downlink_binding_map", invalid_data("map missing"))
                    })?;
                let mut hash =
                    BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>::try_from(
                        map,
                    )
                    .map_err(|error| map_error("ebpf_downlink_binding_map", error))?;
                map_delete_result("ebpf_downlink_binding_remove", hash.remove(&key))
            })
        }

        fn marked_owner_get(
            &self,
            ifindex: u32,
            selector: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<Option<[u8; MARKED_BEARER_OWNER_VALUE_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_owner_get", |device| {
                let map = device.ebpf.map(MAP_MARKED_BEARER_OWNER).ok_or_else(|| {
                    GtpuError::io("ebpf_marked_owner_map", invalid_data("map missing"))
                })?;
                let hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; MARKED_BEARER_OWNER_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_owner_map", error))?;
                match hash.get(&selector, 0) {
                    Ok(value) => Ok(Some(value)),
                    Err(MapError::KeyNotFound) => Ok(None),
                    Err(error) => Err(map_error("ebpf_marked_owner_get", error)),
                }
            })
        }

        fn marked_owner_insert(
            &self,
            ifindex: u32,
            selector: [u8; UPLINK_MARK_KEY_LEN],
            value: [u8; MARKED_BEARER_OWNER_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_marked_owner_insert", |device| {
                let key = UplinkFarKey::decode(&selector);
                let owner = MarkedBearerOwner::decode(&value);
                if key.ue_ip == [0; 4]
                    || key.bearer_mark == [0; 4]
                    || !owner.is_valid()
                    || owner.downlink_binding.ingress_ifindex() != ifindex
                {
                    return Err(state_indeterminate("ebpf_marked_owner_insert"));
                }
                if device
                    .marked_owner_by_teid
                    .get(&owner.local_teid)
                    .is_some_and(|existing| *existing != selector)
                    || device
                        .default_teid_by_ue
                        .values()
                        .any(|existing| *existing == owner.local_teid)
                {
                    return Err(GtpuError::AlreadyExists);
                }
                let map = device
                    .ebpf
                    .map_mut(MAP_MARKED_BEARER_OWNER)
                    .ok_or_else(|| {
                        GtpuError::io("ebpf_marked_owner_map", invalid_data("map missing"))
                    })?;
                let mut hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; MARKED_BEARER_OWNER_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_owner_map", error))?;
                match hash.get(&selector, 0) {
                    Ok(existing) => {
                        let existing = MarkedBearerOwner::decode(&existing);
                        if !existing.is_valid() || existing.local_teid != owner.local_teid {
                            return Err(state_indeterminate("ebpf_marked_owner_insert"));
                        }
                    }
                    Err(MapError::KeyNotFound) => {}
                    Err(error) => return Err(map_error("ebpf_marked_owner_get", error)),
                }
                hash.insert(selector, value, 0)
                    .map_err(|error| map_error("ebpf_marked_owner_insert", error))?;
                device
                    .marked_owner_by_teid
                    .insert(owner.local_teid, selector);
                Ok(())
            })
        }

        fn marked_owner_remove(
            &self,
            ifindex: u32,
            selector: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<bool, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_owner_remove", |device| {
                let map = device
                    .ebpf
                    .map_mut(MAP_MARKED_BEARER_OWNER)
                    .ok_or_else(|| {
                        GtpuError::io("ebpf_marked_owner_map", invalid_data("map missing"))
                    })?;
                let mut hash = BpfHashMap::<
                    _,
                    [u8; UPLINK_MARK_KEY_LEN],
                    [u8; MARKED_BEARER_OWNER_VALUE_LEN],
                >::try_from(map)
                .map_err(|error| map_error("ebpf_marked_owner_map", error))?;
                let encoded = match hash.get(&selector, 0) {
                    Ok(value) => value,
                    Err(MapError::KeyNotFound) => return Ok(false),
                    Err(error) => return Err(map_error("ebpf_marked_owner_get", error)),
                };
                let owner = MarkedBearerOwner::decode(&encoded);
                if !owner.is_valid()
                    || device.marked_owner_by_teid.get(&owner.local_teid) != Some(&selector)
                {
                    return Err(state_indeterminate("ebpf_marked_owner_remove"));
                }
                // Unlike an independently optional forwarding resource, the
                // owner was just read and its in-memory TEID reservation was
                // proven. ENOENT here is a concurrent/ambiguous mutation and
                // must remain an error rather than idempotent absence.
                hash.remove(&selector)
                    .map_err(|error| map_error("ebpf_marked_owner_remove", error))?;
                // The complete-graph commit record, not this compatibility
                // owner mirror, owns the TEID reservation. Its final removal
                // releases the index after every component has been deleted.
                Ok(true)
            })
        }

        fn marked_owner_for_teid(
            &self,
            ifindex: u32,
            local_teid: [u8; 4],
        ) -> Result<Option<[u8; UPLINK_MARK_KEY_LEN]>, GtpuError> {
            self.with_device(ifindex, "ebpf_marked_owner_for_teid", |device| {
                Ok(device.marked_owner_by_teid.get(&local_teid).copied())
            })
        }

        fn default_teid_for_ue(
            &self,
            ifindex: u32,
            ue_ip: [u8; 4],
        ) -> Result<Option<[u8; 4]>, GtpuError> {
            self.with_device(ifindex, "ebpf_default_teid_for_ue", |device| {
                Ok(device.default_teid_by_ue.get(&ue_ip).copied())
            })
        }

        fn default_ue_for_teid(
            &self,
            ifindex: u32,
            local_teid: [u8; 4],
        ) -> Result<Option<[u8; 4]>, GtpuError> {
            self.with_device(ifindex, "ebpf_default_ue_for_teid", |device| {
                Ok(device
                    .default_teid_by_ue
                    .iter()
                    .find_map(|(ue_ip, teid)| (*teid == local_teid).then_some(*ue_ip)))
            })
        }

        fn default_selector_insert(
            &self,
            ifindex: u32,
            ue_ip: [u8; 4],
            local_teid: [u8; 4],
        ) -> Result<(), GtpuError> {
            self.with_device(ifindex, "ebpf_default_selector_insert", |device| {
                if ue_ip == [0; 4] || local_teid == [0; 4] {
                    return Err(state_indeterminate("ebpf_default_selector_insert"));
                }
                if device
                    .default_teid_by_ue
                    .get(&ue_ip)
                    .is_some_and(|existing| *existing != local_teid)
                    || device
                        .default_teid_by_ue
                        .iter()
                        .any(|(existing_ue, existing_teid)| {
                            *existing_teid == local_teid && *existing_ue != ue_ip
                        })
                    || device.marked_owner_by_teid.contains_key(&local_teid)
                {
                    return Err(GtpuError::AlreadyExists);
                }
                device.default_teid_by_ue.insert(ue_ip, local_teid);
                Ok(())
            })
        }

        fn default_selector_remove(
            &self,
            ifindex: u32,
            ue_ip: [u8; 4],
            local_teid: [u8; 4],
        ) -> Result<bool, GtpuError> {
            self.with_device(
                ifindex,
                "ebpf_default_selector_remove",
                |device| match device.default_teid_by_ue.get(&ue_ip) {
                    None => Ok(false),
                    Some(existing) if *existing == local_teid => {
                        device.default_teid_by_ue.remove(&ue_ip);
                        Ok(true)
                    }
                    Some(_) => Err(state_indeterminate("ebpf_default_selector_remove")),
                },
            )
        }

        fn datapath_snapshot(&self, ifindex: u32) -> Result<EbpfGtpuDatapathSnapshot, GtpuError> {
            let devices = self
                .devices
                .lock()
                .map_err(|_| GtpuError::io("ebpf_datapath_snapshot", super::poisoned_lock()))?;
            let device = devices.get(&ifindex).ok_or(GtpuError::NotFound)?;
            let indeterminate = || GtpuError::StateIndeterminate {
                operation: "ebpf_datapath_snapshot",
            };
            if !Self::loaded_datapath_is_current(ifindex, device) {
                return Err(indeterminate());
            }

            let map = device.ebpf.map(MAP_COUNTERS).ok_or_else(indeterminate)?;
            let counters = PerCpuArray::<_, u64>::try_from(map).map_err(|_| {
                GtpuError::io(
                    "ebpf_datapath_counters",
                    invalid_data("counter map has an unexpected shape"),
                )
            })?;
            let aggregate = |index: u32| -> Result<u64, GtpuError> {
                let values = counters
                    .get(&index, 0)
                    .map_err(|error| map_error("ebpf_datapath_counters", error))?;
                Ok(values.iter().copied().fold(0_u64, u64::saturating_add))
            };
            let binding_map = device
                .ebpf
                .map(MAP_DOWNLINK_BINDING_COUNTERS)
                .ok_or_else(indeterminate)?;
            let binding_counters = PerCpuArray::<_, u64>::try_from(binding_map).map_err(|_| {
                GtpuError::io(
                    "ebpf_datapath_binding_counters",
                    invalid_data("binding counter map has an unexpected shape"),
                )
            })?;
            let aggregate_binding = |index: u32| -> Result<u64, GtpuError> {
                let values = binding_counters
                    .get(&index, 0)
                    .map_err(|error| map_error("ebpf_datapath_binding_counters", error))?;
                Ok(values.iter().copied().fold(0_u64, u64::saturating_add))
            };
            let pmtu_map = device
                .ebpf
                .map(MAP_UPLINK_PMTU_COUNTERS)
                .ok_or_else(indeterminate)?;
            let pmtu_counters = PerCpuArray::<_, u64>::try_from(pmtu_map).map_err(|_| {
                GtpuError::io(
                    "ebpf_datapath_pmtu_counters",
                    invalid_data("MTU-drop counter map has an unexpected shape"),
                )
            })?;
            let aggregate_pmtu = |index: u32| -> Result<u64, GtpuError> {
                let values = pmtu_counters
                    .get(&index, 0)
                    .map_err(|error| map_error("ebpf_datapath_pmtu_counters", error))?;
                Ok(values.iter().copied().fold(0_u64, u64::saturating_add))
            };
            let snapshot = EbpfGtpuDatapathSnapshot {
                uplink_program_id: device.datapath_identity.uplink.program_id,
                downlink_program_id: device.datapath_identity.downlink.program_id,
                counters_map_id: device.datapath_identity.pins.counters,
                downlink_binding_counters_map_id: device
                    .datapath_identity
                    .pins
                    .downlink_binding_counters,
                counters: EbpfGtpuDatapathCounters {
                    uplink_encapsulated: aggregate(COUNTER_UL_ENCAP)?,
                    uplink_far_misses: aggregate(COUNTER_UL_FAR_MISS)?,
                    downlink_decapsulated: aggregate(COUNTER_DL_DECAP)?,
                    downlink_unknown_teid: aggregate(COUNTER_DL_UNKNOWN_TEID)?,
                    downlink_malformed: aggregate(COUNTER_DL_MALFORMED)?,
                    downlink_destination_mismatches: aggregate(COUNTER_DL_DST_MISMATCH)?,
                    downlink_binding_invalid: aggregate_binding(COUNTER_DL_BINDING_INVALID)?,
                    downlink_binding_family_mismatches: aggregate_binding(
                        COUNTER_DL_BINDING_FAMILY_MISMATCH,
                    )?,
                    downlink_binding_peer_mismatches: aggregate_binding(
                        COUNTER_DL_BINDING_PEER_MISMATCH,
                    )?,
                    downlink_binding_local_mismatches: aggregate_binding(
                        COUNTER_DL_BINDING_LOCAL_MISMATCH,
                    )?,
                    downlink_binding_ingress_mismatches: aggregate_binding(
                        COUNTER_DL_BINDING_INGRESS_MISMATCH,
                    )?,
                    downlink_binding_source_port_mismatches: aggregate_binding(
                        COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH,
                    )?,
                    uplink_mtu_rejected: aggregate_pmtu(COUNTER_UL_MTU_REJECT)?,
                    uplink_mtu_policy_corrupt: aggregate_pmtu(COUNTER_UL_PMTU_CORRUPT)?,
                },
            };
            // Repeat the complete proof after the reads so any hook or pin
            // replacement still visible at the second check fails closed. An
            // external-root replace-and-restore between checks is outside the
            // required exclusive-writer contract and is not distinguishable.
            if !Self::loaded_datapath_is_current(ifindex, device) {
                return Err(indeterminate());
            }
            Ok(snapshot)
        }

        fn probe_environment(&self) -> EbpfEnvironment {
            EbpfEnvironment {
                platform_supported: true,
                bpffs_present: Path::new("/sys/fs/bpf").is_dir(),
                btf_present: Path::new("/sys/kernel/btf/vmlinux").exists(),
                net_admin_capable: effective_capability(CAP_NET_ADMIN).unwrap_or(false),
                bpf_capable: effective_capability(CAP_BPF).unwrap_or(false)
                    || effective_capability(CAP_SYS_ADMIN).unwrap_or(false),
            }
        }

        fn dscp_datapath_usable(&self, ifindex: u32) -> bool {
            let Ok(devices) = self.devices.lock() else {
                return false;
            };
            devices
                .get(&ifindex)
                .is_some_and(|device| Self::loaded_datapath_is_current(ifindex, device))
        }

        fn source_port_datapath_usable(&self, ifindex: u32) -> bool {
            let Ok(devices) = self.devices.lock() else {
                return false;
            };
            devices
                .get(&ifindex)
                .is_some_and(|device| Self::loaded_datapath_is_current(ifindex, device))
        }

        fn pmtu_datapath_usable(&self, ifindex: u32) -> bool {
            let Ok(devices) = self.devices.lock() else {
                return false;
            };
            devices
                .get(&ifindex)
                .is_some_and(|device| Self::loaded_datapath_is_current(ifindex, device))
        }

        fn bearer_mark_datapath_usable(&self, ifindex: u32) -> bool {
            let Ok(devices) = self.devices.lock() else {
                return false;
            };
            devices
                .get(&ifindex)
                .is_some_and(|device| Self::loaded_datapath_is_current(ifindex, device))
        }

        fn downlink_endpoint_binding_datapath_usable(&self, ifindex: u32) -> bool {
            let Ok(devices) = self.devices.lock() else {
                return false;
            };
            devices
                .get(&ifindex)
                .is_some_and(|device| Self::loaded_datapath_is_current(ifindex, device))
        }

        fn pdp_readback_datapath_usable(&self, ifindex: u32) -> bool {
            let Ok(devices) = self.devices.lock() else {
                return false;
            };
            devices
                .get(&ifindex)
                .is_some_and(|device| Self::loaded_datapath_is_current(ifindex, device))
        }

        fn pdp_cleanup_datapath_usable(&self, ifindex: u32) -> bool {
            let Ok(devices) = self.devices.lock() else {
                return false;
            };
            devices
                .get(&ifindex)
                .is_some_and(|device| Self::loaded_datapath_cleanup_safe(ifindex, device))
        }
    }

    fn effective_capability(capability: u32) -> Result<bool, GtpuError> {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|error| GtpuError::io("capability_probe", error))?;
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:") {
                let caps = u64::from_str_radix(hex.trim(), 16).map_err(|_| {
                    GtpuError::io("capability_probe", invalid_data("invalid CapEff"))
                })?;
                let mask = 1_u64.checked_shl(capability).ok_or_else(|| {
                    GtpuError::io("capability_probe", invalid_data("invalid capability index"))
                })?;
                return Ok((caps & mask) != 0);
            }
        }
        Ok(false)
    }

    /// Map aya program errors to redaction-safe I/O errors. Only the
    /// operation label and any raw OS error survive; aya's error strings
    /// (which can embed interface names and paths) are dropped.
    fn program_error(operation: &'static str, error: &ProgramError) -> GtpuError {
        match error {
            ProgramError::AlreadyAttached => GtpuError::AlreadyExists,
            ProgramError::SyscallError(error) => GtpuError::io(
                operation,
                io::Error::new(error.io_error.kind(), "ebpf syscall failed"),
            ),
            ProgramError::TcError(error) => tc_error(operation, error),
            _ => GtpuError::io(operation, invalid_data("ebpf program operation failed")),
        }
    }

    /// Map aya map errors to redaction-safe I/O errors.
    fn map_error(operation: &'static str, error: MapError) -> GtpuError {
        match error {
            MapError::KeyNotFound => GtpuError::NotFound,
            _ => GtpuError::io(operation, io::Error::other("ebpf map operation failed")),
        }
    }

    /// Classify an Aya hash-map delete without confusing Linux `ENOENT` with
    /// an I/O failure. Aya's lookup API emits `KeyNotFound`, but its delete
    /// API exposes the same absent-key condition as a syscall error.
    fn map_delete_result(
        operation: &'static str,
        result: Result<(), MapError>,
    ) -> Result<bool, GtpuError> {
        match result {
            Ok(()) => Ok(true),
            Err(MapError::KeyNotFound) => Ok(false),
            Err(MapError::SyscallError(error))
                if error.io_error.kind() == io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            Err(error) => Err(map_error(operation, error)),
        }
    }

    fn invalid_data(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    #[cfg(test)]
    mod race_tests {
        use super::*;

        fn instruction(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> bpf_insn {
            bpf_insn {
                code,
                _bitfield_align_1: [],
                _bitfield_1: bpf_insn::new_bitfield_1(dst, src),
                off,
                imm,
            }
        }

        #[test]
        fn legacy_v2_program_tag_hashes_match_kernel_known_answers() {
            // Standard SHA-1/SHA-256 "abc" vectors, truncated to the same
            // first eight bytes exposed by BPF_OBJ_GET_INFO_BY_FD.
            assert_eq!(
                legacy_v2_tags_from_normalized(b"abc"),
                LegacyV2ProgramTags {
                    sha1: 0xa999_3e36_4706_816a,
                    sha256: 0xba78_16bf_8f01_cfea,
                }
            );
        }

        #[test]
        fn legacy_v2_program_tag_normalization_zeros_both_map_load_immediates() {
            let instructions = [
                instruction(0xb7, 1, 0, -2, 0x0102_0304),
                instruction(
                    (BPF_LD | BPF_IMM | BPF_DW) as u8,
                    2,
                    BPF_PSEUDO_MAP_FD as u8,
                    0,
                    0x1122_3344,
                ),
                instruction(0, 0, 0, 0, 0x5566_7788),
                instruction(0x95, 0, 0, 0, 0),
            ];
            let normalized = legacy_v2_normalized_program_bytes(&instructions);
            assert_eq!(normalized.len(), instructions.len() * 8);
            assert_eq!(&normalized[4..8], &0x0102_0304_i32.to_ne_bytes());
            assert_eq!(&normalized[12..16], &[0; 4]);
            assert_eq!(&normalized[20..24], &[0; 4]);
            assert_eq!(&normalized[28..32], &[0; 4]);
        }

        #[test]
        fn legacy_v2_frozen_artifact_exposes_only_derived_tags() {
            let (uplink, downlink) = AyaGtpuRuntime::legacy_v2_artifact_tags()
                .expect("the committed artifact must parse");
            assert_ne!(uplink.sha1, 0);
            assert_ne!(uplink.sha256, 0);
            assert_ne!(downlink.sha1, 0);
            assert_ne!(downlink.sha256, 0);
        }

        #[test]
        fn unproven_hook_observation_errors_are_indeterminate() {
            assert_eq!(
                classify_unproven_hook_absence::<(), ()>(Ok(None), Ok(None)),
                UnprovenHookAbsence::Absent
            );
            assert_eq!(
                classify_unproven_hook_absence::<(), ()>(Ok(Some(())), Ok(None)),
                UnprovenHookAbsence::Occupied
            );
            assert_eq!(
                classify_unproven_hook_absence::<(), ()>(Err(()), Ok(None)),
                UnprovenHookAbsence::Indeterminate
            );
            assert_eq!(
                classify_unproven_hook_absence::<(), ()>(Ok(None), Err(())),
                UnprovenHookAbsence::Indeterminate
            );
            assert_eq!(
                classify_unproven_hook_absence::<(), ()>(Err(()), Err(())),
                UnprovenHookAbsence::Indeterminate
            );
            assert_eq!(
                classify_unproven_hook_absence::<(), ()>(Err(()), Ok(Some(()))),
                UnprovenHookAbsence::Indeterminate
            );
        }

        #[test]
        fn metadata_errors_are_not_absence() {
            assert!(classify_path_metadata(Ok(()), "test_path").unwrap());
            assert!(!classify_path_metadata::<()>(
                Err(io::Error::from(io::ErrorKind::NotFound)),
                "test_path",
            )
            .unwrap());
            assert!(classify_path_metadata::<()>(
                Err(io::Error::from(io::ErrorKind::PermissionDenied)),
                "test_path",
            )
            .is_err());
        }

        #[test]
        fn corrupt_v2_marker_dominates_forwarding_population() {
            let mut exact = LegacyV2FarObservation::default();
            exact.observe(
                UPLINK_DSCP_SCHEMA_MARKER_KEY,
                UPLINK_BEARER_SCHEMA_MARKER_VALUE,
            );
            assert_eq!(exact.finish(), Ok(true));

            let data_key = [10, 45, 0, 2];
            assert_ne!(data_key, UPLINK_DSCP_SCHEMA_MARKER_KEY);
            let mut populated = LegacyV2FarObservation::default();
            populated.observe(data_key, [7; UPLINK_FAR_VALUE_LEN]);
            populated.observe(
                UPLINK_DSCP_SCHEMA_MARKER_KEY,
                UPLINK_BEARER_SCHEMA_MARKER_VALUE,
            );
            assert_eq!(populated.finish(), Ok(false));

            let mut wrong_identity = LegacyV2FarObservation::default();
            wrong_identity.observe(data_key, [7; UPLINK_FAR_VALUE_LEN]);
            wrong_identity.observe(
                UPLINK_DSCP_SCHEMA_MARKER_KEY,
                UPLINK_ENDPOINT_SCHEMA_MARKER_VALUE,
            );
            assert_eq!(
                wrong_identity.finish(),
                Err(LegacyV2IdentityError::Mismatch)
            );
            assert_eq!(
                LegacyV2FarObservation::default().finish(),
                Err(LegacyV2IdentityError::Indeterminate)
            );

            assert_eq!(validate_legacy_v2_config_identity([192, 0, 2, 1]), Ok(()));
            assert_eq!(
                validate_legacy_v2_config_identity([0; 4]),
                Err(LegacyV2IdentityError::Mismatch)
            );
        }

        #[test]
        fn dangling_inner_map_and_proof_paths_are_not_absence() {
            use std::os::unix::fs::symlink;

            let pin_dir = std::env::temp_dir()
                .join(format!("opc-gtpu-v2-dangling-pins-{}", std::process::id()));
            let _ = fs::remove_dir_all(&pin_dir);
            fs::create_dir_all(&pin_dir).expect("create dangling-pin directory");

            let missing = pin_dir.join("missing-target");
            let map_path = pin_dir.join(MAP_UPLINK_FAR);
            symlink(&missing, &map_path).expect("create dangling inner-map symlink");
            assert!(legacy_v2_path_is_present(&map_path, "test_path").unwrap());
            let record = LegacyV2TeardownRecord {
                ifindex: 7,
                tc_priority: 50,
                uplink_program_id: 1,
                downlink_program_id: 2,
                uplink_program_tag: 3,
                downlink_program_tag: 4,
                map_ids: [5; LEGACY_V2_MAP_NAMES.len()],
                proof_map_id: 6,
            };
            assert!(AyaGtpuRuntime::legacy_v2_recorded_pin_count(&pin_dir, record).is_err());
            fs::remove_file(&map_path).expect("remove dangling inner-map symlink");

            let proof_path = pin_dir.join(LEGACY_V2_TEARDOWN_PROOF_MAP);
            symlink(&missing, &proof_path).expect("create dangling proof symlink");
            assert!(legacy_v2_path_is_present(&proof_path, "test_path").unwrap());
            assert!(AyaGtpuRuntime::read_legacy_v2_teardown_proof(&pin_dir).is_err());

            fs::remove_dir_all(&pin_dir).expect("remove dangling-pin directory");
        }

        #[test]
        fn pending_v2_teardown_proof_fences_normal_schema_preflight() {
            let pin_dir = std::env::temp_dir().join(format!(
                "opc-gtpu-v2-proof-preflight-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&pin_dir);
            fs::create_dir_all(&pin_dir).expect("create proof-only pin directory");
            fs::write(pin_dir.join(LEGACY_V2_TEARDOWN_PROOF_MAP), b"proof")
                .expect("create pending proof marker");

            assert!(matches!(
                AyaGtpuRuntime::bearer_schema_preflight(&pin_dir),
                Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_legacy_v2_teardown_pending"
                })
            ));
            fs::remove_dir_all(&pin_dir).expect("remove proof-only pin directory");
        }

        #[test]
        fn non_directory_and_symlink_pin_names_are_never_absence() {
            let root = std::env::temp_dir()
                .join(format!("opc-gtpu-v2-path-identity-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("create path identity root");
            let pin_dir = root.join("s2bu");
            fs::write(&pin_dir, b"foreign").expect("create foreign non-directory occupant");

            let runtime = AyaGtpuRuntime::new();
            assert_eq!(
                runtime
                    .teardown_drained_v2("s2bu", 7, &pin_dir, 50)
                    .expect("classify non-directory occupant"),
                DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IdentityMismatch)
            );
            assert_eq!(
                fs::read(&pin_dir).expect("foreign occupant must survive"),
                b"foreign"
            );

            fs::remove_file(&pin_dir).expect("remove foreign file");
            let target = root.join("target");
            fs::create_dir(&target).expect("create symlink target");
            std::os::unix::fs::symlink(&target, &pin_dir).expect("create foreign symlink");
            assert_eq!(
                runtime
                    .teardown_drained_v2("s2bu", 7, &pin_dir, 50)
                    .expect("classify symlink occupant"),
                DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IdentityMismatch)
            );
            assert!(pin_dir.symlink_metadata().is_ok());
            assert!(target.is_dir());
            fs::remove_file(&pin_dir).expect("remove foreign symlink");
            fs::remove_dir_all(&root).expect("remove path identity root");
        }

        #[test]
        #[ignore = "requires CAP_BPF and writable bpffs"]
        fn program_tag_candidates_match_the_running_kernel() {
            if std::env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
                return;
            }
            let pin_dir = std::path::PathBuf::from(format!(
                "/sys/fs/bpf/opc-gtpu-tag-proof-{}",
                std::process::id()
            ));
            fs::create_dir_all(&pin_dir).expect("create live tag proof pin directory");
            let object = AyaObject::parse(DATAPATH_OBJECT).expect("parse current datapath object");
            let (uplink_tags, downlink_tags) = AyaGtpuRuntime::object_program_tags(object)
                .expect("derive current object tag candidates");
            let mut ebpf = EbpfLoader::new()
                .default_map_pin_directory(&pin_dir)
                .load(DATAPATH_OBJECT)
                .expect("load current datapath object for live tag proof");
            for (name, expected) in [(PROG_UPLINK, uplink_tags), (PROG_DOWNLINK, downlink_tags)] {
                let program: &mut SchedClassifier = ebpf
                    .program_mut(name)
                    .expect("current tc program")
                    .try_into()
                    .expect("current program is a tc classifier");
                program.load().expect("load current tc program");
                let live_tag = program.info().expect("read live program info").tag();
                assert!(
                    expected.contains(live_tag),
                    "running-kernel tag must be one exact normalized candidate"
                );
            }
            drop(ebpf);
            fs::remove_dir_all(&pin_dir).expect("remove live tag proof pins");
        }

        #[test]
        fn legacy_v2_teardown_record_rejects_tamper_and_inconsistent_hook_identity() {
            let identity = LegacyV2DatapathIdentity {
                uplink: LegacyV2ProgramIdentity {
                    tags: LegacyV2ProgramTags { sha1: 1, sha256: 2 },
                    map_ids: vec![1, 2, 3, 4, 7, 8, 9],
                },
                downlink: LegacyV2ProgramIdentity {
                    tags: LegacyV2ProgramTags { sha1: 3, sha256: 4 },
                    map_ids: vec![5, 6, 7, 8],
                },
                map_ids: [1, 2, 3, 4, 5, 6, 7, 8, 9],
            };
            let unbound =
                LegacyV2TeardownRecord::from_identity(7, 50, &identity, (101, 1), (102, 3));
            assert_eq!(LegacyV2TeardownRecord::decode(&unbound.encode()), None);
            let record = unbound.bind_to_proof_map(301).unwrap();
            let encoded = record.encode();
            assert_eq!(LegacyV2TeardownRecord::decode(&encoded), Some(record));

            let mut tampered = encoded;
            tampered[40] ^= 1;
            assert_eq!(LegacyV2TeardownRecord::decode(&tampered), None);

            let mut inconsistent = record;
            inconsistent.uplink_program_tag = 0;
            assert_eq!(LegacyV2TeardownRecord::decode(&inconsistent.encode()), None);

            let mut absent_hook = record;
            absent_hook.downlink_program_id = 0;
            absent_hook.downlink_program_tag = 0;
            assert_eq!(LegacyV2TeardownRecord::decode(&absent_hook.encode()), None);

            assert!(legacy_v2_proof_map_abi_is_exact(
                bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                4,
                LEGACY_V2_TEARDOWN_PROOF_LEN as u32,
                1,
                0,
            ));
            for abi in [
                (
                    bpf_map_type::BPF_MAP_TYPE_HASH as u32,
                    4,
                    LEGACY_V2_TEARDOWN_PROOF_LEN as u32,
                    1,
                    0,
                ),
                (
                    bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                    8,
                    LEGACY_V2_TEARDOWN_PROOF_LEN as u32,
                    1,
                    0,
                ),
                (
                    bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                    4,
                    LEGACY_V2_TEARDOWN_PROOF_LEN as u32 + 1,
                    1,
                    0,
                ),
                (
                    bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                    4,
                    LEGACY_V2_TEARDOWN_PROOF_LEN as u32,
                    2,
                    0,
                ),
                (
                    bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
                    4,
                    LEGACY_V2_TEARDOWN_PROOF_LEN as u32,
                    1,
                    1,
                ),
            ] {
                assert!(!legacy_v2_proof_map_abi_is_exact(
                    abi.0, abi.1, abi.2, abi.3, abi.4,
                ));
            }
            assert!(legacy_v2_proof_record_is_authoritative(
                record,
                301,
                identity.uplink.tags,
                identity.downlink.tags,
            ));
            assert!(!legacy_v2_proof_record_is_authoritative(
                record,
                302,
                identity.uplink.tags,
                identity.downlink.tags,
            ));
            assert!(!legacy_v2_proof_record_is_authoritative(
                record,
                301,
                LegacyV2ProgramTags {
                    sha1: 999,
                    sha256: 1_000,
                },
                identity.downlink.tags,
            ));
            assert!(!legacy_v2_proof_record_is_authoritative(
                record,
                301,
                identity.uplink.tags,
                LegacyV2ProgramTags {
                    sha1: 999,
                    sha256: 1_000,
                },
            ));
        }

        #[test]
        fn map_delete_treats_aya_enoent_as_an_idempotent_absence() {
            assert!(!map_delete_result("delete", Err(MapError::KeyNotFound)).unwrap());
            let absent = MapError::SyscallError(aya::sys::SyscallError {
                call: "bpf_map_delete_elem",
                io_error: io::Error::from(io::ErrorKind::NotFound),
            });
            assert!(!map_delete_result("delete", Err(absent)).unwrap());

            let denied = MapError::SyscallError(aya::sys::SyscallError {
                call: "bpf_map_delete_elem",
                io_error: io::Error::from(io::ErrorKind::PermissionDenied),
            });
            assert!(matches!(
                map_delete_result("delete", Err(denied)).unwrap_err(),
                GtpuError::Io {
                    operation: "delete",
                    kind: io::ErrorKind::Other,
                    ..
                }
            ));
        }

        fn hook(
            name: &'static str,
            attach_type: TcAttachType,
            program_id: u32,
        ) -> ProgramHook<'static> {
            ProgramHook {
                name,
                attach_type,
                program_id,
            }
        }

        #[test]
        fn failed_attach_ack_is_reconciled_from_each_exact_live_hook() {
            for hook in [
                hook(PROG_UPLINK, TcAttachType::Egress, 71),
                hook(PROG_DOWNLINK, TcAttachType::Ingress, 72),
            ] {
                let exact = Ok(Some(FilterOwner {
                    name: hook.name.into(),
                    program_id: Some(hook.program_id),
                }));
                assert_eq!(
                    classify_failed_attach_readback(SlotDisposition::Empty, hook, &exact),
                    FailedAttachReadback::AdoptExact
                );
                assert_eq!(
                    classify_failed_attach_readback(
                        SlotDisposition::ReplaceExact {
                            current_program_id: hook.program_id.saturating_sub(1),
                        },
                        hook,
                        &exact,
                    ),
                    FailedAttachReadback::AdoptExact
                );
            }
        }

        #[test]
        fn failed_atomic_replace_distinguishes_the_original_from_unknown_state() {
            let hook = hook(PROG_UPLINK, TcAttachType::Egress, 71);
            let slot = SlotDisposition::ReplaceExact {
                current_program_id: 70,
            };
            let original = Ok(Some(FilterOwner {
                name: hook.name.into(),
                program_id: Some(70),
            }));
            assert_eq!(
                classify_failed_attach_readback(slot, hook, &original),
                FailedAttachReadback::ProvenOriginal
            );

            for owner in [
                Ok(None),
                Ok(Some(FilterOwner {
                    name: hook.name.into(),
                    program_id: Some(69),
                })),
                Ok(Some(FilterOwner {
                    name: "external".into(),
                    program_id: Some(70),
                })),
            ] {
                assert_eq!(
                    classify_failed_attach_readback(slot, hook, &owner),
                    FailedAttachReadback::Indeterminate
                );
            }
        }

        #[test]
        fn failed_attach_is_ordinary_only_when_an_originally_empty_slot_is_proven_empty() {
            let hook = hook(PROG_UPLINK, TcAttachType::Egress, 71);
            let empty = Ok(None);
            assert_eq!(
                classify_failed_attach_readback(SlotDisposition::Empty, hook, &empty),
                FailedAttachReadback::ProvenAbsent
            );
            assert_eq!(
                classify_failed_attach_readback(
                    SlotDisposition::ReplaceExact {
                        current_program_id: 70,
                    },
                    hook,
                    &empty,
                ),
                FailedAttachReadback::Indeterminate
            );
            let foreign = Ok(Some(FilterOwner {
                name: "external".into(),
                program_id: Some(99),
            }));
            assert_eq!(
                classify_failed_attach_readback(SlotDisposition::Empty, hook, &foreign),
                FailedAttachReadback::Indeterminate
            );
            let unreadable = Err(GtpuError::io(
                "ebpf_tc_filter_dump",
                io::Error::other("injected"),
            ));
            assert_eq!(
                classify_failed_attach_readback(SlotDisposition::Empty, hook, &unreadable),
                FailedAttachReadback::Indeterminate
            );
        }

        #[test]
        fn mutation_ack_loss_and_failed_rollbacks_are_indeterminate() {
            assert!(matches!(
                mutation_or_indeterminate::<(), _>(Err(()), "ebpf_tc_replace"),
                Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_tc_replace"
                })
            ));
            for source in ["second_hook", "schema_marker", "devices_lock"] {
                let error = error_after_rollback(
                    GtpuError::io(source, io::Error::other("injected source")),
                    Err(GtpuError::io(
                        "ebpf_tc_attach_rollback",
                        io::Error::other("injected rollback"),
                    )),
                    false,
                    "ebpf_tc_attach_rollback",
                );
                assert!(matches!(
                    error,
                    GtpuError::StateIndeterminate {
                        operation: "ebpf_tc_attach_rollback"
                    }
                ));
            }
            let source = error_after_rollback(
                GtpuError::AlreadyExists,
                Ok(()),
                false,
                "ebpf_tc_attach_rollback",
            );
            assert!(matches!(source, GtpuError::AlreadyExists));
            let replaced_source = error_after_rollback(
                GtpuError::AlreadyExists,
                Ok(()),
                true,
                "ebpf_tc_attach_rollback",
            );
            assert!(matches!(
                replaced_source,
                GtpuError::StateIndeterminate {
                    operation: "ebpf_tc_attach_rollback"
                }
            ));
        }

        #[test]
        fn indeterminate_or_preexisting_state_blocks_fresh_pin_cleanup() {
            assert!(fresh_pin_cleanup_allowed(false, &GtpuError::AlreadyExists));
            assert!(!fresh_pin_cleanup_allowed(true, &GtpuError::AlreadyExists));
            assert!(!fresh_pin_cleanup_allowed(
                false,
                &state_indeterminate("ebpf_tc_attach")
            ));
        }

        #[test]
        fn detach_failure_classification_preserves_only_pre_first_hook_conflicts() {
            assert!(matches!(
                classify_detach_failure(GtpuError::AlreadyExists, false),
                GtpuError::AlreadyExists
            ));
            assert!(matches!(
                classify_detach_failure(
                    GtpuError::io("ebpf_tc_detach", io::Error::other("injected")),
                    false,
                ),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_tc_detach"
                }
            ));
            assert!(matches!(
                classify_detach_failure(GtpuError::AlreadyExists, true),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_tc_detach"
                }
            ));
        }

        #[test]
        fn fresh_cleanup_rejects_swapped_named_pin_paths() {
            let expected = PinnedMapIdentity {
                uplink_far: 1,
                uplink_mark_far: 2,
                uplink_dscp: 3,
                uplink_mark_dscp: 4,
                uplink_source_port: 12,
                uplink_mark_source_port: 13,
                uplink_pmtu: 14,
                uplink_pmtu_counters: 15,
                downlink_pdr: 5,
                downlink_mark_pdr: 6,
                downlink_binding: 7,
                marked_owner: 8,
                counters: 9,
                downlink_binding_counters: 10,
                config: 11,
            };
            let swapped = PinnedMapIdentity {
                uplink_far: expected.uplink_dscp,
                uplink_dscp: expected.uplink_far,
                ..expected.clone()
            };

            assert_ne!(swapped, expected);
            assert!(pin_cleanup_preflight_matches(
                Some(&expected),
                Some(&expected),
                true,
            ));
            assert!(!pin_cleanup_preflight_matches(
                Some(&expected),
                Some(&swapped),
                true,
            ));
            assert!(!pin_cleanup_preflight_matches(
                Some(&expected),
                Some(&expected),
                false,
            ));
            assert!(pin_cleanup_preflight_matches(None, None, true));
            assert!(!pin_cleanup_preflight_matches(None, None, false));
        }

        const TEST_DUMP_SEQUENCE: u32 = 37;
        const TEST_DUMP_PORT_ID: u32 = 91;
        const TEST_DUMP_IFINDEX: i32 = 7;
        const TEST_DUMP_PARENT: u32 = sys::TC_H_CLSACT_INGRESS;

        fn dump_message(
            message_type: u16,
            flags: u16,
            sequence: u32,
            port_id: u32,
            body: &[u8],
        ) -> Vec<u8> {
            const NL_HDR: usize = 16;
            let length = NL_HDR + body.len();
            let aligned = sys::align_to_netlink(length).unwrap();
            let mut message = vec![0_u8; aligned];
            message[..4].copy_from_slice(&(length as u32).to_ne_bytes());
            message[4..6].copy_from_slice(&message_type.to_ne_bytes());
            message[6..8].copy_from_slice(&flags.to_ne_bytes());
            message[8..12].copy_from_slice(&sequence.to_ne_bytes());
            message[12..16].copy_from_slice(&port_id.to_ne_bytes());
            message[NL_HDR..length].copy_from_slice(body);
            message
        }

        fn dump_attribute(attribute_type: u16, value: &[u8]) -> Vec<u8> {
            const ATTR_HDR: usize = 4;
            let length = ATTR_HDR + value.len();
            let aligned = sys::align_to_netlink(length).unwrap();
            let mut attribute = vec![0_u8; aligned];
            attribute[..2].copy_from_slice(&(length as u16).to_ne_bytes());
            attribute[2..4].copy_from_slice(&attribute_type.to_ne_bytes());
            attribute[ATTR_HDR..length].copy_from_slice(value);
            attribute
        }

        fn filter_dump_message(
            flags: u16,
            sequence: u32,
            port_id: u32,
            owner: Option<(&str, u32)>,
        ) -> Vec<u8> {
            const TCMSG: usize = 20;
            let mut body = vec![0_u8; TCMSG];
            body[4..8].copy_from_slice(&TEST_DUMP_IFINDEX.to_ne_bytes());
            body[8..12].copy_from_slice(&u32::from(TC_HANDLE).to_ne_bytes());
            body[12..16].copy_from_slice(&TEST_DUMP_PARENT.to_ne_bytes());
            body[16..20].copy_from_slice(
                &((u32::from(crate::ebpf::DEFAULT_TC_PRIORITY) << 16) | u32::from(TC_PROTOCOL_ALL))
                    .to_ne_bytes(),
            );
            if let Some((name, program_id)) = owner {
                body.extend_from_slice(&dump_attribute(sys::TCA_KIND, b"bpf\0"));
                let mut options = dump_attribute(sys::TCA_BPF_NAME, name.as_bytes());
                options
                    .extend_from_slice(&dump_attribute(sys::TCA_BPF_ID, &program_id.to_ne_bytes()));
                body.extend_from_slice(&dump_attribute(sys::TCA_OPTIONS, &options));
            }
            dump_message(sys::RTM_NEWTFILTER, flags, sequence, port_id, &body)
        }

        fn done_dump_message(flags: u16, sequence: u32, port_id: u32, status: i32) -> Vec<u8> {
            dump_message(
                sys::NLMSG_DONE,
                flags,
                sequence,
                port_id,
                &status.to_ne_bytes(),
            )
        }

        fn parse_test_dump(
            message: &[u8],
            state: &mut TfilterDumpState,
        ) -> Result<DumpOutcome, GtpuError> {
            parse_tfilter_dump(
                message,
                crate::ebpf::DEFAULT_TC_PRIORITY,
                TfilterDumpExpectation {
                    sequence: TEST_DUMP_SEQUENCE,
                    port_id: TEST_DUMP_PORT_ID,
                    ifindex: TEST_DUMP_IFINDEX,
                    parent: TEST_DUMP_PARENT,
                    protocol: TC_PROTOCOL_ALL,
                    legacy_v2_scan: LegacyV2ProgramScan::Disabled,
                },
                state,
            )
        }

        fn assert_incomplete(error: GtpuError) {
            assert!(matches!(
                error,
                GtpuError::StateIndeterminate {
                    operation: "ebpf_tc_filter_dump"
                }
            ));
        }

        #[test]
        fn exact_slot_non_bpf_filter_is_foreign_not_absent() {
            let message = filter_dump_message(
                sys::NLM_F_MULTI,
                TEST_DUMP_SEQUENCE,
                TEST_DUMP_PORT_ID,
                None,
            );
            let mut state = TfilterDumpState::default();

            assert!(matches!(
                parse_test_dump(&message, &mut state).unwrap(),
                DumpOutcome::More
            ));
            let owner = state.owner.expect("exact-slot owner");
            assert_eq!(owner.name, "<non-bpf-filter>");
            assert_eq!(owner.program_id, None);
        }

        #[test]
        fn clean_dump_proves_owner_or_absence_only_after_done() {
            let owner_message = filter_dump_message(
                sys::NLM_F_MULTI,
                TEST_DUMP_SEQUENCE,
                TEST_DUMP_PORT_ID,
                Some(("owned\0", 73)),
            );
            let done =
                done_dump_message(sys::NLM_F_MULTI, TEST_DUMP_SEQUENCE, TEST_DUMP_PORT_ID, 0);
            let mut owner_state = TfilterDumpState::default();
            assert!(matches!(
                parse_test_dump(&owner_message, &mut owner_state).unwrap(),
                DumpOutcome::More
            ));
            assert_eq!(
                owner_state.owner,
                Some(FilterOwner {
                    name: String::from("owned"),
                    program_id: Some(73),
                })
            );
            assert!(matches!(
                parse_test_dump(&done, &mut owner_state).unwrap(),
                DumpOutcome::Done
            ));

            let mut absent_state = TfilterDumpState::default();
            assert!(matches!(
                parse_test_dump(&done, &mut absent_state).unwrap(),
                DumpOutcome::Done
            ));
            assert_eq!(absent_state.owner, None);
        }

        #[test]
        fn interrupted_object_or_done_is_not_authoritative() {
            for message in [
                filter_dump_message(
                    sys::NLM_F_MULTI | sys::NLM_F_DUMP_INTR,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID,
                    None,
                ),
                done_dump_message(
                    sys::NLM_F_MULTI | sys::NLM_F_DUMP_INTR,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID,
                    0,
                ),
            ] {
                let mut state = TfilterDumpState::default();
                assert_incomplete(parse_test_dump(&message, &mut state).unwrap_err());
            }
        }

        #[test]
        fn observed_owner_followed_by_interrupted_done_is_not_authoritative() {
            let mut datagram = filter_dump_message(
                sys::NLM_F_MULTI,
                TEST_DUMP_SEQUENCE,
                TEST_DUMP_PORT_ID,
                Some(("owned\0", 73)),
            );
            datagram.extend_from_slice(&done_dump_message(
                sys::NLM_F_MULTI | sys::NLM_F_DUMP_INTR,
                TEST_DUMP_SEQUENCE,
                TEST_DUMP_PORT_ID,
                0,
            ));
            let mut state = TfilterDumpState::default();
            assert_incomplete(parse_test_dump(&datagram, &mut state).unwrap_err());
        }

        #[test]
        fn overrun_is_not_authoritative() {
            let message = dump_message(
                sys::NLMSG_OVERRUN,
                sys::NLM_F_MULTI,
                TEST_DUMP_SEQUENCE,
                TEST_DUMP_PORT_ID,
                &[],
            );
            let mut state = TfilterDumpState::default();
            assert_incomplete(parse_test_dump(&message, &mut state).unwrap_err());
        }

        #[test]
        fn done_requires_exact_zero_status() {
            let negative =
                done_dump_message(sys::NLM_F_MULTI, TEST_DUMP_SEQUENCE, TEST_DUMP_PORT_ID, -4);
            let mut state = TfilterDumpState::default();
            assert_incomplete(parse_test_dump(&negative, &mut state).unwrap_err());

            for body in [&[][..], &[0, 0, 0][..], &[0, 0, 0, 0, 0][..]] {
                let malformed = dump_message(
                    sys::NLMSG_DONE,
                    sys::NLM_F_MULTI,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID,
                    body,
                );
                let mut state = TfilterDumpState::default();
                assert!(matches!(
                    parse_test_dump(&malformed, &mut state).unwrap_err(),
                    GtpuError::Io {
                        operation: "tc_filter_dump",
                        kind: io::ErrorKind::InvalidData,
                        ..
                    }
                ));
            }
        }

        #[test]
        fn every_dump_header_must_match_sequence_and_local_port() {
            for message in [
                done_dump_message(
                    sys::NLM_F_MULTI,
                    TEST_DUMP_SEQUENCE + 1,
                    TEST_DUMP_PORT_ID,
                    0,
                ),
                done_dump_message(
                    sys::NLM_F_MULTI,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID + 1,
                    0,
                ),
            ] {
                let mut state = TfilterDumpState::default();
                assert_incomplete(parse_test_dump(&message, &mut state).unwrap_err());
            }
        }

        #[test]
        fn every_filter_message_must_match_requested_hook_identity() {
            const NL_HDR: usize = 16;
            let valid = filter_dump_message(
                sys::NLM_F_MULTI,
                TEST_DUMP_SEQUENCE,
                TEST_DUMP_PORT_ID,
                Some((PROG_UPLINK, 73)),
            );
            let mut wrong_family = valid.clone();
            wrong_family[NL_HDR] = 2;
            let mut wrong_ifindex = valid.clone();
            wrong_ifindex[NL_HDR + 4..NL_HDR + 8]
                .copy_from_slice(&(TEST_DUMP_IFINDEX + 1).to_ne_bytes());
            let mut wrong_parent = valid.clone();
            wrong_parent[NL_HDR + 12..NL_HDR + 16]
                .copy_from_slice(&sys::TC_H_CLSACT_EGRESS.to_ne_bytes());
            let mut wrong_protocol = valid;
            let info =
                u32::from_ne_bytes(wrong_protocol[NL_HDR + 16..NL_HDR + 20].try_into().unwrap());
            wrong_protocol[NL_HDR + 16..NL_HDR + 20].copy_from_slice(
                &((info & 0xffff_0000) | u32::from(TC_PROTOCOL_ALL.wrapping_add(1))).to_ne_bytes(),
            );

            for message in [wrong_family, wrong_ifindex, wrong_parent, wrong_protocol] {
                let mut state = TfilterDumpState::default();
                assert_incomplete(parse_test_dump(&message, &mut state).unwrap_err());
            }
        }

        #[test]
        fn legacy_v2_scan_allows_only_the_expected_exact_slot_program() {
            const NL_HDR: usize = 16;
            for (expected_name, observed_name) in [
                (PROG_UPLINK, PROG_UPLINK),
                (PROG_UPLINK, PROG_DOWNLINK),
                (PROG_DOWNLINK, PROG_DOWNLINK),
                (PROG_DOWNLINK, PROG_UPLINK),
            ] {
                let kernel_name = std::str::from_utf8(kernel_program_name(observed_name)).unwrap();
                let exact = filter_dump_message(
                    sys::NLM_F_MULTI,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID,
                    Some((kernel_name, 73)),
                );
                let mut state = TfilterDumpState::default();
                assert!(matches!(
                    parse_tfilter_dump(
                        &exact,
                        crate::ebpf::DEFAULT_TC_PRIORITY,
                        TfilterDumpExpectation {
                            sequence: TEST_DUMP_SEQUENCE,
                            port_id: TEST_DUMP_PORT_ID,
                            ifindex: TEST_DUMP_IFINDEX,
                            parent: TEST_DUMP_PARENT,
                            protocol: TC_PROTOCOL_ALL,
                            legacy_v2_scan: LegacyV2ProgramScan::AllowExact(expected_name),
                        },
                        &mut state,
                    )
                    .unwrap(),
                    DumpOutcome::More
                ));
                assert_eq!(
                    state.unexpected_legacy_v2_program_seen,
                    expected_name != observed_name,
                    "cross-direction legacy program names must be rejected"
                );

                let mut message = filter_dump_message(
                    sys::NLM_F_MULTI,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID,
                    Some((kernel_name, 74)),
                );
                let info = ((u32::from(crate::ebpf::DEFAULT_TC_PRIORITY) + 1) << 16)
                    | u32::from(TC_PROTOCOL_ALL);
                message[NL_HDR + 16..NL_HDR + 20].copy_from_slice(&info.to_ne_bytes());
                let mut state = TfilterDumpState::default();

                assert!(matches!(
                    parse_tfilter_dump(
                        &message,
                        crate::ebpf::DEFAULT_TC_PRIORITY,
                        TfilterDumpExpectation {
                            sequence: TEST_DUMP_SEQUENCE,
                            port_id: TEST_DUMP_PORT_ID,
                            ifindex: TEST_DUMP_IFINDEX,
                            parent: TEST_DUMP_PARENT,
                            protocol: TC_PROTOCOL_ALL,
                            legacy_v2_scan: LegacyV2ProgramScan::AllowExact(expected_name),
                        },
                        &mut state,
                    )
                    .unwrap(),
                    DumpOutcome::More
                ));
                assert!(state.unexpected_legacy_v2_program_seen);
                assert!(state.owner.is_none());
            }
        }

        #[test]
        fn exact_legacy_v2_program_plus_same_or_cross_name_extra_is_rejected() {
            const NL_HDR: usize = 16;
            let expected_name = std::str::from_utf8(kernel_program_name(PROG_UPLINK)).unwrap();
            for extra_name in [PROG_UPLINK, PROG_DOWNLINK] {
                let extra_name = std::str::from_utf8(kernel_program_name(extra_name)).unwrap();
                let mut datagram = filter_dump_message(
                    sys::NLM_F_MULTI,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID,
                    Some((expected_name, 73)),
                );
                let mut extra = filter_dump_message(
                    sys::NLM_F_MULTI,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID,
                    Some((extra_name, 74)),
                );
                let info = ((u32::from(crate::ebpf::DEFAULT_TC_PRIORITY) + 1) << 16)
                    | u32::from(TC_PROTOCOL_ALL);
                extra[NL_HDR + 16..NL_HDR + 20].copy_from_slice(&info.to_ne_bytes());
                datagram.extend_from_slice(&extra);
                datagram.extend_from_slice(&done_dump_message(
                    sys::NLM_F_MULTI,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID,
                    0,
                ));
                let mut state = TfilterDumpState::default();

                assert!(matches!(
                    parse_tfilter_dump(
                        &datagram,
                        crate::ebpf::DEFAULT_TC_PRIORITY,
                        TfilterDumpExpectation {
                            sequence: TEST_DUMP_SEQUENCE,
                            port_id: TEST_DUMP_PORT_ID,
                            ifindex: TEST_DUMP_IFINDEX,
                            parent: TEST_DUMP_PARENT,
                            protocol: TC_PROTOCOL_ALL,
                            legacy_v2_scan: LegacyV2ProgramScan::AllowExact(PROG_UPLINK),
                        },
                        &mut state,
                    )
                    .unwrap(),
                    DumpOutcome::Done
                ));
                assert_eq!(
                    state.owner,
                    Some(FilterOwner {
                        name: expected_name.into(),
                        program_id: Some(73),
                    })
                );
                assert!(state.unexpected_legacy_v2_program_seen);
            }
        }

        #[test]
        fn absence_scan_ignores_foreign_names_but_detects_either_legacy_name() {
            for (name, is_legacy) in [
                ("foreign", false),
                (
                    std::str::from_utf8(kernel_program_name(PROG_UPLINK)).unwrap(),
                    true,
                ),
                (
                    std::str::from_utf8(kernel_program_name(PROG_DOWNLINK)).unwrap(),
                    true,
                ),
            ] {
                let message = filter_dump_message(
                    sys::NLM_F_MULTI,
                    TEST_DUMP_SEQUENCE,
                    TEST_DUMP_PORT_ID,
                    Some((name, 73)),
                );
                let mut state = TfilterDumpState::default();
                assert!(matches!(
                    parse_tfilter_dump(
                        &message,
                        crate::ebpf::DEFAULT_TC_PRIORITY,
                        TfilterDumpExpectation {
                            sequence: TEST_DUMP_SEQUENCE,
                            port_id: TEST_DUMP_PORT_ID,
                            ifindex: TEST_DUMP_IFINDEX,
                            parent: TEST_DUMP_PARENT,
                            protocol: TC_PROTOCOL_ALL,
                            legacy_v2_scan: LegacyV2ProgramScan::RequireAbsent,
                        },
                        &mut state,
                    )
                    .unwrap(),
                    DumpOutcome::More
                ));
                assert_eq!(state.unexpected_legacy_v2_program_seen, is_legacy);
            }
        }

        #[test]
        fn duplicate_or_conflicting_exact_slot_owners_are_not_authoritative() {
            let first = filter_dump_message(
                sys::NLM_F_MULTI,
                TEST_DUMP_SEQUENCE,
                TEST_DUMP_PORT_ID,
                Some(("first\0", 73)),
            );
            let duplicate = first.clone();
            let conflicting = filter_dump_message(
                sys::NLM_F_MULTI,
                TEST_DUMP_SEQUENCE,
                TEST_DUMP_PORT_ID,
                Some(("second\0", 74)),
            );

            for second in [duplicate, conflicting] {
                let mut state = TfilterDumpState::default();
                assert!(matches!(
                    parse_test_dump(&first, &mut state).unwrap(),
                    DumpOutcome::More
                ));
                assert_incomplete(parse_test_dump(&second, &mut state).unwrap_err());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::net::Ipv6Addr;
    use std::sync::{Barrier, Mutex};

    use opc_gtpu_ebpf_common::default_bearer_graph_is_valid;

    use crate::model::{GtpBearerMark, Teid};
    use crate::{DrainedV2TeardownProgress, GtpAddressFamily};

    use super::*;

    const S2BU_IFINDEX: u32 = 7;
    const LEGACY_V2_PIN_COUNT: usize = 9;

    #[derive(Debug)]
    struct FakeRuntime {
        ifindexes: HashMap<String, u32>,
        state: Mutex<FakeState>,
        environment: EbpfEnvironment,
    }

    #[derive(Debug, Default)]
    struct FakeState {
        attached: HashMap<u32, FakeAttachment>,
        // Simulates pinned state that survives detach-free process restarts.
        pinned_config: HashMap<PathBuf, [u8; 4]>,
        far: HashMap<(u32, [u8; 4]), [u8; UPLINK_FAR_VALUE_LEN]>,
        marked_far: HashMap<(u32, [u8; UPLINK_MARK_KEY_LEN]), [u8; UPLINK_FAR_VALUE_LEN]>,
        dscp: HashMap<(u32, [u8; 4]), [u8; UPLINK_DSCP_VALUE_LEN]>,
        marked_dscp: HashMap<(u32, [u8; UPLINK_MARK_KEY_LEN]), [u8; UPLINK_DSCP_VALUE_LEN]>,
        sport: HashMap<(u32, [u8; 4]), [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>,
        marked_sport: HashMap<(u32, [u8; UPLINK_MARK_KEY_LEN]), [u8; UPLINK_SOURCE_PORT_VALUE_LEN]>,
        pmtu_policy: HashMap<u32, [u8; UPLINK_PMTU_VALUE_LEN]>,
        pdr: HashMap<(u32, [u8; 4]), [u8; DOWNLINK_PDR_VALUE_LEN]>,
        marked_pdr: HashMap<(u32, [u8; 4]), [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>,
        downlink_binding: HashMap<(u32, [u8; 4]), [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>,
        marked_owner:
            HashMap<(u32, [u8; UPLINK_MARK_KEY_LEN]), [u8; MARKED_BEARER_OWNER_VALUE_LEN]>,
        marked_owner_by_teid: HashMap<(u32, [u8; 4]), [u8; UPLINK_MARK_KEY_LEN]>,
        default_teid_by_ue: HashMap<(u32, [u8; 4]), [u8; 4]>,
        datapath_snapshot: EbpfGtpuDatapathSnapshot,
        dscp_map_ready: HashSet<u32>,
        marked_far_map_ready: HashSet<u32>,
        marked_dscp_map_ready: HashSet<u32>,
        sport_map_ready: HashSet<u32>,
        marked_sport_map_ready: HashSet<u32>,
        pmtu_map_ready: HashSet<u32>,
        pmtu_counters_map_ready: HashSet<u32>,
        marked_pdr_map_ready: HashSet<u32>,
        marked_owner_map_ready: HashSet<u32>,
        downlink_binding_map_ready: HashSet<u32>,
        downlink_binding_counters_map_ready: HashSet<u32>,
        uplink_filter_ready: HashSet<u32>,
        downlink_filter_ready: HashSet<u32>,
        uplink_filter_foreign: HashSet<u32>,
        downlink_filter_foreign: HashSet<u32>,
        legacy_v2_extra_hooks: HashSet<(u32, FakeLegacyV2Hook, FakeLegacyV2Program)>,
        pin_identity_invalid: HashSet<u32>,
        v2_schema_identity_invalid: HashSet<u32>,
        // One durable marker state per pin directory, mirroring the single
        // reserved FAR entry used by production.
        schema: HashMap<PathBuf, FakeSchema>,
        // Durable legacy-v2 teardown evidence and remaining pin count model
        // crash/retry boundaries without weakening the production algorithm.
        v2_teardown_proof: HashSet<PathBuf>,
        v2_pins_remaining: HashMap<PathBuf, usize>,
        empty_pin_dirs: HashSet<PathBuf>,
        operations: Vec<&'static str>,
        failures: VecDeque<&'static str>,
        crashes_after: VecDeque<&'static str>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum FakeLegacyV2Hook {
        Egress,
        Ingress,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum FakeLegacyV2Program {
        Uplink,
        Downlink,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeSchema {
        LegacyV0,
        V1Uncommitted,
        DscpV1,
        BearerV2,
        EndpointV3,
        SourcePortV4,
        PmtuV5,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FakeAttachment {
        interface: String,
        pin_dir: PathBuf,
        tc_priority: u16,
    }

    impl FakeRuntime {
        fn new() -> Self {
            Self {
                ifindexes: HashMap::from([("s2bu".to_string(), S2BU_IFINDEX)]),
                state: Mutex::new(FakeState::default()),
                environment: EbpfEnvironment {
                    platform_supported: true,
                    bpffs_present: true,
                    btf_present: true,
                    net_admin_capable: true,
                    bpf_capable: true,
                },
            }
        }

        fn with_environment(environment: EbpfEnvironment) -> Self {
            Self {
                environment,
                ..Self::new()
            }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn fail_in_order(&self, operations: impl IntoIterator<Item = &'static str>) {
            self.state().failures.extend(operations);
        }

        fn crash_after_in_order(&self, operations: impl IntoIterator<Item = &'static str>) {
            self.state().crashes_after.extend(operations);
        }

        fn fail_if_requested(
            state: &mut FakeState,
            operation: &'static str,
        ) -> Result<(), GtpuError> {
            if state.failures.front().copied() == Some(operation) {
                state.failures.pop_front();
                return Err(GtpuError::io(
                    operation,
                    io::Error::other("injected fake runtime failure"),
                ));
            }
            Ok(())
        }

        fn crash_if_requested(state: &mut FakeState, operation: &'static str) {
            if state.crashes_after.front().copied() == Some(operation) {
                state.crashes_after.pop_front();
                panic!("injected deterministic crash after {operation}");
            }
        }

        fn validate_schema(
            state: &FakeState,
            pin_dir: &Path,
            ifindex: u32,
        ) -> Result<(), GtpuError> {
            if state.v2_teardown_proof.contains(pin_dir) {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_legacy_v2_teardown_pending",
                });
            }
            match state.schema.get(pin_dir).copied() {
                None | Some(FakeSchema::LegacyV0) => Ok(()),
                Some(FakeSchema::V1Uncommitted | FakeSchema::DscpV1) => {
                    if state.dscp_map_ready.contains(&ifindex) {
                        Ok(())
                    } else {
                        Err(GtpuError::io(
                            "ebpf_dscp_schema",
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                "adopted DSCP map pin is missing",
                            ),
                        ))
                    }
                }
                Some(FakeSchema::BearerV2) => Err(GtpuError::io(
                    "ebpf_endpoint_schema",
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "endpoint-unbound GTP-U schema requires drained reprovisioning",
                    ),
                )),
                Some(FakeSchema::EndpointV3) => {
                    if state.dscp_map_ready.contains(&ifindex)
                        && state.marked_far_map_ready.contains(&ifindex)
                        && state.marked_dscp_map_ready.contains(&ifindex)
                        && state.marked_pdr_map_ready.contains(&ifindex)
                        && state.marked_owner_map_ready.contains(&ifindex)
                        && state.downlink_binding_map_ready.contains(&ifindex)
                        && state.downlink_binding_counters_map_ready.contains(&ifindex)
                    {
                        Ok(())
                    } else {
                        Err(GtpuError::io(
                            "ebpf_bearer_schema",
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                "adopted bearer map pin is missing",
                            ),
                        ))
                    }
                }
                Some(FakeSchema::SourcePortV4) => {
                    if state.dscp_map_ready.contains(&ifindex)
                        && state.marked_far_map_ready.contains(&ifindex)
                        && state.marked_dscp_map_ready.contains(&ifindex)
                        && state.sport_map_ready.contains(&ifindex)
                        && state.marked_sport_map_ready.contains(&ifindex)
                        && state.marked_pdr_map_ready.contains(&ifindex)
                        && state.marked_owner_map_ready.contains(&ifindex)
                        && state.downlink_binding_map_ready.contains(&ifindex)
                        && state.downlink_binding_counters_map_ready.contains(&ifindex)
                    {
                        Ok(())
                    } else {
                        Err(GtpuError::io(
                            "ebpf_bearer_schema",
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                "adopted source-port map pin is missing",
                            ),
                        ))
                    }
                }
                Some(FakeSchema::PmtuV5) => {
                    if state.dscp_map_ready.contains(&ifindex)
                        && state.marked_far_map_ready.contains(&ifindex)
                        && state.marked_dscp_map_ready.contains(&ifindex)
                        && state.sport_map_ready.contains(&ifindex)
                        && state.marked_sport_map_ready.contains(&ifindex)
                        && state.pmtu_map_ready.contains(&ifindex)
                        && state.pmtu_counters_map_ready.contains(&ifindex)
                        && state.marked_pdr_map_ready.contains(&ifindex)
                        && state.marked_owner_map_ready.contains(&ifindex)
                        && state.downlink_binding_map_ready.contains(&ifindex)
                        && state.downlink_binding_counters_map_ready.contains(&ifindex)
                    {
                        Ok(())
                    } else {
                        Err(GtpuError::io(
                            "ebpf_bearer_schema",
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                "adopted MTU policy map pin is missing",
                            ),
                        ))
                    }
                }
            }
        }

        fn rebuild_owner_index(
            state: &mut FakeState,
            ifindex: u32,
            local_ip: [u8; 4],
            source_port_committed: bool,
        ) -> Result<(), GtpuError> {
            let invalid = || GtpuError::StateIndeterminate {
                operation: "ebpf_marked_owner_rebuild",
            };
            let entries = state
                .marked_owner
                .iter()
                .filter_map(|((index, selector), value)| {
                    (*index == ifindex).then_some((*selector, *value))
                })
                .collect::<Vec<_>>();
            let mut rebuilt = HashMap::new();
            for (selector, encoded) in entries {
                let key = UplinkFarKey::decode(&selector);
                let owner = MarkedBearerOwner::decode(&encoded);
                if key.ue_ip == [0; 4]
                    || key.ue_ip == local_ip
                    || key.bearer_mark == [0; 4]
                    || !owner.is_valid()
                    || owner.uplink_far.local_ip != local_ip
                    || owner.downlink_binding.ingress_ifindex() != ifindex
                    || state.pdr.contains_key(&(ifindex, owner.local_teid))
                    || rebuilt.insert(owner.local_teid, selector).is_some()
                    || source_port_committed && owner.phase != MarkedBearerOwnerPhase::Active
                {
                    return Err(invalid());
                }
                let migration_commit = PdpContextCommit::new(
                    owner.local_teid,
                    owner.uplink_far,
                    owner.egress_dscp(),
                    owner.downlink_binding,
                    crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
                    owner.phase,
                )
                .ok_or_else(invalid)?;
                let expected_far = owner.uplink_far.encode();
                let expected_dscp = owner.egress_dscp().map(|value| [value]);
                let expected_pdr = MarkedDownlinkPdr {
                    ue_ip: key.ue_ip,
                    bearer_mark: key.bearer_mark,
                }
                .encode();
                let far = state.marked_far.get(&(ifindex, selector)).copied();
                let dscp = state.marked_dscp.get(&(ifindex, selector)).copied();
                let sport = state.marked_sport.get(&(ifindex, selector)).copied();
                let pdr = state.marked_pdr.get(&(ifindex, owner.local_teid)).copied();
                let binding = state
                    .downlink_binding
                    .get(&(ifindex, owner.local_teid))
                    .copied();
                let expected_binding = owner.downlink_binding.encode();
                let sport_matches = match sport {
                    Some(value) => {
                        let commit = PdpContextCommit::decode(&value);
                        commit.is_valid()
                            && if source_port_committed {
                                commit.marked_owner() == owner
                            } else {
                                commit == migration_commit
                            }
                    }
                    None => !source_port_committed,
                };
                let resources_owned = far.is_none_or(|value| {
                    let value = UplinkFar::decode(&value);
                    value.local_ip == local_ip && value.peer_ip != [0; 4] && value.o_teid != [0; 4]
                }) && dscp.is_none_or(|value| value[0] <= 63)
                    && pdr.is_none_or(|value| value == expected_pdr)
                    && binding.is_none_or(|value| {
                        let value = DownlinkEndpointBinding::decode(&value);
                        value.is_valid()
                            && value.ingress_ifindex() == ifindex
                            && value.local_address() == owner.downlink_binding.local_address()
                    });
                let complete = far == Some(expected_far)
                    && dscp == expected_dscp
                    && pdr == Some(expected_pdr)
                    && binding == Some(expected_binding)
                    && sport_matches;
                if !resources_owned
                    || !sport_matches
                    || owner.phase == MarkedBearerOwnerPhase::Active && !complete
                {
                    return Err(invalid());
                }
            }
            for (index, selector) in state.marked_far.keys() {
                if *index == ifindex && !state.marked_owner.contains_key(&(*index, *selector)) {
                    return Err(invalid());
                }
            }
            for (index, selector) in state.marked_dscp.keys() {
                if *index == ifindex && !state.marked_owner.contains_key(&(*index, *selector)) {
                    return Err(invalid());
                }
            }
            for (index, selector) in state.marked_sport.keys() {
                if *index == ifindex && !state.marked_owner.contains_key(&(*index, *selector)) {
                    return Err(invalid());
                }
            }
            for ((index, teid), encoded) in &state.marked_pdr {
                if *index != ifindex {
                    continue;
                }
                let pdr = MarkedDownlinkPdr::decode(encoded);
                let selector = UplinkFarKey {
                    ue_ip: pdr.ue_ip,
                    bearer_mark: pdr.bearer_mark,
                }
                .encode();
                let Some(encoded_owner) = state.marked_owner.get(&(*index, selector)) else {
                    return Err(invalid());
                };
                if MarkedBearerOwner::decode(encoded_owner).local_teid != *teid {
                    return Err(invalid());
                }
            }

            let mut default_teids = HashSet::new();
            let mut default_teid_by_ue = HashMap::new();
            for ((index, teid), encoded) in &state.pdr {
                if *index != ifindex {
                    continue;
                }
                let pdr = DownlinkPdr::decode(encoded);
                let far = state
                    .far
                    .get(&(*index, pdr.ue_ip))
                    .copied()
                    .ok_or_else(invalid)?;
                let far = UplinkFar::decode(&far);
                let binding = state
                    .downlink_binding
                    .get(&(*index, *teid))
                    .copied()
                    .ok_or_else(invalid)?;
                let binding = DownlinkEndpointBinding::decode(&binding);
                if !default_bearer_graph_is_valid(*teid, pdr, far, binding, local_ip, ifindex)
                    || !default_teids.insert(*teid)
                    || default_teid_by_ue.insert(pdr.ue_ip, *teid).is_some()
                {
                    return Err(invalid());
                }
                if state
                    .dscp
                    .get(&(*index, pdr.ue_ip))
                    .is_some_and(|value| value[0] > 63)
                {
                    return Err(invalid());
                }
                let dscp = state.dscp.get(&(*index, pdr.ue_ip)).map(|value| value[0]);
                let migration_commit = PdpContextCommit::new(
                    *teid,
                    far,
                    dscp,
                    binding,
                    crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
                    MarkedBearerOwnerPhase::Active,
                )
                .ok_or_else(invalid)?;
                match state.sport.get(&(*index, pdr.ue_ip)).copied() {
                    Some(value) => {
                        let commit = PdpContextCommit::decode(&value);
                        if !commit.is_valid()
                            || if source_port_committed {
                                !commit.authorizes_graph(*teid, &far, dscp, &binding)
                            } else {
                                commit != migration_commit
                            }
                        {
                            return Err(invalid());
                        }
                    }
                    None if !source_port_committed => {}
                    None => return Err(invalid()),
                }
            }
            for (index, ue_ip) in state.far.keys() {
                if *index == ifindex
                    && *ue_ip != opc_gtpu_ebpf_common::UPLINK_DSCP_SCHEMA_MARKER_KEY
                    && !default_teid_by_ue.contains_key(ue_ip)
                {
                    return Err(invalid());
                }
            }
            for ((index, _), value) in &state.dscp {
                if *index == ifindex && value[0] > 63 {
                    return Err(invalid());
                }
            }
            for ((index, ue_ip), value) in &state.sport {
                if *index == ifindex
                    && (!default_teid_by_ue.contains_key(ue_ip)
                        || !PdpContextCommit::decode(value).is_valid())
                {
                    return Err(invalid());
                }
            }
            for ((index, teid), encoded) in &state.downlink_binding {
                if *index != ifindex {
                    continue;
                }
                let binding = DownlinkEndpointBinding::decode(encoded);
                let has_default = state.pdr.contains_key(&(*index, *teid));
                let has_marked = rebuilt.contains_key(teid);
                if !binding.is_valid() || has_default == has_marked {
                    return Err(invalid());
                }
            }
            if default_teids.iter().any(|teid| rebuilt.contains_key(teid)) {
                return Err(invalid());
            }
            state
                .marked_owner_by_teid
                .retain(|(index, _), _| *index != ifindex);
            state.marked_owner_by_teid.extend(
                rebuilt
                    .into_iter()
                    .map(|(teid, selector)| ((ifindex, teid), selector)),
            );
            state
                .default_teid_by_ue
                .retain(|(index, _), _| *index != ifindex);
            state.default_teid_by_ue.extend(
                default_teid_by_ue
                    .into_iter()
                    .map(|(ue_ip, teid)| ((ifindex, ue_ip), teid)),
            );
            Ok(())
        }

        fn recover_incomplete_pdp_commits(
            state: &mut FakeState,
            ifindex: u32,
            local_ip: [u8; 4],
        ) -> Result<(), GtpuError> {
            let invalid = || GtpuError::StateIndeterminate {
                operation: "ebpf_pdp_recovery",
            };
            let default_incomplete = state
                .sport
                .iter()
                .filter(|((index, _), _)| *index == ifindex)
                .try_fold(false, |found, (_, encoded)| {
                    let commit = PdpContextCommit::decode(encoded);
                    if !commit.is_valid() {
                        Err(invalid())
                    } else {
                        Ok(found || commit.phase() != MarkedBearerOwnerPhase::Active)
                    }
                })?;
            let marked_incomplete = state
                .marked_sport
                .iter()
                .filter(|((index, _), _)| *index == ifindex)
                .try_fold(false, |found, (_, encoded)| {
                    let commit = PdpContextCommit::decode(encoded);
                    if !commit.is_valid() {
                        Err(invalid())
                    } else {
                        Ok(found || commit.phase() != MarkedBearerOwnerPhase::Active)
                    }
                })?;
            if !default_incomplete && !marked_incomplete {
                return Ok(());
            }
            let owner_teids = state
                .marked_owner
                .iter()
                .filter_map(|((index, selector), encoded)| {
                    if *index != ifindex {
                        return None;
                    }
                    let owner = MarkedBearerOwner::decode(encoded);
                    Some((owner.local_teid, (*selector, owner)))
                })
                .collect::<HashMap<_, _>>();
            if owner_teids.len()
                != state
                    .marked_owner
                    .keys()
                    .filter(|(index, _)| *index == ifindex)
                    .count()
                || owner_teids.values().any(|(_, owner)| !owner.is_valid())
            {
                return Err(invalid());
            }

            let mut claimed_teids = HashSet::new();
            let mut default_transactions = Vec::new();
            for ((index, ue_ip), encoded) in &state.sport {
                if *index != ifindex {
                    continue;
                }
                let commit = PdpContextCommit::decode(encoded);
                if *ue_ip == [0; 4]
                    || !commit.is_valid()
                    || commit.uplink_far().local_ip != local_ip
                    || commit.downlink_binding().ingress_ifindex() != ifindex
                    || !claimed_teids.insert(commit.local_teid())
                {
                    return Err(invalid());
                }
                if commit.phase() == MarkedBearerOwnerPhase::Active {
                    continue;
                }
                if owner_teids.contains_key(&commit.local_teid())
                    || state
                        .marked_pdr
                        .contains_key(&(ifindex, commit.local_teid()))
                    || state
                        .pdr
                        .get(&(ifindex, commit.local_teid()))
                        .is_some_and(|value| DownlinkPdr::decode(value).ue_ip != *ue_ip)
                {
                    return Err(invalid());
                }
                if state.far.get(&(*index, *ue_ip)).is_some_and(|value| {
                    let value = UplinkFar::decode(value);
                    value.local_ip != local_ip || value.peer_ip == [0; 4] || value.o_teid == [0; 4]
                }) || state
                    .dscp
                    .get(&(*index, *ue_ip))
                    .is_some_and(|value| value[0] > 63)
                    || state
                        .downlink_binding
                        .get(&(*index, commit.local_teid()))
                        .is_some_and(|value| {
                            let value = DownlinkEndpointBinding::decode(value);
                            !value.is_valid()
                                || value.ingress_ifindex() != ifindex
                                || value.local_address()
                                    != commit.downlink_binding().local_address()
                        })
                {
                    return Err(invalid());
                }
                default_transactions.push((*ue_ip, commit.local_teid()));
            }

            let mut marked_transactions = Vec::new();
            for ((index, selector), encoded) in &state.marked_sport {
                if *index != ifindex {
                    continue;
                }
                let selector_value = UplinkFarKey::decode(selector);
                let commit = PdpContextCommit::decode(encoded);
                if selector_value.ue_ip == [0; 4]
                    || selector_value.ue_ip == local_ip
                    || selector_value.bearer_mark == [0; 4]
                    || !commit.is_valid()
                    || commit.uplink_far().local_ip != local_ip
                    || commit.downlink_binding().ingress_ifindex() != ifindex
                    || !claimed_teids.insert(commit.local_teid())
                {
                    return Err(invalid());
                }
                if commit.phase() == MarkedBearerOwnerPhase::Active {
                    continue;
                }
                let expected_pdr = MarkedDownlinkPdr {
                    ue_ip: selector_value.ue_ip,
                    bearer_mark: selector_value.bearer_mark,
                };
                if state.pdr.contains_key(&(ifindex, commit.local_teid()))
                    || state
                        .marked_pdr
                        .get(&(ifindex, commit.local_teid()))
                        .is_some_and(|value| MarkedDownlinkPdr::decode(value) != expected_pdr)
                    || owner_teids.get(&commit.local_teid()).is_some_and(
                        |(owner_selector, owner)| {
                            *owner_selector != *selector
                                || owner.uplink_far.local_ip != local_ip
                                || owner.downlink_binding.ingress_ifindex() != ifindex
                        },
                    )
                    || state
                        .marked_owner
                        .get(&(ifindex, *selector))
                        .is_some_and(|encoded_owner| {
                            let owner = MarkedBearerOwner::decode(encoded_owner);
                            owner.local_teid != commit.local_teid()
                                || owner.uplink_far.local_ip != local_ip
                                || owner.downlink_binding.ingress_ifindex() != ifindex
                        })
                    || state
                        .marked_far
                        .get(&(*index, *selector))
                        .is_some_and(|value| {
                            let value = UplinkFar::decode(value);
                            value.local_ip != local_ip
                                || value.peer_ip == [0; 4]
                                || value.o_teid == [0; 4]
                        })
                    || state
                        .marked_dscp
                        .get(&(*index, *selector))
                        .is_some_and(|value| value[0] > 63)
                    || state
                        .downlink_binding
                        .get(&(*index, commit.local_teid()))
                        .is_some_and(|value| {
                            let value = DownlinkEndpointBinding::decode(value);
                            !value.is_valid()
                                || value.ingress_ifindex() != ifindex
                                || value.local_address()
                                    != commit.downlink_binding().local_address()
                        })
                {
                    return Err(invalid());
                }
                marked_transactions.push((*selector, commit.local_teid()));
            }

            for (ue_ip, local_teid) in default_transactions {
                for operation in [
                    "recover_default_far_remove",
                    "recover_default_dscp_remove",
                    "recover_default_binding_remove",
                    "recover_default_pdr_remove",
                    "recover_default_commit_remove",
                ] {
                    state.operations.push(operation);
                    Self::fail_if_requested(state, operation)?;
                    match operation {
                        "recover_default_far_remove" => {
                            state.far.remove(&(ifindex, ue_ip));
                        }
                        "recover_default_dscp_remove" => {
                            state.dscp.remove(&(ifindex, ue_ip));
                        }
                        "recover_default_binding_remove" => {
                            state.downlink_binding.remove(&(ifindex, local_teid));
                        }
                        "recover_default_pdr_remove" => {
                            state.pdr.remove(&(ifindex, local_teid));
                        }
                        "recover_default_commit_remove" => {
                            state.sport.remove(&(ifindex, ue_ip));
                        }
                        _ => return Err(invalid()),
                    }
                    Self::crash_if_requested(state, operation);
                }
            }
            for (selector, local_teid) in marked_transactions {
                for operation in [
                    "recover_marked_far_remove",
                    "recover_marked_dscp_remove",
                    "recover_marked_binding_remove",
                    "recover_marked_pdr_remove",
                    "recover_marked_owner_remove",
                    "recover_marked_commit_remove",
                ] {
                    state.operations.push(operation);
                    Self::fail_if_requested(state, operation)?;
                    match operation {
                        "recover_marked_far_remove" => {
                            state.marked_far.remove(&(ifindex, selector));
                        }
                        "recover_marked_dscp_remove" => {
                            state.marked_dscp.remove(&(ifindex, selector));
                        }
                        "recover_marked_binding_remove" => {
                            state.downlink_binding.remove(&(ifindex, local_teid));
                        }
                        "recover_marked_pdr_remove" => {
                            state.marked_pdr.remove(&(ifindex, local_teid));
                        }
                        "recover_marked_owner_remove" => {
                            state.marked_owner.remove(&(ifindex, selector));
                        }
                        "recover_marked_commit_remove" => {
                            state.marked_sport.remove(&(ifindex, selector));
                        }
                        _ => return Err(invalid()),
                    }
                    Self::crash_if_requested(state, operation);
                }
            }
            Ok(())
        }

        fn materialize_legacy_source_port_policies(
            state: &mut FakeState,
            ifindex: u32,
        ) -> Result<(), GtpuError> {
            let default_commits = state
                .pdr
                .iter()
                .filter_map(|((index, teid), encoded)| {
                    if *index == ifindex {
                        let pdr = DownlinkPdr::decode(encoded);
                        let far = state.far.get(&(*index, pdr.ue_ip)).map(UplinkFar::decode)?;
                        let binding = state
                            .downlink_binding
                            .get(&(*index, *teid))
                            .map(DownlinkEndpointBinding::decode)?;
                        let dscp = state.dscp.get(&(*index, pdr.ue_ip)).map(|value| value[0]);
                        PdpContextCommit::new(
                            *teid,
                            far,
                            dscp,
                            binding,
                            crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
                            MarkedBearerOwnerPhase::Active,
                        )
                        .map(|commit| (pdr.ue_ip, commit))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            let marked_commits = state
                .marked_owner
                .iter()
                .filter_map(|((index, selector), encoded)| {
                    if *index == ifindex {
                        let owner = MarkedBearerOwner::decode(encoded);
                        PdpContextCommit::new(
                            owner.local_teid,
                            owner.uplink_far,
                            owner.egress_dscp(),
                            owner.downlink_binding,
                            crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
                            owner.phase,
                        )
                        .map(|commit| (*selector, commit))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            for (ue_ip, commit) in default_commits {
                Self::fail_if_requested(state, "source_port_schema_default_insert")?;
                state.sport.insert((ifindex, ue_ip), commit.encode());
            }
            for (selector, commit) in marked_commits {
                Self::fail_if_requested(state, "source_port_schema_marked_insert")?;
                state
                    .marked_sport
                    .insert((ifindex, selector), commit.encode());
            }
            Ok(())
        }
    }

    impl EbpfGtpuRuntime for FakeRuntime {
        fn ifindex_by_name(&self, name: &str) -> Result<u32, GtpuError> {
            self.ifindexes.get(name).copied().ok_or(GtpuError::NotFound)
        }

        fn attach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            tc_priority: u16,
            local_ip: [u8; 4],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            state.operations.push("attach");
            if state.attached.contains_key(&ifindex) {
                return Err(GtpuError::AlreadyExists);
            }
            Self::validate_schema(&state, pin_dir, ifindex)?;
            let source_port_committed = matches!(
                state.schema.get(pin_dir),
                Some(&FakeSchema::SourcePortV4 | &FakeSchema::PmtuV5)
            );
            if source_port_committed {
                Self::recover_incomplete_pdp_commits(&mut state, ifindex, local_ip)?;
                Self::rebuild_owner_index(&mut state, ifindex, local_ip, true)?;
            } else {
                Self::rebuild_owner_index(&mut state, ifindex, local_ip, false)?;
                Self::materialize_legacy_source_port_policies(&mut state, ifindex)?;
                Self::recover_incomplete_pdp_commits(&mut state, ifindex, local_ip)?;
                Self::rebuild_owner_index(&mut state, ifindex, local_ip, true)?;
            }
            if state.pmtu_policy.get(&ifindex).is_some_and(|value| {
                matches!(
                    GtpuUplinkMtuPolicy::decode_map_value(value),
                    UplinkMtuMapState::Corrupt
                )
            }) {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_pmtu_policy_adopt",
                });
            }
            state.pinned_config.insert(pin_dir.to_path_buf(), local_ip);
            state.attached.insert(
                ifindex,
                FakeAttachment {
                    interface: interface.to_string(),
                    pin_dir: pin_dir.to_path_buf(),
                    tc_priority,
                },
            );
            state.dscp_map_ready.insert(ifindex);
            state.marked_far_map_ready.insert(ifindex);
            state.marked_dscp_map_ready.insert(ifindex);
            state.sport_map_ready.insert(ifindex);
            state.marked_sport_map_ready.insert(ifindex);
            state.marked_pdr_map_ready.insert(ifindex);
            state.marked_owner_map_ready.insert(ifindex);
            state.downlink_binding_map_ready.insert(ifindex);
            state.downlink_binding_counters_map_ready.insert(ifindex);
            state.pmtu_map_ready.insert(ifindex);
            state.pmtu_counters_map_ready.insert(ifindex);
            state.uplink_filter_ready.insert(ifindex);
            state.downlink_filter_ready.insert(ifindex);
            // The additive MTU policy slot persists across restarts; only a
            // fresh provisioning initializes the explicit unset state.
            state
                .pmtu_policy
                .entry(ifindex)
                .or_insert([0; UPLINK_PMTU_VALUE_LEN]);
            state
                .schema
                .insert(pin_dir.to_path_buf(), FakeSchema::PmtuV5);
            Ok(())
        }

        fn adopt(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            tc_priority: u16,
        ) -> Result<[u8; 4], GtpuError> {
            let mut state = self.state();
            state.operations.push("adopt");
            if state.attached.contains_key(&ifindex) {
                return Err(GtpuError::AlreadyExists);
            }
            Self::validate_schema(&state, pin_dir, ifindex)?;
            let local_ip = *state
                .pinned_config
                .get(pin_dir)
                .ok_or(GtpuError::NotFound)?;
            let source_port_committed = matches!(
                state.schema.get(pin_dir),
                Some(&FakeSchema::SourcePortV4 | &FakeSchema::PmtuV5)
            );
            if source_port_committed {
                Self::recover_incomplete_pdp_commits(&mut state, ifindex, local_ip)?;
                Self::rebuild_owner_index(&mut state, ifindex, local_ip, true)?;
            } else {
                Self::rebuild_owner_index(&mut state, ifindex, local_ip, false)?;
                Self::materialize_legacy_source_port_policies(&mut state, ifindex)?;
                Self::recover_incomplete_pdp_commits(&mut state, ifindex, local_ip)?;
                Self::rebuild_owner_index(&mut state, ifindex, local_ip, true)?;
            }
            if state.pmtu_policy.get(&ifindex).is_some_and(|value| {
                matches!(
                    GtpuUplinkMtuPolicy::decode_map_value(value),
                    UplinkMtuMapState::Corrupt
                )
            }) {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_pmtu_policy_adopt",
                });
            }
            state.attached.insert(
                ifindex,
                FakeAttachment {
                    interface: interface.to_string(),
                    pin_dir: pin_dir.to_path_buf(),
                    tc_priority,
                },
            );
            // Additive schema upgrade: adopting pre-DSCP pins creates the
            // missing map before the datapath becomes available.
            state.dscp_map_ready.insert(ifindex);
            state.marked_far_map_ready.insert(ifindex);
            state.marked_dscp_map_ready.insert(ifindex);
            state.sport_map_ready.insert(ifindex);
            state.marked_sport_map_ready.insert(ifindex);
            state.marked_pdr_map_ready.insert(ifindex);
            state.marked_owner_map_ready.insert(ifindex);
            state.downlink_binding_map_ready.insert(ifindex);
            state.downlink_binding_counters_map_ready.insert(ifindex);
            state.pmtu_map_ready.insert(ifindex);
            state.pmtu_counters_map_ready.insert(ifindex);
            state.uplink_filter_ready.insert(ifindex);
            state.downlink_filter_ready.insert(ifindex);
            state
                .pmtu_policy
                .entry(ifindex)
                .or_insert([0; UPLINK_PMTU_VALUE_LEN]);
            state
                .schema
                .insert(pin_dir.to_path_buf(), FakeSchema::PmtuV5);
            Ok(local_ip)
        }

        fn detach(
            &self,
            _interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            _tc_priority: u16,
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            state.operations.push("detach");
            state.attached.remove(&ifindex);
            state.dscp_map_ready.remove(&ifindex);
            state.marked_far_map_ready.remove(&ifindex);
            state.marked_dscp_map_ready.remove(&ifindex);
            state.sport_map_ready.remove(&ifindex);
            state.marked_sport_map_ready.remove(&ifindex);
            state.marked_pdr_map_ready.remove(&ifindex);
            state.marked_owner_map_ready.remove(&ifindex);
            state.downlink_binding_map_ready.remove(&ifindex);
            state.downlink_binding_counters_map_ready.remove(&ifindex);
            state.pmtu_map_ready.remove(&ifindex);
            state.pmtu_counters_map_ready.remove(&ifindex);
            state.uplink_filter_ready.remove(&ifindex);
            state.downlink_filter_ready.remove(&ifindex);
            state.uplink_filter_foreign.remove(&ifindex);
            state.downlink_filter_foreign.remove(&ifindex);
            state
                .legacy_v2_extra_hooks
                .retain(|(index, _, _)| *index != ifindex);
            state.pin_identity_invalid.remove(&ifindex);
            state.v2_schema_identity_invalid.remove(&ifindex);
            state.schema.remove(pin_dir);
            state.pinned_config.remove(pin_dir);
            state.empty_pin_dirs.remove(pin_dir);
            state.far.retain(|(index, _), _| *index != ifindex);
            state.marked_far.retain(|(index, _), _| *index != ifindex);
            state.dscp.retain(|(index, _), _| *index != ifindex);
            state.marked_dscp.retain(|(index, _), _| *index != ifindex);
            state.sport.retain(|(index, _), _| *index != ifindex);
            state.marked_sport.retain(|(index, _), _| *index != ifindex);
            state.pmtu_policy.remove(&ifindex);
            state.pdr.retain(|(index, _), _| *index != ifindex);
            state.marked_pdr.retain(|(index, _), _| *index != ifindex);
            state
                .downlink_binding
                .retain(|(index, _), _| *index != ifindex);
            state.marked_owner.retain(|(index, _), _| *index != ifindex);
            state
                .marked_owner_by_teid
                .retain(|(index, _), _| *index != ifindex);
            state
                .default_teid_by_ue
                .retain(|(index, _), _| *index != ifindex);
            Ok(())
        }

        fn teardown_drained_v2(
            &self,
            _interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            _tc_priority: u16,
        ) -> Result<DrainedV2TeardownOutcome, GtpuError> {
            let mut state = self.state();
            state.operations.push("teardown_drained_v2");
            let proof_exists = state.v2_teardown_proof.contains(pin_dir);
            if !proof_exists && !state.schema.contains_key(pin_dir) {
                let uplink = Self::fail_if_requested(&mut state, "v2_observe_uplink").map(|()| {
                    (state.uplink_filter_ready.contains(&ifindex)
                        || state.legacy_v2_extra_hooks.iter().any(|(index, hook, _)| {
                            *index == ifindex && *hook == FakeLegacyV2Hook::Egress
                        }))
                    .then_some(())
                });
                let downlink =
                    Self::fail_if_requested(&mut state, "v2_observe_downlink").map(|()| {
                        (state.downlink_filter_ready.contains(&ifindex)
                            || state.legacy_v2_extra_hooks.iter().any(|(index, hook, _)| {
                                *index == ifindex && *hook == FakeLegacyV2Hook::Ingress
                            }))
                        .then_some(())
                    });
                return match (uplink, downlink) {
                    (Err(_), _) | (_, Err(_)) => Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::IndeterminateState,
                    )),
                    (Ok(Some(_)), _) | (_, Ok(Some(_))) => Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::IdentityMismatch,
                    )),
                    (Ok(None), Ok(None)) if state.pinned_config.contains_key(pin_dir) => {
                        Ok(DrainedV2TeardownOutcome::Refused(
                            DrainedV2TeardownRefusal::IdentityMismatch,
                        ))
                    }
                    (Ok(None), Ok(None)) => {
                        if state.empty_pin_dirs.contains(pin_dir)
                            && Self::fail_if_requested(&mut state, "v2_pin_dir_remove").is_ok()
                        {
                            state.empty_pin_dirs.remove(pin_dir);
                        }
                        Ok(DrainedV2TeardownOutcome::AlreadyAbsent)
                    }
                };
            }
            if !proof_exists && state.schema.get(pin_dir).copied() != Some(FakeSchema::BearerV2) {
                return Ok(DrainedV2TeardownOutcome::Refused(
                    DrainedV2TeardownRefusal::NotLegacyV2,
                ));
            }
            if state.pin_identity_invalid.contains(&ifindex)
                || state.v2_schema_identity_invalid.contains(&ifindex)
                || state.uplink_filter_foreign.contains(&ifindex)
                || state.downlink_filter_foreign.contains(&ifindex)
                || state.sport_map_ready.contains(&ifindex)
                || state.marked_sport_map_ready.contains(&ifindex)
                || state.downlink_binding_map_ready.contains(&ifindex)
                || state.downlink_binding_counters_map_ready.contains(&ifindex)
                || state
                    .legacy_v2_extra_hooks
                    .iter()
                    .any(|(index, _, _)| *index == ifindex)
            {
                return Ok(if proof_exists {
                    DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::Indeterminate)
                } else {
                    DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IdentityMismatch)
                });
            }
            if !proof_exists
                && (!state.uplink_filter_ready.contains(&ifindex)
                    || !state.downlink_filter_ready.contains(&ifindex))
            {
                return Ok(DrainedV2TeardownOutcome::Refused(
                    DrainedV2TeardownRefusal::IdentityMismatch,
                ));
            }

            let forwarding_state_present = state.far.keys().any(|(index, _)| *index == ifindex)
                || state.marked_far.keys().any(|(index, _)| *index == ifindex)
                || state.dscp.keys().any(|(index, _)| *index == ifindex)
                || state.marked_dscp.keys().any(|(index, _)| *index == ifindex)
                || state.pdr.keys().any(|(index, _)| *index == ifindex)
                || state.marked_pdr.keys().any(|(index, _)| *index == ifindex)
                || state
                    .marked_owner
                    .keys()
                    .any(|(index, _)| *index == ifindex);
            if forwarding_state_present {
                return Ok(if proof_exists {
                    DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::PopulatedStateObserved,
                    )
                } else {
                    DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::PopulatedState)
                });
            }

            if !proof_exists {
                let complete_v2_pins = state
                    .pinned_config
                    .get(pin_dir)
                    .is_some_and(|local_ip| *local_ip != [0; 4])
                    && state.dscp_map_ready.contains(&ifindex)
                    && state.marked_far_map_ready.contains(&ifindex)
                    && state.marked_dscp_map_ready.contains(&ifindex)
                    && state.marked_pdr_map_ready.contains(&ifindex)
                    && state.marked_owner_map_ready.contains(&ifindex);
                if !complete_v2_pins {
                    return Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::IndeterminateState,
                    ));
                }
                if Self::fail_if_requested(&mut state, "v2_proof_commit").is_err() {
                    return Ok(DrainedV2TeardownOutcome::Refused(
                        DrainedV2TeardownRefusal::IndeterminateState,
                    ));
                }
                state.v2_teardown_proof.insert(pin_dir.to_path_buf());
                state
                    .v2_pins_remaining
                    .insert(pin_dir.to_path_buf(), LEGACY_V2_PIN_COUNT);
                if Self::fail_if_requested(&mut state, "v2_proof_readback").is_err() {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::Indeterminate,
                    ));
                }
            }

            if state
                .v2_pins_remaining
                .get(pin_dir)
                .is_some_and(|remaining| *remaining < LEGACY_V2_PIN_COUNT)
                && (state.uplink_filter_ready.contains(&ifindex)
                    || state.downlink_filter_ready.contains(&ifindex))
            {
                return Ok(DrainedV2TeardownOutcome::Partial(
                    DrainedV2TeardownProgress::Indeterminate,
                ));
            }

            if state.uplink_filter_ready.contains(&ifindex) {
                if Self::fail_if_requested(&mut state, "v2_detach_uplink").is_err() {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        if state.downlink_filter_ready.contains(&ifindex) {
                            DrainedV2TeardownProgress::ProofCommitted
                        } else {
                            DrainedV2TeardownProgress::OneHookDetached
                        },
                    ));
                }
                state.uplink_filter_ready.remove(&ifindex);
            }
            if state.downlink_filter_ready.contains(&ifindex) {
                if Self::fail_if_requested(&mut state, "v2_detach_downlink").is_err() {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        DrainedV2TeardownProgress::OneHookDetached,
                    ));
                }
                state.downlink_filter_ready.remove(&ifindex);
            }

            loop {
                let remaining = state.v2_pins_remaining.get(pin_dir).copied().unwrap_or(0);
                if remaining == 0 {
                    break;
                }
                let operation = if remaining + 1 == LEGACY_V2_PIN_COUNT {
                    "v2_pin_remove_after_one"
                } else {
                    "v2_pin_remove"
                };
                if Self::fail_if_requested(&mut state, operation).is_err() {
                    return Ok(DrainedV2TeardownOutcome::Partial(
                        if remaining == LEGACY_V2_PIN_COUNT {
                            DrainedV2TeardownProgress::HooksDetached
                        } else {
                            DrainedV2TeardownProgress::PinCleanupStarted
                        },
                    ));
                }
                state
                    .v2_pins_remaining
                    .insert(pin_dir.to_path_buf(), remaining - 1);
            }
            state.schema.remove(pin_dir);
            state.pinned_config.remove(pin_dir);
            state.dscp_map_ready.remove(&ifindex);
            state.marked_far_map_ready.remove(&ifindex);
            state.marked_dscp_map_ready.remove(&ifindex);
            state.marked_pdr_map_ready.remove(&ifindex);
            state.marked_owner_map_ready.remove(&ifindex);
            state.v2_schema_identity_invalid.remove(&ifindex);
            if Self::fail_if_requested(&mut state, "v2_proof_only_inventory").is_err() {
                return Ok(DrainedV2TeardownOutcome::Partial(
                    DrainedV2TeardownProgress::Indeterminate,
                ));
            }
            if Self::fail_if_requested(&mut state, "v2_proof_remove").is_err() {
                return Ok(DrainedV2TeardownOutcome::Partial(
                    DrainedV2TeardownProgress::PinCleanupStarted,
                ));
            }
            state.v2_teardown_proof.remove(pin_dir);
            state.v2_pins_remaining.remove(pin_dir);
            // Once hooks, maps, and proof are gone, directory cleanup is
            // cosmetic and cannot turn terminal success into retryable state.
            if Self::fail_if_requested(&mut state, "v2_pin_dir_remove").is_err() {
                state.empty_pin_dirs.insert(pin_dir.to_path_buf());
            } else {
                state.empty_pin_dirs.remove(pin_dir);
            }
            Ok(DrainedV2TeardownOutcome::Removed)
        }

        fn far_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; UPLINK_FAR_VALUE_LEN]>, GtpuError> {
            Ok(self.state().far.get(&(ifindex, key)).copied())
        }

        fn far_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; UPLINK_FAR_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            state.operations.push("far_insert");
            Self::fail_if_requested(&mut state, "far_insert")?;
            state.far.insert((ifindex, key), value);
            Self::crash_if_requested(&mut state, "far_insert");
            Ok(())
        }

        fn far_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            state.operations.push("far_remove");
            Self::fail_if_requested(&mut state, "far_remove")?;
            let existed = state.far.remove(&(ifindex, key)).is_some();
            Self::crash_if_requested(&mut state, "far_remove");
            Ok(existed)
        }

        fn marked_far_get(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<Option<[u8; UPLINK_FAR_VALUE_LEN]>, GtpuError> {
            let state = self.state();
            if !state.marked_far_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_far_map",
                    io::Error::new(io::ErrorKind::NotFound, "marked FAR map unavailable"),
                ));
            }
            Ok(state.marked_far.get(&(ifindex, key)).copied())
        }

        fn marked_far_insert(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
            value: [u8; UPLINK_FAR_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            if !state.marked_far_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_far_map",
                    io::Error::new(io::ErrorKind::NotFound, "marked FAR map unavailable"),
                ));
            }
            state.operations.push("marked_far_insert");
            Self::fail_if_requested(&mut state, "marked_far_insert")?;
            state.marked_far.insert((ifindex, key), value);
            Self::crash_if_requested(&mut state, "marked_far_insert");
            Ok(())
        }

        fn marked_far_remove(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<bool, GtpuError> {
            let mut state = self.state();
            if !state.marked_far_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_far_map",
                    io::Error::new(io::ErrorKind::NotFound, "marked FAR map unavailable"),
                ));
            }
            state.operations.push("marked_far_remove");
            Self::fail_if_requested(&mut state, "marked_far_remove")?;
            let existed = state.marked_far.remove(&(ifindex, key)).is_some();
            Self::crash_if_requested(&mut state, "marked_far_remove");
            Ok(existed)
        }

        fn dscp_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; UPLINK_DSCP_VALUE_LEN]>, GtpuError> {
            let state = self.state();
            if !state.dscp_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_dscp_map",
                    io::Error::new(io::ErrorKind::NotFound, "DSCP map unavailable"),
                ));
            }
            Ok(state.dscp.get(&(ifindex, key)).copied())
        }

        fn dscp_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; UPLINK_DSCP_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            if !state.dscp_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_dscp_map",
                    io::Error::new(io::ErrorKind::NotFound, "DSCP map unavailable"),
                ));
            }
            state.operations.push("dscp_insert");
            Self::fail_if_requested(&mut state, "dscp_insert")?;
            state.dscp.insert((ifindex, key), value);
            Self::crash_if_requested(&mut state, "dscp_insert");
            Ok(())
        }

        fn dscp_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            if !state.dscp_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_dscp_map",
                    io::Error::new(io::ErrorKind::NotFound, "DSCP map unavailable"),
                ));
            }
            state.operations.push("dscp_remove");
            Self::fail_if_requested(&mut state, "dscp_remove")?;
            let existed = state.dscp.remove(&(ifindex, key)).is_some();
            Self::crash_if_requested(&mut state, "dscp_remove");
            Ok(existed)
        }

        fn marked_dscp_get(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<Option<[u8; UPLINK_DSCP_VALUE_LEN]>, GtpuError> {
            let state = self.state();
            if !state.marked_dscp_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_dscp_map",
                    io::Error::new(io::ErrorKind::NotFound, "marked DSCP map unavailable"),
                ));
            }
            Ok(state.marked_dscp.get(&(ifindex, key)).copied())
        }

        fn marked_dscp_insert(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
            value: [u8; UPLINK_DSCP_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            if !state.marked_dscp_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_dscp_map",
                    io::Error::new(io::ErrorKind::NotFound, "marked DSCP map unavailable"),
                ));
            }
            state.operations.push("marked_dscp_insert");
            Self::fail_if_requested(&mut state, "marked_dscp_insert")?;
            state.marked_dscp.insert((ifindex, key), value);
            Self::crash_if_requested(&mut state, "marked_dscp_insert");
            Ok(())
        }

        fn marked_dscp_remove(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<bool, GtpuError> {
            let mut state = self.state();
            if !state.marked_dscp_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_dscp_map",
                    io::Error::new(io::ErrorKind::NotFound, "marked DSCP map unavailable"),
                ));
            }
            state.operations.push("marked_dscp_remove");
            Self::fail_if_requested(&mut state, "marked_dscp_remove")?;
            let existed = state.marked_dscp.remove(&(ifindex, key)).is_some();
            Self::crash_if_requested(&mut state, "marked_dscp_remove");
            Ok(existed)
        }

        fn sport_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; UPLINK_SOURCE_PORT_VALUE_LEN]>, GtpuError> {
            let state = self.state();
            if !state.sport_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_sport_map",
                    io::Error::new(io::ErrorKind::NotFound, "source-port map unavailable"),
                ));
            }
            Ok(state.sport.get(&(ifindex, key)).copied())
        }

        fn sport_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            if !state.sport_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_sport_map",
                    io::Error::new(io::ErrorKind::NotFound, "source-port map unavailable"),
                ));
            }
            let commit = PdpContextCommit::decode(&value);
            let phase_operation = match commit.phase() {
                MarkedBearerOwnerPhase::Pending => "sport_insert_pending",
                MarkedBearerOwnerPhase::Active => "sport_insert_active",
                MarkedBearerOwnerPhase::Removing => "sport_insert_removing",
            };
            state.operations.push("sport_insert");
            Self::fail_if_requested(&mut state, phase_operation)?;
            Self::fail_if_requested(&mut state, "sport_insert")?;
            if key == [0; 4]
                || !commit.is_valid()
                || commit.downlink_binding().ingress_ifindex() != ifindex
            {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_sport_insert",
                });
            }
            if state
                .default_teid_by_ue
                .get(&(ifindex, key))
                .is_some_and(|existing| *existing != commit.local_teid())
                || state
                    .default_teid_by_ue
                    .iter()
                    .any(|((index, existing_ue), existing_teid)| {
                        *index == ifindex
                            && *existing_teid == commit.local_teid()
                            && *existing_ue != key
                    })
                || state
                    .marked_owner_by_teid
                    .contains_key(&(ifindex, commit.local_teid()))
                || state.sport.get(&(ifindex, key)).is_some_and(|existing| {
                    let existing = PdpContextCommit::decode(existing);
                    !existing.is_valid() || existing.local_teid() != commit.local_teid()
                })
            {
                return Err(GtpuError::AlreadyExists);
            }
            state.sport.insert((ifindex, key), value);
            state
                .default_teid_by_ue
                .insert((ifindex, key), commit.local_teid());
            Self::crash_if_requested(&mut state, phase_operation);
            Ok(())
        }

        fn sport_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            if !state.sport_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_sport_map",
                    io::Error::new(io::ErrorKind::NotFound, "source-port map unavailable"),
                ));
            }
            state.operations.push("sport_remove");
            Self::fail_if_requested(&mut state, "sport_remove")?;
            let Some(encoded) = state.sport.get(&(ifindex, key)).copied() else {
                return Ok(false);
            };
            let commit = PdpContextCommit::decode(&encoded);
            if !commit.is_valid()
                || state.default_teid_by_ue.get(&(ifindex, key)) != Some(&commit.local_teid())
            {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_sport_remove",
                });
            }
            state.sport.remove(&(ifindex, key));
            state.default_teid_by_ue.remove(&(ifindex, key));
            Self::crash_if_requested(&mut state, "sport_remove");
            Ok(true)
        }

        fn marked_sport_get(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<Option<[u8; UPLINK_SOURCE_PORT_VALUE_LEN]>, GtpuError> {
            let state = self.state();
            if !state.marked_sport_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_sport_map",
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "marked source-port map unavailable",
                    ),
                ));
            }
            Ok(state.marked_sport.get(&(ifindex, key)).copied())
        }

        fn marked_sport_insert(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
            value: [u8; UPLINK_SOURCE_PORT_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            if !state.marked_sport_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_sport_map",
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "marked source-port map unavailable",
                    ),
                ));
            }
            let selector = UplinkFarKey::decode(&key);
            let commit = PdpContextCommit::decode(&value);
            let phase_operation = match commit.phase() {
                MarkedBearerOwnerPhase::Pending => "marked_sport_insert_pending",
                MarkedBearerOwnerPhase::Active => "marked_sport_insert_active",
                MarkedBearerOwnerPhase::Removing => "marked_sport_insert_removing",
            };
            state.operations.push("marked_sport_insert");
            Self::fail_if_requested(&mut state, phase_operation)?;
            Self::fail_if_requested(&mut state, "marked_sport_insert")?;
            if selector.ue_ip == [0; 4]
                || selector.bearer_mark == [0; 4]
                || !commit.is_valid()
                || commit.downlink_binding().ingress_ifindex() != ifindex
            {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_marked_sport_insert",
                });
            }
            if state
                .marked_owner_by_teid
                .get(&(ifindex, commit.local_teid()))
                .is_some_and(|existing| *existing != key)
                || state
                    .default_teid_by_ue
                    .iter()
                    .any(|((index, _), existing)| {
                        *index == ifindex && *existing == commit.local_teid()
                    })
                || state
                    .marked_sport
                    .get(&(ifindex, key))
                    .is_some_and(|existing| {
                        let existing = PdpContextCommit::decode(existing);
                        !existing.is_valid() || existing.local_teid() != commit.local_teid()
                    })
            {
                return Err(GtpuError::AlreadyExists);
            }
            state.marked_sport.insert((ifindex, key), value);
            state
                .marked_owner_by_teid
                .insert((ifindex, commit.local_teid()), key);
            Self::crash_if_requested(&mut state, phase_operation);
            Ok(())
        }

        fn marked_sport_remove(
            &self,
            ifindex: u32,
            key: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<bool, GtpuError> {
            let mut state = self.state();
            if !state.marked_sport_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_sport_map",
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "marked source-port map unavailable",
                    ),
                ));
            }
            state.operations.push("marked_sport_remove");
            Self::fail_if_requested(&mut state, "marked_sport_remove")?;
            let Some(encoded) = state.marked_sport.get(&(ifindex, key)).copied() else {
                return Ok(false);
            };
            let commit = PdpContextCommit::decode(&encoded);
            if !commit.is_valid()
                || state
                    .marked_owner_by_teid
                    .get(&(ifindex, commit.local_teid()))
                    != Some(&key)
            {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_marked_sport_remove",
                });
            }
            state.marked_sport.remove(&(ifindex, key));
            state
                .marked_owner_by_teid
                .remove(&(ifindex, commit.local_teid()));
            Self::crash_if_requested(&mut state, "marked_sport_remove");
            Ok(true)
        }

        fn pdr_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; DOWNLINK_PDR_VALUE_LEN]>, GtpuError> {
            Ok(self.state().pdr.get(&(ifindex, key)).copied())
        }

        fn pdr_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; DOWNLINK_PDR_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            state.operations.push("pdr_insert");
            Self::fail_if_requested(&mut state, "pdr_insert")?;
            state.pdr.insert((ifindex, key), value);
            Self::crash_if_requested(&mut state, "pdr_insert");
            Ok(())
        }

        fn pdr_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            state.operations.push("pdr_remove");
            Self::fail_if_requested(&mut state, "pdr_remove")?;
            let existed = state.pdr.remove(&(ifindex, key)).is_some();
            Self::crash_if_requested(&mut state, "pdr_remove");
            Ok(existed)
        }

        fn marked_pdr_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>, GtpuError> {
            let state = self.state();
            if !state.marked_pdr_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_pdr_map",
                    io::Error::new(io::ErrorKind::NotFound, "marked PDR map unavailable"),
                ));
            }
            Ok(state.marked_pdr.get(&(ifindex, key)).copied())
        }

        fn marked_pdr_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; MARKED_DOWNLINK_PDR_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            if !state.marked_pdr_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_pdr_map",
                    io::Error::new(io::ErrorKind::NotFound, "marked PDR map unavailable"),
                ));
            }
            state.operations.push("marked_pdr_insert");
            Self::fail_if_requested(&mut state, "marked_pdr_insert")?;
            state.marked_pdr.insert((ifindex, key), value);
            Self::crash_if_requested(&mut state, "marked_pdr_insert");
            Ok(())
        }

        fn marked_pdr_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            if !state.marked_pdr_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_pdr_map",
                    io::Error::new(io::ErrorKind::NotFound, "marked PDR map unavailable"),
                ));
            }
            state.operations.push("marked_pdr_remove");
            Self::fail_if_requested(&mut state, "marked_pdr_remove")?;
            let existed = state.marked_pdr.remove(&(ifindex, key)).is_some();
            Self::crash_if_requested(&mut state, "marked_pdr_remove");
            Ok(existed)
        }

        fn downlink_binding_get(
            &self,
            ifindex: u32,
            key: [u8; 4],
        ) -> Result<Option<[u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]>, GtpuError> {
            let state = self.state();
            if !state.downlink_binding_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_downlink_binding_map",
                    io::Error::new(io::ErrorKind::NotFound, "downlink binding map unavailable"),
                ));
            }
            Ok(state.downlink_binding.get(&(ifindex, key)).copied())
        }

        fn downlink_binding_insert(
            &self,
            ifindex: u32,
            key: [u8; 4],
            value: [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            if !state.downlink_binding_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_downlink_binding_map",
                    io::Error::new(io::ErrorKind::NotFound, "downlink binding map unavailable"),
                ));
            }
            state.operations.push("downlink_binding_insert");
            Self::fail_if_requested(&mut state, "downlink_binding_insert")?;
            let binding = DownlinkEndpointBinding::decode(&value);
            if !binding.is_valid() || binding.ingress_ifindex() != ifindex {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_downlink_binding_insert",
                });
            }
            state.downlink_binding.insert((ifindex, key), value);
            Self::crash_if_requested(&mut state, "downlink_binding_insert");
            Ok(())
        }

        fn downlink_binding_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            if !state.downlink_binding_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_downlink_binding_map",
                    io::Error::new(io::ErrorKind::NotFound, "downlink binding map unavailable"),
                ));
            }
            state.operations.push("downlink_binding_remove");
            Self::fail_if_requested(&mut state, "downlink_binding_remove")?;
            let existed = state.downlink_binding.remove(&(ifindex, key)).is_some();
            Self::crash_if_requested(&mut state, "downlink_binding_remove");
            Ok(existed)
        }

        fn marked_owner_get(
            &self,
            ifindex: u32,
            selector: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<Option<[u8; MARKED_BEARER_OWNER_VALUE_LEN]>, GtpuError> {
            let state = self.state();
            if !state.marked_owner_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_owner_map",
                    io::Error::new(io::ErrorKind::NotFound, "owner map unavailable"),
                ));
            }
            Ok(state.marked_owner.get(&(ifindex, selector)).copied())
        }

        fn marked_owner_insert(
            &self,
            ifindex: u32,
            selector: [u8; UPLINK_MARK_KEY_LEN],
            value: [u8; MARKED_BEARER_OWNER_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            if !state.marked_owner_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_owner_map",
                    io::Error::new(io::ErrorKind::NotFound, "owner map unavailable"),
                ));
            }
            let key = UplinkFarKey::decode(&selector);
            let owner = MarkedBearerOwner::decode(&value);
            let operation = match owner.phase {
                MarkedBearerOwnerPhase::Pending => "marked_owner_insert_pending",
                MarkedBearerOwnerPhase::Active => "marked_owner_insert_active",
                MarkedBearerOwnerPhase::Removing => "marked_owner_insert_removing",
            };
            state.operations.push(operation);
            Self::fail_if_requested(&mut state, operation)?;
            if key.ue_ip == [0; 4]
                || key.bearer_mark == [0; 4]
                || !owner.is_valid()
                || owner.downlink_binding.ingress_ifindex() != ifindex
            {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_marked_owner_insert",
                });
            }
            if state
                .marked_owner_by_teid
                .get(&(ifindex, owner.local_teid))
                .is_some_and(|existing| *existing != selector)
                || state
                    .default_teid_by_ue
                    .iter()
                    .any(|((index, _), existing)| {
                        *index == ifindex && *existing == owner.local_teid
                    })
            {
                return Err(GtpuError::AlreadyExists);
            }
            if state
                .marked_owner
                .get(&(ifindex, selector))
                .is_some_and(|existing| {
                    let existing = MarkedBearerOwner::decode(existing);
                    !existing.is_valid() || existing.local_teid != owner.local_teid
                })
            {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_marked_owner_insert",
                });
            }
            state.marked_owner.insert((ifindex, selector), value);
            state
                .marked_owner_by_teid
                .insert((ifindex, owner.local_teid), selector);
            Self::crash_if_requested(&mut state, operation);
            Ok(())
        }

        fn marked_owner_remove(
            &self,
            ifindex: u32,
            selector: [u8; UPLINK_MARK_KEY_LEN],
        ) -> Result<bool, GtpuError> {
            let mut state = self.state();
            if !state.marked_owner_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_marked_owner_map",
                    io::Error::new(io::ErrorKind::NotFound, "owner map unavailable"),
                ));
            }
            state.operations.push("marked_owner_remove");
            Self::fail_if_requested(&mut state, "marked_owner_remove")?;
            let Some(encoded) = state.marked_owner.get(&(ifindex, selector)).copied() else {
                return Ok(false);
            };
            let owner = MarkedBearerOwner::decode(&encoded);
            if !owner.is_valid()
                || state.marked_owner_by_teid.get(&(ifindex, owner.local_teid)) != Some(&selector)
            {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_marked_owner_remove",
                });
            }
            state.marked_owner.remove(&(ifindex, selector));
            Self::crash_if_requested(&mut state, "marked_owner_remove");
            // The complete-graph commit retains this reservation until its
            // final deletion linearizes removal.
            Ok(true)
        }

        fn marked_owner_for_teid(
            &self,
            ifindex: u32,
            local_teid: [u8; 4],
        ) -> Result<Option<[u8; UPLINK_MARK_KEY_LEN]>, GtpuError> {
            Ok(self
                .state()
                .marked_owner_by_teid
                .get(&(ifindex, local_teid))
                .copied())
        }

        fn default_teid_for_ue(
            &self,
            ifindex: u32,
            ue_ip: [u8; 4],
        ) -> Result<Option<[u8; 4]>, GtpuError> {
            Ok(self
                .state()
                .default_teid_by_ue
                .get(&(ifindex, ue_ip))
                .copied())
        }

        fn default_ue_for_teid(
            &self,
            ifindex: u32,
            local_teid: [u8; 4],
        ) -> Result<Option<[u8; 4]>, GtpuError> {
            Ok(self
                .state()
                .default_teid_by_ue
                .iter()
                .find_map(|((index, ue_ip), teid)| {
                    (*index == ifindex && *teid == local_teid).then_some(*ue_ip)
                }))
        }

        fn default_selector_insert(
            &self,
            ifindex: u32,
            ue_ip: [u8; 4],
            local_teid: [u8; 4],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            Self::fail_if_requested(&mut state, "default_selector_insert")?;
            if ue_ip == [0; 4]
                || local_teid == [0; 4]
                || state
                    .default_teid_by_ue
                    .get(&(ifindex, ue_ip))
                    .is_some_and(|existing| *existing != local_teid)
                || state
                    .default_teid_by_ue
                    .iter()
                    .any(|((index, existing_ue), existing_teid)| {
                        *index == ifindex && *existing_teid == local_teid && *existing_ue != ue_ip
                    })
                || state
                    .marked_owner_by_teid
                    .contains_key(&(ifindex, local_teid))
            {
                return Err(GtpuError::AlreadyExists);
            }
            state
                .default_teid_by_ue
                .insert((ifindex, ue_ip), local_teid);
            Ok(())
        }

        fn default_selector_remove(
            &self,
            ifindex: u32,
            ue_ip: [u8; 4],
            local_teid: [u8; 4],
        ) -> Result<bool, GtpuError> {
            let mut state = self.state();
            Self::fail_if_requested(&mut state, "default_selector_remove")?;
            match state.default_teid_by_ue.get(&(ifindex, ue_ip)) {
                None => Ok(false),
                Some(existing) if *existing == local_teid => {
                    state.default_teid_by_ue.remove(&(ifindex, ue_ip));
                    Ok(true)
                }
                Some(_) => Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_default_selector_remove",
                }),
            }
        }

        fn datapath_snapshot(&self, ifindex: u32) -> Result<EbpfGtpuDatapathSnapshot, GtpuError> {
            let mut state = self.state();
            let exact = state.attached.contains_key(&ifindex)
                && state.dscp_map_ready.contains(&ifindex)
                && state.marked_far_map_ready.contains(&ifindex)
                && state.marked_dscp_map_ready.contains(&ifindex)
                && state.sport_map_ready.contains(&ifindex)
                && state.marked_sport_map_ready.contains(&ifindex)
                && state.pmtu_map_ready.contains(&ifindex)
                && state.pmtu_counters_map_ready.contains(&ifindex)
                && state.marked_pdr_map_ready.contains(&ifindex)
                && state.marked_owner_map_ready.contains(&ifindex)
                && state.downlink_binding_map_ready.contains(&ifindex)
                && state.downlink_binding_counters_map_ready.contains(&ifindex)
                && state.uplink_filter_ready.contains(&ifindex)
                && state.downlink_filter_ready.contains(&ifindex)
                && !state.pin_identity_invalid.contains(&ifindex)
                && !state.uplink_filter_foreign.contains(&ifindex)
                && !state.downlink_filter_foreign.contains(&ifindex);
            if !exact {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_datapath_snapshot",
                });
            }
            state.operations.push("datapath_snapshot");
            Ok(state.datapath_snapshot)
        }

        fn pmtu_policy_get(&self, ifindex: u32) -> Result<[u8; UPLINK_PMTU_VALUE_LEN], GtpuError> {
            let state = self.state();
            if !state.pmtu_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_pmtu_map",
                    io::Error::new(io::ErrorKind::NotFound, "MTU policy map unavailable"),
                ));
            }
            Ok(state.pmtu_policy.get(&ifindex).copied().unwrap_or([0; 4]))
        }

        fn pmtu_policy_write(
            &self,
            ifindex: u32,
            value: [u8; UPLINK_PMTU_VALUE_LEN],
        ) -> Result<(), GtpuError> {
            let mut state = self.state();
            if !state.pmtu_map_ready.contains(&ifindex) {
                return Err(GtpuError::io(
                    "ebpf_pmtu_map",
                    io::Error::new(io::ErrorKind::NotFound, "MTU policy map unavailable"),
                ));
            }
            if matches!(
                GtpuUplinkMtuPolicy::decode_map_value(&value),
                UplinkMtuMapState::Corrupt
            ) {
                return Err(GtpuError::invalid_config(
                    "device.uplink_mtu_policy",
                    "non-canonical MTU policy bytes",
                ));
            }
            state.operations.push("pmtu_policy_write");
            Self::fail_if_requested(&mut state, "pmtu_policy_write")?;
            state.pmtu_policy.insert(ifindex, value);
            Ok(())
        }

        fn probe_environment(&self) -> EbpfEnvironment {
            self.environment
        }

        fn dscp_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.dscp_map_ready.contains(&ifindex)
                && state.uplink_filter_ready.contains(&ifindex)
        }

        fn source_port_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.sport_map_ready.contains(&ifindex)
                && state.marked_sport_map_ready.contains(&ifindex)
                && state.uplink_filter_ready.contains(&ifindex)
        }

        fn pmtu_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.pmtu_map_ready.contains(&ifindex)
                && state.pmtu_counters_map_ready.contains(&ifindex)
                && state.uplink_filter_ready.contains(&ifindex)
        }

        fn bearer_mark_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.marked_far_map_ready.contains(&ifindex)
                && state.marked_dscp_map_ready.contains(&ifindex)
                && state.marked_sport_map_ready.contains(&ifindex)
                && state.marked_pdr_map_ready.contains(&ifindex)
                && state.marked_owner_map_ready.contains(&ifindex)
                && state.downlink_binding_map_ready.contains(&ifindex)
                && state.downlink_binding_counters_map_ready.contains(&ifindex)
                && state.uplink_filter_ready.contains(&ifindex)
                && state.downlink_filter_ready.contains(&ifindex)
        }

        fn downlink_endpoint_binding_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.downlink_binding_map_ready.contains(&ifindex)
                && state.downlink_binding_counters_map_ready.contains(&ifindex)
                && state.downlink_filter_ready.contains(&ifindex)
                && !state.pin_identity_invalid.contains(&ifindex)
                && !state.downlink_filter_foreign.contains(&ifindex)
        }

        fn pdp_readback_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.dscp_map_ready.contains(&ifindex)
                && state.marked_far_map_ready.contains(&ifindex)
                && state.marked_dscp_map_ready.contains(&ifindex)
                && state.sport_map_ready.contains(&ifindex)
                && state.marked_sport_map_ready.contains(&ifindex)
                && state.marked_pdr_map_ready.contains(&ifindex)
                && state.marked_owner_map_ready.contains(&ifindex)
                && state.downlink_binding_map_ready.contains(&ifindex)
                && state.downlink_binding_counters_map_ready.contains(&ifindex)
                && state.uplink_filter_ready.contains(&ifindex)
                && state.downlink_filter_ready.contains(&ifindex)
                && !state.pin_identity_invalid.contains(&ifindex)
                && !state.uplink_filter_foreign.contains(&ifindex)
                && !state.downlink_filter_foreign.contains(&ifindex)
        }

        fn pdp_cleanup_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.dscp_map_ready.contains(&ifindex)
                && state.marked_far_map_ready.contains(&ifindex)
                && state.marked_dscp_map_ready.contains(&ifindex)
                && state.sport_map_ready.contains(&ifindex)
                && state.marked_sport_map_ready.contains(&ifindex)
                && state.marked_pdr_map_ready.contains(&ifindex)
                && state.marked_owner_map_ready.contains(&ifindex)
                && state.downlink_binding_map_ready.contains(&ifindex)
                && !state.pin_identity_invalid.contains(&ifindex)
                && !state.uplink_filter_foreign.contains(&ifindex)
                && !state.downlink_filter_foreign.contains(&ifindex)
        }
    }

    fn teid(value: u32) -> Teid {
        Teid::new(value).unwrap()
    }

    fn create_request() -> CreateGtpDeviceRequest {
        let mut request = CreateGtpDeviceRequest::new("s2bu");
        request.bind_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        request
    }

    fn context() -> GtpPdpContext {
        GtpPdpContext {
            local_teid: teid(0x1000_0001),
            peer_teid: teid(0x2000_0001),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 45, 0, 2)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: S2BU_IFINDEX,
            downlink_source_port_policy: crate::GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
        }
    }

    fn remove_request() -> RemovePdpContextRequest {
        RemovePdpContextRequest {
            local_teid: teid(0x1000_0001),
            link_ifindex: S2BU_IFINDEX,
            gtp_version: GtpVersion::V1,
            address_family: GtpAddressFamily::Ipv4,
        }
    }

    fn marked_context(mark: u32, local_teid: u32, peer_teid: u32) -> GtpPdpContext {
        let mut context = context();
        context.local_teid = teid(local_teid);
        context.peer_teid = teid(peer_teid);
        context.bearer_mark = GtpBearerMark::new(mark);
        context
    }

    fn commit_for_context(
        context: &GtpPdpContext,
        phase: MarkedBearerOwnerPhase,
    ) -> PdpContextCommit {
        let IpAddr::V4(peer_ip) = context.peer_address else {
            panic!("test context must use IPv4");
        };
        let far = UplinkFar {
            peer_ip: peer_ip.octets(),
            local_ip: [192, 0, 2, 1],
            o_teid: context.peer_teid.get().to_be_bytes(),
        };
        let binding = DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv4(peer_ip.octets()),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 1]),
            context.link_ifindex,
            context.downlink_source_port_policy,
        )
        .expect("canonical test binding");
        PdpContextCommit::new(
            context.local_teid.get().to_be_bytes(),
            far,
            context.egress_dscp.map(crate::DscpCodepoint::get),
            binding,
            context.uplink_source_port_policy,
            phase,
        )
        .expect("canonical test commit")
    }

    fn backend_with_fake() -> (EbpfGtpuDataplaneBackend, Arc<FakeRuntime>) {
        let runtime = Arc::new(FakeRuntime::new());
        let backend = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        (backend, runtime)
    }

    fn seed_drained_v2(runtime: &FakeRuntime) -> PathBuf {
        let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
        let mut state = runtime.state();
        state.schema.insert(pin_dir.clone(), FakeSchema::BearerV2);
        state.pinned_config.insert(pin_dir.clone(), [192, 0, 2, 1]);
        state.dscp_map_ready.insert(S2BU_IFINDEX);
        state.marked_far_map_ready.insert(S2BU_IFINDEX);
        state.marked_dscp_map_ready.insert(S2BU_IFINDEX);
        state.marked_pdr_map_ready.insert(S2BU_IFINDEX);
        state.marked_owner_map_ready.insert(S2BU_IFINDEX);
        state.uplink_filter_ready.insert(S2BU_IFINDEX);
        state.downlink_filter_ready.insert(S2BU_IFINDEX);
        pin_dir
    }

    fn drained_v2_request(ifindex: u32) -> DrainedV2TeardownRequest {
        DrainedV2TeardownRequest::new(
            GtpDevice {
                name: "s2bu".to_string(),
                ifindex,
            },
            crate::GtpuV2DrainProof::sessions_and_traffic_drained(),
        )
    }

    #[tokio::test]
    async fn drained_v2_teardown_is_idempotent_and_allows_fresh_v4_provisioning() {
        let (backend, runtime) = backend_with_fake();
        seed_drained_v2(&runtime);

        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Removed
        );
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::AlreadyAbsent
        );
        let device = backend.create_device(create_request()).await.unwrap();
        assert_eq!(device.ifindex, S2BU_IFINDEX);
        let state = runtime.state();
        assert_eq!(
            state
                .schema
                .get(&PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu")),
            Some(&FakeSchema::PmtuV5)
        );
        assert!(state.sport_map_ready.contains(&S2BU_IFINDEX));
        assert!(state.marked_sport_map_ready.contains(&S2BU_IFINDEX));
        assert!(state.pmtu_map_ready.contains(&S2BU_IFINDEX));
        assert!(state.pmtu_counters_map_ready.contains(&S2BU_IFINDEX));
    }

    #[tokio::test]
    async fn drained_v2_teardown_reports_hook_observation_errors_as_indeterminate() {
        for failures in [
            vec!["v2_observe_uplink"],
            vec!["v2_observe_downlink"],
            vec!["v2_observe_uplink", "v2_observe_downlink"],
        ] {
            let (backend, runtime) = backend_with_fake();
            runtime.fail_in_order(failures);
            assert_eq!(
                backend
                    .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                    .await
                    .unwrap(),
                DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IndeterminateState)
            );
        }
    }

    #[tokio::test]
    async fn drained_v2_teardown_refuses_changed_or_managed_interface_identity() {
        let (backend, runtime) = backend_with_fake();
        seed_drained_v2(&runtime);
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX + 1))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::InterfaceIdentityChanged)
        );

        let missing_runtime = Arc::new(FakeRuntime {
            ifindexes: HashMap::new(),
            ..FakeRuntime::new()
        });
        let missing_backend = EbpfGtpuDataplaneBackend::with_runtime(missing_runtime);
        assert_eq!(
            missing_backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::InterfaceIdentityChanged)
        );

        let (managed, _runtime) = backend_with_fake();
        let device = managed.create_device(create_request()).await.unwrap();
        assert_eq!(
            managed
                .teardown_drained_v2(DrainedV2TeardownRequest::new(
                    device,
                    crate::GtpuV2DrainProof::sessions_and_traffic_drained(),
                ))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::ManagedAttachment)
        );
    }

    #[tokio::test]
    async fn drained_v2_teardown_refuses_every_populated_forwarding_map_class() {
        for map_class in 0..7 {
            let (backend, runtime) = backend_with_fake();
            seed_drained_v2(&runtime);
            {
                let mut state = runtime.state();
                match map_class {
                    0 => {
                        state
                            .far
                            .insert((S2BU_IFINDEX, [1; 4]), [2; UPLINK_FAR_VALUE_LEN]);
                    }
                    1 => {
                        state.marked_far.insert(
                            (S2BU_IFINDEX, [1; UPLINK_MARK_KEY_LEN]),
                            [2; UPLINK_FAR_VALUE_LEN],
                        );
                    }
                    2 => {
                        state
                            .dscp
                            .insert((S2BU_IFINDEX, [1; 4]), [2; UPLINK_DSCP_VALUE_LEN]);
                    }
                    3 => {
                        state.marked_dscp.insert(
                            (S2BU_IFINDEX, [1; UPLINK_MARK_KEY_LEN]),
                            [2; UPLINK_DSCP_VALUE_LEN],
                        );
                    }
                    4 => {
                        state
                            .pdr
                            .insert((S2BU_IFINDEX, [1; 4]), [2; DOWNLINK_PDR_VALUE_LEN]);
                    }
                    5 => {
                        state
                            .marked_pdr
                            .insert((S2BU_IFINDEX, [1; 4]), [2; MARKED_DOWNLINK_PDR_VALUE_LEN]);
                    }
                    _ => {
                        state.marked_owner.insert(
                            (S2BU_IFINDEX, [1; UPLINK_MARK_KEY_LEN]),
                            [2; MARKED_BEARER_OWNER_VALUE_LEN],
                        );
                    }
                }
            }
            assert_eq!(
                backend
                    .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                    .await
                    .unwrap(),
                DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::PopulatedState),
                "map class {map_class} must fail closed"
            );
            let state = runtime.state();
            assert!(!state
                .v2_teardown_proof
                .contains(&PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu")));
            assert_eq!(
                state
                    .schema
                    .get(&PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu")),
                Some(&FakeSchema::BearerV2)
            );
        }
    }

    #[tokio::test]
    async fn drained_v2_schema_identity_mismatch_dominates_populated_state() {
        let (backend, runtime) = backend_with_fake();
        let pin_dir = seed_drained_v2(&runtime);
        {
            let mut state = runtime.state();
            state.v2_schema_identity_invalid.insert(S2BU_IFINDEX);
            state
                .pdr
                .insert((S2BU_IFINDEX, [1; 4]), [2; DOWNLINK_PDR_VALUE_LEN]);
        }

        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IdentityMismatch)
        );
        let state = runtime.state();
        assert!(!state.v2_teardown_proof.contains(&pin_dir));
        assert!(state.pdr.contains_key(&(S2BU_IFINDEX, [1; 4])));
    }

    #[tokio::test]
    async fn drained_v2_teardown_refuses_foreign_incomplete_or_non_v2_state() {
        for mutation in 0..6 {
            let (backend, runtime) = backend_with_fake();
            let pin_dir = seed_drained_v2(&runtime);
            {
                let mut state = runtime.state();
                match mutation {
                    0 => {
                        state.uplink_filter_foreign.insert(S2BU_IFINDEX);
                    }
                    1 => {
                        state.pin_identity_invalid.insert(S2BU_IFINDEX);
                    }
                    2 => {
                        state.marked_owner_map_ready.remove(&S2BU_IFINDEX);
                    }
                    3 => {
                        state.sport_map_ready.insert(S2BU_IFINDEX);
                    }
                    4 => {
                        state.marked_sport_map_ready.insert(S2BU_IFINDEX);
                    }
                    _ => {
                        state.schema.insert(pin_dir, FakeSchema::EndpointV3);
                    }
                }
            }
            let outcome = backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                DrainedV2TeardownOutcome::Refused(
                    DrainedV2TeardownRefusal::IdentityMismatch
                        | DrainedV2TeardownRefusal::IndeterminateState
                        | DrainedV2TeardownRefusal::NotLegacyV2
                )
            ));
        }
    }

    #[tokio::test]
    async fn drained_v2_teardown_retries_each_partial_boundary_exactly_once() {
        for (failure, expected) in [
            (
                "v2_detach_uplink",
                DrainedV2TeardownProgress::ProofCommitted,
            ),
            (
                "v2_detach_downlink",
                DrainedV2TeardownProgress::OneHookDetached,
            ),
            ("v2_pin_remove", DrainedV2TeardownProgress::HooksDetached),
            (
                "v2_pin_remove_after_one",
                DrainedV2TeardownProgress::PinCleanupStarted,
            ),
            (
                "v2_proof_remove",
                DrainedV2TeardownProgress::PinCleanupStarted,
            ),
            (
                "v2_proof_only_inventory",
                DrainedV2TeardownProgress::Indeterminate,
            ),
        ] {
            let (backend, runtime) = backend_with_fake();
            seed_drained_v2(&runtime);
            runtime.fail_in_order([failure]);
            assert_eq!(
                backend
                    .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                    .await
                    .unwrap(),
                DrainedV2TeardownOutcome::Partial(expected),
                "failure boundary {failure}"
            );
            assert_eq!(
                backend
                    .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                    .await
                    .unwrap(),
                DrainedV2TeardownOutcome::Removed,
                "retry boundary {failure}"
            );
        }
    }

    #[tokio::test]
    async fn published_proof_with_failed_readback_is_partial_and_fences_current_schema() {
        let (backend, runtime) = backend_with_fake();
        let pin_dir = seed_drained_v2(&runtime);
        runtime.fail_in_order(["v2_proof_readback"]);

        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::Indeterminate)
        );
        assert!(runtime.state().v2_teardown_proof.contains(&pin_dir));
        assert!(matches!(
            backend.create_device(create_request()).await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_legacy_v2_teardown_pending"
            })
        ));
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Removed
        );
    }

    #[tokio::test]
    async fn directory_cleanup_failure_after_proof_removal_is_terminal_success() {
        let (backend, runtime) = backend_with_fake();
        let pin_dir = seed_drained_v2(&runtime);
        runtime.fail_in_order(["v2_pin_dir_remove", "v2_pin_dir_remove"]);

        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Removed
        );
        assert!(runtime.state().empty_pin_dirs.contains(&pin_dir));
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::AlreadyAbsent
        );
        assert!(runtime.state().empty_pin_dirs.contains(&pin_dir));
        let device = backend.create_device(create_request()).await.unwrap();
        assert_eq!(device.ifindex, S2BU_IFINDEX);
    }

    #[tokio::test]
    async fn empty_namespace_is_absent_despite_cosmetic_cleanup_failure_and_foreign_hook() {
        let (backend, runtime) = backend_with_fake();
        let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
        {
            let mut state = runtime.state();
            state.empty_pin_dirs.insert(pin_dir.clone());
            state.uplink_filter_foreign.insert(S2BU_IFINDEX);
        }
        runtime.fail_in_order(["v2_pin_dir_remove"]);

        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::AlreadyAbsent
        );
        let state = runtime.state();
        assert!(state.empty_pin_dirs.contains(&pin_dir));
        assert!(state.uplink_filter_foreign.contains(&S2BU_IFINDEX));
    }

    #[tokio::test]
    async fn pending_teardown_proof_fences_create_and_adopt_until_exact_retry() {
        let (backend, runtime) = backend_with_fake();
        let pin_dir = seed_drained_v2(&runtime);
        runtime.fail_in_order(["v2_proof_remove"]);
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::PinCleanupStarted)
        );
        assert!(runtime.state().v2_teardown_proof.contains(&pin_dir));

        assert!(matches!(
            backend.create_device(create_request()).await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_legacy_v2_teardown_pending"
            })
        ));
        assert!(matches!(
            backend.resolve_device("s2bu").await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_legacy_v2_teardown_pending"
            })
        ));

        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Removed
        );
        let device = backend.create_device(create_request()).await.unwrap();
        backend.remove_device(&device).await.unwrap();
    }

    #[tokio::test]
    async fn drained_v2_teardown_rejects_unproven_absence_and_preserves_proof_on_conflict() {
        let (backend, runtime) = backend_with_fake();
        let pin_dir = seed_drained_v2(&runtime);
        runtime.state().downlink_filter_ready.remove(&S2BU_IFINDEX);
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IdentityMismatch)
        );
        assert!(!runtime.state().v2_teardown_proof.contains(&pin_dir));

        runtime.state().downlink_filter_ready.insert(S2BU_IFINDEX);
        runtime.fail_in_order(["v2_detach_uplink"]);
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::ProofCommitted)
        );
        runtime.state().uplink_filter_foreign.insert(S2BU_IFINDEX);
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::Indeterminate)
        );
        let state = runtime.state();
        assert!(state.v2_teardown_proof.contains(&pin_dir));
        assert_eq!(state.schema.get(&pin_dir), Some(&FakeSchema::BearerV2));
    }

    #[tokio::test]
    async fn drained_v2_teardown_preserves_exact_graph_when_any_legacy_program_extra_exists() {
        for (hook, program) in [
            (FakeLegacyV2Hook::Egress, FakeLegacyV2Program::Uplink),
            (FakeLegacyV2Hook::Egress, FakeLegacyV2Program::Downlink),
            (FakeLegacyV2Hook::Ingress, FakeLegacyV2Program::Downlink),
            (FakeLegacyV2Hook::Ingress, FakeLegacyV2Program::Uplink),
        ] {
            let (backend, runtime) = backend_with_fake();
            let pin_dir = seed_drained_v2(&runtime);
            runtime
                .state()
                .legacy_v2_extra_hooks
                .insert((S2BU_IFINDEX, hook, program));

            assert_eq!(
                backend
                    .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                    .await
                    .unwrap(),
                DrainedV2TeardownOutcome::Refused(DrainedV2TeardownRefusal::IdentityMismatch)
            );
            let state = runtime.state();
            assert!(!state.v2_teardown_proof.contains(&pin_dir));
            assert!(state.uplink_filter_ready.contains(&S2BU_IFINDEX));
            assert!(state.downlink_filter_ready.contains(&S2BU_IFINDEX));
            assert_eq!(state.schema.get(&pin_dir), Some(&FakeSchema::BearerV2));
            assert!(state.pinned_config.contains_key(&pin_dir));
            assert!(state
                .legacy_v2_extra_hooks
                .contains(&(S2BU_IFINDEX, hook, program)));
        }
    }

    #[tokio::test]
    async fn proof_retry_preserves_every_hook_and_pin_when_a_legacy_program_extra_appears() {
        for (hook, program) in [
            (FakeLegacyV2Hook::Egress, FakeLegacyV2Program::Uplink),
            (FakeLegacyV2Hook::Egress, FakeLegacyV2Program::Downlink),
            (FakeLegacyV2Hook::Ingress, FakeLegacyV2Program::Downlink),
            (FakeLegacyV2Hook::Ingress, FakeLegacyV2Program::Uplink),
        ] {
            let (backend, runtime) = backend_with_fake();
            let pin_dir = seed_drained_v2(&runtime);
            runtime.fail_in_order(["v2_detach_uplink"]);
            assert_eq!(
                backend
                    .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                    .await
                    .unwrap(),
                DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::ProofCommitted)
            );
            runtime
                .state()
                .legacy_v2_extra_hooks
                .insert((S2BU_IFINDEX, hook, program));

            assert_eq!(
                backend
                    .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                    .await
                    .unwrap(),
                DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::Indeterminate)
            );
            let state = runtime.state();
            assert!(state.v2_teardown_proof.contains(&pin_dir));
            assert_eq!(
                state.v2_pins_remaining.get(&pin_dir),
                Some(&LEGACY_V2_PIN_COUNT)
            );
            assert!(state.uplink_filter_ready.contains(&S2BU_IFINDEX));
            assert!(state.downlink_filter_ready.contains(&S2BU_IFINDEX));
            assert!(state
                .legacy_v2_extra_hooks
                .contains(&(S2BU_IFINDEX, hook, program)));
        }
    }

    #[tokio::test]
    async fn retry_reports_started_cleanup_when_the_first_remaining_pin_unlink_fails() {
        let (backend, runtime) = backend_with_fake();
        let pin_dir = seed_drained_v2(&runtime);
        {
            let mut state = runtime.state();
            state.v2_teardown_proof.insert(pin_dir.clone());
            state
                .v2_pins_remaining
                .insert(pin_dir.clone(), LEGACY_V2_PIN_COUNT - 1);
            state.uplink_filter_ready.remove(&S2BU_IFINDEX);
            state.downlink_filter_ready.remove(&S2BU_IFINDEX);
        }
        runtime.fail_in_order(["v2_pin_remove_after_one"]);

        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::PinCleanupStarted)
        );
        let state = runtime.state();
        assert!(state.v2_teardown_proof.contains(&pin_dir));
        assert_eq!(
            state.v2_pins_remaining.get(&pin_dir),
            Some(&(LEGACY_V2_PIN_COUNT - 1))
        );
    }

    #[tokio::test]
    async fn drained_v2_teardown_refuses_repopulation_after_partial_pin_cleanup() {
        let (backend, runtime) = backend_with_fake();
        let pin_dir = seed_drained_v2(&runtime);
        runtime.fail_in_order(["v2_pin_remove_after_one"]);
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::PinCleanupStarted)
        );
        let remaining_before = runtime.state().v2_pins_remaining.get(&pin_dir).copied();
        runtime
            .state()
            .pdr
            .insert((S2BU_IFINDEX, [9; 4]), [7; DOWNLINK_PDR_VALUE_LEN]);

        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Partial(DrainedV2TeardownProgress::PopulatedStateObserved)
        );
        {
            let state = runtime.state();
            assert_eq!(
                state.v2_pins_remaining.get(&pin_dir).copied(),
                remaining_before
            );
            assert!(state.pdr.contains_key(&(S2BU_IFINDEX, [9; 4])));
        }
        runtime.state().pdr.remove(&(S2BU_IFINDEX, [9; 4]));
        assert_eq!(
            backend
                .teardown_drained_v2(drained_v2_request(S2BU_IFINDEX))
                .await
                .unwrap(),
            DrainedV2TeardownOutcome::Removed
        );
    }

    #[tokio::test]
    async fn create_device_attaches_to_existing_interface() {
        let (backend, runtime) = backend_with_fake();
        let device = backend.create_device(create_request()).await.unwrap();
        assert_eq!(device.name, "s2bu");
        assert_eq!(device.ifindex, S2BU_IFINDEX);

        let state = runtime.state();
        let attachment = state.attached.get(&S2BU_IFINDEX).unwrap();
        assert_eq!(attachment.interface, "s2bu");
        assert_eq!(
            attachment.pin_dir,
            PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu")
        );
        assert_eq!(attachment.tc_priority, DEFAULT_TC_PRIORITY);
        assert_eq!(
            state.pinned_config.get(&attachment.pin_dir),
            Some(&[192, 0, 2, 1])
        );
    }

    #[tokio::test]
    async fn datapath_snapshot_returns_exact_identity_bound_counters() {
        let (backend, runtime) = backend_with_fake();
        let expected = EbpfGtpuDatapathSnapshot {
            uplink_program_id: 101,
            downlink_program_id: 102,
            counters_map_id: 201,
            downlink_binding_counters_map_id: 202,
            counters: EbpfGtpuDatapathCounters {
                uplink_encapsulated: 11,
                uplink_far_misses: 12,
                downlink_decapsulated: 13,
                downlink_unknown_teid: 14,
                downlink_malformed: 15,
                downlink_destination_mismatches: 16,
                downlink_binding_invalid: 17,
                downlink_binding_family_mismatches: 18,
                downlink_binding_peer_mismatches: 19,
                downlink_binding_local_mismatches: 20,
                downlink_binding_ingress_mismatches: 21,
                downlink_binding_source_port_mismatches: 22,
                uplink_mtu_rejected: 23,
                uplink_mtu_policy_corrupt: 24,
            },
        };
        runtime.state().datapath_snapshot = expected;
        let device = backend.create_device(create_request()).await.unwrap();

        assert_eq!(backend.datapath_snapshot(&device).await.unwrap(), expected);
        assert_eq!(
            runtime.state().operations.last(),
            Some(&"datapath_snapshot")
        );
    }

    #[tokio::test]
    async fn datapath_snapshot_rejects_unmanaged_or_identity_lost_devices() {
        let (backend, runtime) = backend_with_fake();
        let device = backend.create_device(create_request()).await.unwrap();
        let unknown = GtpDevice {
            name: device.name.clone(),
            ifindex: device.ifindex + 1,
        };
        assert!(matches!(
            backend.datapath_snapshot(&unknown).await.unwrap_err(),
            GtpuError::NotFound
        ));

        runtime.state().pin_identity_invalid.insert(device.ifindex);
        assert!(matches!(
            backend.datapath_snapshot(&device).await.unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_datapath_snapshot"
            }
        ));
    }

    #[tokio::test]
    async fn create_device_rejects_missing_interface_and_duplicates() {
        let (backend, _runtime) = backend_with_fake();
        let mut missing = create_request();
        missing.name = "nope0".to_string();
        assert!(matches!(
            backend.create_device(missing).await.unwrap_err(),
            GtpuError::NotFound
        ));

        backend.create_device(create_request()).await.unwrap();
        assert!(matches!(
            backend.create_device(create_request()).await.unwrap_err(),
            GtpuError::AlreadyExists
        ));
    }

    #[tokio::test]
    async fn create_device_requires_concrete_ipv4_bind_address() {
        let (backend, _runtime) = backend_with_fake();

        let mut unspecified = create_request();
        unspecified.bind_address = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert!(matches!(
            backend.create_device(unspecified).await.unwrap_err(),
            GtpuError::InvalidConfig { field, .. } if field == "device.bind_address"
        ));

        let mut ipv6 = create_request();
        ipv6.bind_address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(matches!(
            backend.create_device(ipv6).await.unwrap_err(),
            GtpuError::InvalidConfig { field, .. } if field == "device.bind_address"
        ));
    }

    #[tokio::test]
    async fn install_writes_both_map_directions_with_exact_layouts() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();

        let state = runtime.state();
        let far = state
            .far
            .get(&(S2BU_IFINDEX, [10, 45, 0, 2]))
            .expect("uplink FAR keyed by UE PAA");
        assert_eq!(
            UplinkFar::decode(far),
            UplinkFar {
                peer_ip: [192, 0, 2, 10],
                local_ip: [192, 0, 2, 1],
                o_teid: 0x2000_0001_u32.to_be_bytes(),
            }
        );
        let pdr = state
            .pdr
            .get(&(S2BU_IFINDEX, 0x1000_0001_u32.to_be_bytes()))
            .expect("downlink PDR keyed by local TEID");
        assert_eq!(DownlinkPdr::decode(pdr).ue_ip, [10, 45, 0, 2]);
        let binding = DownlinkEndpointBinding::decode(
            state
                .downlink_binding
                .get(&(S2BU_IFINDEX, 0x1000_0001_u32.to_be_bytes()))
                .expect("downlink binding keyed by local TEID"),
        );
        assert!(binding.is_valid());
        assert_eq!(
            binding.peer_address(),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 10])
        );
        assert_eq!(
            binding.local_address(),
            GtpuEndpointAddress::Ipv4([192, 0, 2, 1])
        );
        assert_eq!(binding.ingress_ifindex(), S2BU_IFINDEX);
        assert_eq!(
            binding.source_port_policy(),
            crate::GtpuSourcePortPolicy::Any
        );
    }

    #[tokio::test]
    async fn install_is_idempotent_for_identical_state() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();

        let state = runtime.state();
        assert_eq!(state.far.len(), 1);
        assert_eq!(state.pdr.len(), 1);
        assert_eq!(
            state
                .operations
                .iter()
                .filter(|operation| **operation == "far_insert")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn install_persists_each_explicit_source_port_policy() {
        for policy in [
            crate::GtpuSourcePortPolicy::Any,
            crate::GtpuSourcePortPolicy::Exact(21_152),
            crate::GtpuSourcePortPolicy::inclusive_range(20_000, 21_000).unwrap(),
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut requested = context();
            requested.downlink_source_port_policy = policy;
            backend.install_pdp_context(requested).await.unwrap();

            let binding = DownlinkEndpointBinding::decode(
                runtime
                    .state()
                    .downlink_binding
                    .get(&(S2BU_IFINDEX, 0x1000_0001_u32.to_be_bytes()))
                    .expect("source-port policy binding"),
            );
            assert_eq!(binding.source_port_policy(), policy);
        }
    }

    #[tokio::test]
    async fn failed_default_relocation_retains_only_the_old_authorized_peer() {
        for failure in [
            "dscp_insert",
            "sport_insert",
            "far_insert",
            "downlink_binding_insert",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let original = context();
            backend.install_pdp_context(original.clone()).await.unwrap();

            let mut relocated = original.clone();
            relocated.peer_teid = teid(0x3000_0003);
            relocated.peer_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
            relocated.downlink_source_port_policy = crate::GtpuSourcePortPolicy::Exact(21_152);
            relocated.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            relocated.uplink_source_port_policy = selected_source_port(40_000);
            runtime.fail_in_order([failure]);

            assert!(matches!(
                backend
                    .install_pdp_context(relocated)
                    .await
                    .unwrap_err(),
                GtpuError::Io { operation, .. } if operation == failure
            ));
            let state = runtime.state();
            let far = UplinkFar::decode(
                state
                    .far
                    .get(&(S2BU_IFINDEX, [10, 45, 0, 2]))
                    .expect("old FAR restored"),
            );
            let binding = DownlinkEndpointBinding::decode(
                state
                    .downlink_binding
                    .get(&(S2BU_IFINDEX, 0x1000_0001_u32.to_be_bytes()))
                    .expect("old binding retained"),
            );
            assert_eq!(far.peer_ip, [192, 0, 2, 10], "{failure}");
            assert_eq!(far.o_teid, 0x2000_0001_u32.to_be_bytes(), "{failure}");
            assert_eq!(
                binding.peer_address(),
                GtpuEndpointAddress::Ipv4([192, 0, 2, 10]),
                "{failure}"
            );
            assert_eq!(
                binding.source_port_policy(),
                crate::GtpuSourcePortPolicy::Any,
                "{failure}"
            );
            assert!(state.dscp.is_empty(), "{failure}");
            assert_eq!(
                state.sport.get(&(S2BU_IFINDEX, [10, 45, 0, 2])),
                Some(&commit_for_context(&original, MarkedBearerOwnerPhase::Active).encode()),
                "{failure}"
            );
            assert_eq!(state.pdr.len(), 1, "{failure}");
        }
    }

    #[tokio::test]
    async fn failed_marked_relocation_retains_only_the_old_active_peer() {
        for failure in [
            "marked_dscp_insert",
            "marked_sport_insert",
            "marked_far_insert",
            "downlink_binding_insert",
            "marked_owner_insert_active",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut original = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            original.egress_dscp = Some(crate::DscpCodepoint::new(10).unwrap());
            backend.install_pdp_context(original.clone()).await.unwrap();

            let mut relocated = original.clone();
            relocated.peer_teid = teid(0x3000_0003);
            relocated.peer_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
            relocated.downlink_source_port_policy = crate::GtpuSourcePortPolicy::Exact(21_152);
            relocated.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            relocated.uplink_source_port_policy = selected_source_port(40_000);
            runtime.fail_in_order([failure]);

            assert!(matches!(
                backend
                    .install_pdp_context(relocated)
                    .await
                    .unwrap_err(),
                GtpuError::Io { operation, .. } if operation == failure
            ));
            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: 0x1001_u32.to_be_bytes(),
            }
            .encode();
            let state = runtime.state();
            let owner = MarkedBearerOwner::decode(
                state
                    .marked_owner
                    .get(&(S2BU_IFINDEX, selector))
                    .expect("old active owner retained"),
            );
            assert_eq!(owner.phase, MarkedBearerOwnerPhase::Active, "{failure}");
            assert_eq!(owner.uplink_far.peer_ip, [192, 0, 2, 10], "{failure}");
            assert_eq!(owner.egress_dscp(), Some(10), "{failure}");
            assert_eq!(
                owner.downlink_binding.peer_address(),
                GtpuEndpointAddress::Ipv4([192, 0, 2, 10]),
                "{failure}"
            );
            assert_eq!(
                state
                    .downlink_binding
                    .get(&(S2BU_IFINDEX, original.local_teid.get().to_be_bytes())),
                Some(&owner.downlink_binding.encode()),
                "{failure}"
            );
            assert_eq!(
                state.marked_far.get(&(S2BU_IFINDEX, selector)),
                Some(&owner.uplink_far.encode()),
                "{failure}"
            );
            assert_eq!(
                state.marked_dscp.get(&(S2BU_IFINDEX, selector)),
                Some(&[10]),
                "{failure}"
            );
            assert_eq!(
                state.marked_sport.get(&(S2BU_IFINDEX, selector)),
                Some(&commit_for_context(&original, MarkedBearerOwnerPhase::Active).encode()),
                "{failure}"
            );
        }
    }

    #[tokio::test]
    async fn install_stages_dscp_before_routing_and_records_exact_codepoint() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        runtime.state().operations.clear();

        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        backend.install_pdp_context(marked).await.unwrap();

        let state = runtime.state();
        assert_eq!(
            state.operations,
            vec![
                "sport_insert",
                "dscp_insert",
                "far_insert",
                "downlink_binding_insert",
                "pdr_insert",
                "sport_insert"
            ]
        );
        assert_eq!(state.dscp.get(&(S2BU_IFINDEX, [10, 45, 0, 2])), Some(&[46]));
    }

    #[tokio::test]
    async fn crash_restart_reconciles_dscp_only_publication_orphan() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        {
            let mut state = runtime.state();
            // Model a crash after DSCP publication and before FAR insertion.
            state.dscp.insert((S2BU_IFINDEX, [10, 45, 0, 2]), [10]);
            state.attached.clear();
            state.operations.clear();
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        restarted.resolve_device("s2bu").await.unwrap();
        runtime.state().operations.clear();
        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        restarted.install_pdp_context(marked).await.unwrap();

        let state = runtime.state();
        assert_eq!(
            state.operations,
            vec![
                "sport_insert",
                "dscp_insert",
                "far_insert",
                "downlink_binding_insert",
                "pdr_insert",
                "sport_insert"
            ]
        );
        assert_eq!(state.dscp.get(&(S2BU_IFINDEX, [10, 45, 0, 2])), Some(&[46]));
        assert_eq!(state.far.len(), 1);
        assert_eq!(state.pdr.len(), 1);
    }

    #[tokio::test]
    async fn one_sided_far_or_pdr_state_is_indeterminate() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();

        runtime.state().pdr.clear();
        assert!(matches!(
            backend.install_pdp_context(context()).await.unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context"
            }
        ));

        {
            let mut state = runtime.state();
            state.far.clear();
            state.pdr.insert(
                (S2BU_IFINDEX, 0x1000_0001_u32.to_be_bytes()),
                DownlinkPdr {
                    ue_ip: [10, 45, 0, 2],
                }
                .encode(),
            );
        }
        assert!(matches!(
            backend.install_pdp_context(context()).await.unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context"
            }
        ));
    }

    #[tokio::test]
    async fn exact_session_reconciles_dscp_only_changes_atomically() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();
        runtime.state().operations.clear();

        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(10).unwrap());
        backend.install_pdp_context(marked.clone()).await.unwrap();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        backend.install_pdp_context(marked).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();

        let state = runtime.state();
        assert_eq!(
            state.operations,
            vec![
                "sport_insert",
                "dscp_insert",
                "far_insert",
                "downlink_binding_insert",
                "pdr_insert",
                "sport_insert",
                "sport_insert",
                "dscp_insert",
                "far_insert",
                "downlink_binding_insert",
                "pdr_insert",
                "sport_insert",
                "sport_insert",
                "dscp_remove",
                "far_insert",
                "downlink_binding_insert",
                "pdr_insert",
                "sport_insert",
            ]
        );
        assert!(state.dscp.is_empty());
        assert_eq!(state.far.len(), 1);
        assert_eq!(state.pdr.len(), 1);
    }

    #[tokio::test]
    async fn failed_pdr_insert_rolls_back_routing_before_dscp() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        runtime.state().operations.clear();
        runtime.fail_in_order(["pdr_insert"]);
        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());

        assert!(matches!(
            backend.install_pdp_context(marked).await.unwrap_err(),
            GtpuError::Io {
                operation: "pdr_insert",
                ..
            }
        ));
        let state = runtime.state();
        assert_eq!(
            state.operations,
            vec![
                "sport_insert",
                "dscp_insert",
                "far_insert",
                "downlink_binding_insert",
                "pdr_insert",
                "sport_insert",
                "far_remove",
                "dscp_remove",
                "downlink_binding_remove",
                "pdr_remove",
                "sport_remove"
            ]
        );
        assert!(state.far.is_empty());
        assert!(state.pdr.is_empty());
        assert!(state.dscp.is_empty());
    }

    #[tokio::test]
    async fn failed_install_rollback_reports_indeterminate_state() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        runtime.fail_in_order(["pdr_insert", "far_remove"]);
        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());

        assert!(matches!(
            backend.install_pdp_context(marked).await.unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context"
            }
        ));
    }

    #[tokio::test]
    async fn install_relocates_exact_identity_and_rejects_a_conflicting_selector() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();

        // The same UE/local-TEID identity may relocate to a new peer. The
        // binding-map replacement is the downlink authorization cutover.
        let mut relocated = context();
        relocated.peer_teid = teid(0x3000_0003);
        relocated.peer_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        backend.install_pdp_context(relocated).await.unwrap();
        {
            let state = runtime.state();
            let far = UplinkFar::decode(
                state
                    .far
                    .get(&(S2BU_IFINDEX, [10, 45, 0, 2]))
                    .expect("relocated FAR"),
            );
            let binding = DownlinkEndpointBinding::decode(
                state
                    .downlink_binding
                    .get(&(S2BU_IFINDEX, 0x1000_0001_u32.to_be_bytes()))
                    .expect("relocated binding"),
            );
            assert_eq!(far.peer_ip, [192, 0, 2, 20]);
            assert_eq!(far.o_teid, 0x3000_0003_u32.to_be_bytes());
            assert_eq!(
                binding.peer_address(),
                GtpuEndpointAddress::Ipv4([192, 0, 2, 20])
            );
        }

        // Same local TEID, different UE PAA.
        let mut conflicting_paa = context();
        conflicting_paa.ms_address = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 3));
        assert!(matches!(
            backend
                .install_pdp_context(conflicting_paa)
                .await
                .unwrap_err(),
            GtpuError::AlreadyExists
        ));
    }

    #[tokio::test]
    async fn install_validates_addresses_and_managed_interface() {
        let (backend, _runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();

        let mut ipv6 = context();
        ipv6.ms_address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(matches!(
            backend.install_pdp_context(ipv6).await.unwrap_err(),
            GtpuError::InvalidConfig { field, .. } if field == "pdp.ms_address"
        ));

        let mut ipv6_peer = context();
        ipv6_peer.peer_address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(matches!(
            backend.install_pdp_context(ipv6_peer).await.unwrap_err(),
            GtpuError::InvalidConfig { field, .. } if field == "pdp.peer_address"
        ));

        let mut loops = context();
        loops.ms_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(matches!(
            backend.install_pdp_context(loops).await.unwrap_err(),
            GtpuError::InvalidConfig { field, .. } if field == "pdp.ms_address"
        ));

        let mut unmanaged = context();
        unmanaged.link_ifindex = 999;
        assert!(matches!(
            backend.install_pdp_context(unmanaged).await.unwrap_err(),
            GtpuError::NotFound
        ));
    }

    #[tokio::test]
    async fn remove_deletes_both_directions_and_is_idempotent() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        backend.install_pdp_context(marked).await.unwrap();
        runtime.state().operations.clear();

        let remove = remove_request();
        backend.remove_pdp_context(remove.clone()).await.unwrap();
        {
            let state = runtime.state();
            assert!(state.far.is_empty());
            assert!(state.pdr.is_empty());
            assert!(state.dscp.is_empty());
            assert!(state.sport.is_empty());
            assert_eq!(
                state.operations,
                vec![
                    "sport_insert",
                    "far_remove",
                    "dscp_remove",
                    "downlink_binding_remove",
                    "pdr_remove",
                    "sport_remove"
                ]
            );
        }
        // Removing an absent context is idempotent success.
        backend.remove_pdp_context(remove).await.unwrap();
    }

    #[tokio::test]
    async fn failed_default_removal_is_cleaned_to_absence_on_restart() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        backend.install_pdp_context(marked).await.unwrap();
        runtime.state().operations.clear();
        runtime.fail_in_order(["dscp_remove"]);

        assert!(matches!(
            backend
                .remove_pdp_context(remove_request())
                .await
                .unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context"
            }
        ));
        {
            let mut state = runtime.state();
            assert!(state.far.is_empty(), "FAR must be disabled first");
            assert_eq!(state.dscp.len(), 1, "failed DSCP delete remains retryable");
            assert_eq!(state.pdr.len(), 1, "PDR retains the UE-key journal");
            assert_eq!(
                state.downlink_binding.len(),
                1,
                "binding remains paired with the PDR"
            );
            state.attached.clear();
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        restarted.resolve_device("s2bu").await.unwrap();
        let state = runtime.state();
        assert!(state.far.is_empty());
        assert!(state.dscp.is_empty());
        assert!(state.pdr.is_empty());
        assert!(state.downlink_binding.is_empty());
        assert!(state.sport.is_empty());
    }

    #[tokio::test]
    async fn concurrent_relocations_never_publish_mixed_subresources() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();

        let mut first = context();
        first.egress_dscp = Some(crate::DscpCodepoint::new(10).unwrap());
        let mut second = context();
        second.peer_teid = teid(0x3000_0003);
        second.peer_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        second.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let first_task = {
            let backend = backend.clone();
            let barrier = barrier.clone();
            tokio::task::spawn_blocking(move || {
                barrier.wait();
                backend.install_pdp_context_sync(first)
            })
        };
        let second_task = {
            let backend = backend.clone();
            let barrier = barrier.clone();
            tokio::task::spawn_blocking(move || {
                barrier.wait();
                backend.install_pdp_context_sync(second)
            })
        };
        barrier.wait();
        let first_result = first_task.await.unwrap();
        let second_result = second_task.await.unwrap();
        assert!(first_result.is_ok());
        assert!(second_result.is_ok());

        let state = runtime.state();
        let far = UplinkFar::decode(
            state
                .far
                .get(&(S2BU_IFINDEX, [10, 45, 0, 2]))
                .expect("winning FAR"),
        );
        let dscp = state
            .dscp
            .get(&(S2BU_IFINDEX, [10, 45, 0, 2]))
            .expect("winning DSCP")[0];
        let binding = DownlinkEndpointBinding::decode(
            state
                .downlink_binding
                .get(&(S2BU_IFINDEX, 0x1000_0001_u32.to_be_bytes()))
                .expect("winning binding"),
        );
        assert!(
            (far.o_teid == 0x2000_0001_u32.to_be_bytes()
                && far.peer_ip == [192, 0, 2, 10]
                && dscp == 10
                && binding.peer_address() == GtpuEndpointAddress::Ipv4([192, 0, 2, 10]))
                || (far.o_teid == 0x3000_0003_u32.to_be_bytes()
                    && far.peer_ip == [192, 0, 2, 20]
                    && dscp == 46
                    && binding.peer_address() == GtpuEndpointAddress::Ipv4([192, 0, 2, 20]))
        );
        assert_eq!(state.pdr.len(), 1);
    }

    #[tokio::test]
    async fn concurrent_install_and_remove_leave_a_complete_state_or_none() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();

        let mut replacement = context();
        replacement.peer_teid = teid(0x3000_0003);
        replacement.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let install_task = {
            let backend = backend.clone();
            let barrier = barrier.clone();
            tokio::task::spawn_blocking(move || {
                barrier.wait();
                backend.install_pdp_context_sync(replacement)
            })
        };
        let remove_task = {
            let backend = backend.clone();
            let barrier = barrier.clone();
            tokio::task::spawn_blocking(move || {
                barrier.wait();
                backend.remove_pdp_context_sync(remove_request())
            })
        };
        barrier.wait();
        let install_result = install_task.await.unwrap();
        remove_task.await.unwrap().unwrap();
        assert!(install_result.is_ok() || matches!(install_result, Err(GtpuError::AlreadyExists)));

        let state = runtime.state();
        if state.pdr.is_empty() {
            assert!(state.far.is_empty());
            assert!(state.dscp.is_empty());
        } else {
            assert_eq!(state.pdr.len(), 1);
            let far = UplinkFar::decode(
                state
                    .far
                    .get(&(S2BU_IFINDEX, [10, 45, 0, 2]))
                    .expect("replacement FAR"),
            );
            assert_eq!(far.o_teid, 0x3000_0003_u32.to_be_bytes());
            assert_eq!(state.dscp.get(&(S2BU_IFINDEX, [10, 45, 0, 2])), Some(&[46]));
        }
    }

    #[tokio::test]
    async fn resolve_device_adopts_restored_state_and_reuses_local_ip() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();

        // Simulate a process restart with surviving pinned state: a fresh
        // backend over the same runtime pins.
        runtime.state().attached.clear();
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        let device = restarted.resolve_device("s2bu").await.unwrap();
        assert_eq!(device.ifindex, S2BU_IFINDEX);

        restarted.install_pdp_context(context()).await.unwrap();
        let state = runtime.state();
        let far = state.far.get(&(S2BU_IFINDEX, [10, 45, 0, 2])).unwrap();
        // The adopted local S2b-U address is stamped into new FAR entries.
        assert_eq!(UplinkFar::decode(far).local_ip, [192, 0, 2, 1]);
    }

    #[tokio::test]
    async fn a_second_live_reconciler_cannot_adopt_the_same_interface() {
        let (first, runtime) = backend_with_fake();
        first.create_device(create_request()).await.unwrap();

        let second = EbpfGtpuDataplaneBackend::with_runtime(runtime);
        assert!(matches!(
            second.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::AlreadyExists
        ));
    }

    #[tokio::test]
    async fn legacy_v0_pin_adoption_commits_endpoint_bound_schema() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        {
            let mut state = runtime.state();
            state.attached.clear();
            state.dscp_map_ready.clear();
            state.marked_far_map_ready.clear();
            state.marked_dscp_map_ready.clear();
            state.marked_pdr_map_ready.clear();
            state.marked_owner_map_ready.clear();
            state.schema.insert(
                PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu"),
                FakeSchema::LegacyV0,
            );
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        restarted.resolve_device("s2bu").await.unwrap();
        let probe = restarted.probe().await.unwrap();
        assert_eq!(probe.egress_dscp_marking, GtpuCapability::Available);
        assert_eq!(probe.downlink_endpoint_binding, GtpuCapability::Available);
        assert_eq!(probe.per_bearer_marking, GtpuCapability::Available);
        let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        restarted.install_pdp_context(marked).await.unwrap();
        let state = runtime.state();
        let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
        assert_eq!(state.schema.get(&pin_dir), Some(&FakeSchema::PmtuV5));
    }

    #[tokio::test]
    async fn endpoint_unbound_v2_schema_requires_drained_reprovisioning() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        {
            let mut state = runtime.state();
            state.attached.clear();
            state.schema.insert(
                PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu"),
                FakeSchema::BearerV2,
            );
            state.operations.clear();
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::Io {
                operation: "ebpf_endpoint_schema",
                ..
            }
        ));
        let state = runtime.state();
        assert_eq!(state.operations, vec!["adopt"]);
        assert!(!state.attached.contains_key(&S2BU_IFINDEX));
    }

    #[tokio::test]
    async fn uncommitted_v1_and_committed_v1_adopt_to_endpoint_v3() {
        for v1_marker_committed in [false, true] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            {
                let mut state = runtime.state();
                state.attached.clear();
                state.marked_far_map_ready.clear();
                state.marked_dscp_map_ready.clear();
                state.marked_pdr_map_ready.clear();
                state.marked_owner_map_ready.clear();
                state.schema.insert(
                    PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu"),
                    if v1_marker_committed {
                        FakeSchema::DscpV1
                    } else {
                        FakeSchema::V1Uncommitted
                    },
                );
            }
            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            restarted.resolve_device("s2bu").await.unwrap();
            assert_eq!(
                restarted.probe().await.unwrap().per_bearer_marking,
                GtpuCapability::Available
            );
            let state = runtime.state();
            assert!(state.marked_far_map_ready.contains(&S2BU_IFINDEX));
            assert!(state.marked_dscp_map_ready.contains(&S2BU_IFINDEX));
            assert!(state.marked_pdr_map_ready.contains(&S2BU_IFINDEX));
            assert!(state.marked_owner_map_ready.contains(&S2BU_IFINDEX));
        }
    }

    #[tokio::test]
    async fn committed_v3_fails_closed_when_each_bearer_map_is_missing() {
        for missing in ["far", "dscp", "pdr", "owner", "binding", "binding-counters"] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            {
                let mut state = runtime.state();
                state.attached.clear();
                match missing {
                    "far" => state.marked_far_map_ready.clear(),
                    "dscp" => state.marked_dscp_map_ready.clear(),
                    "pdr" => state.marked_pdr_map_ready.clear(),
                    "owner" => state.marked_owner_map_ready.clear(),
                    "binding" => state.downlink_binding_map_ready.clear(),
                    _ => state.downlink_binding_counters_map_ready.clear(),
                }
            }
            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            assert!(matches!(
                restarted.resolve_device("s2bu").await.unwrap_err(),
                GtpuError::Io {
                    operation: "ebpf_bearer_schema",
                    ..
                }
            ));
            assert!(!runtime.state().attached.contains_key(&S2BU_IFINDEX));
        }
    }

    #[tokio::test]
    async fn adoption_rejects_corrupt_default_bearer_identity_before_attachment() {
        for case in [
            "zero-local-teid",
            "zero-peer-teid",
            "unspecified-ue",
            "ue-is-managed-local-ip",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            backend.install_pdp_context(context()).await.unwrap();
            {
                let mut state = runtime.state();
                state.attached.clear();
                state.uplink_filter_ready.clear();
                state.downlink_filter_ready.clear();
                state.operations.clear();

                let local_teid = 0x1000_0001_u32.to_be_bytes();
                let ue_ip = [10, 45, 0, 2];
                match case {
                    "zero-local-teid" => {
                        let pdr = state
                            .pdr
                            .remove(&(S2BU_IFINDEX, local_teid))
                            .expect("installed default PDR");
                        let binding = state
                            .downlink_binding
                            .remove(&(S2BU_IFINDEX, local_teid))
                            .expect("installed default binding");
                        state.pdr.insert((S2BU_IFINDEX, [0; 4]), pdr);
                        state
                            .downlink_binding
                            .insert((S2BU_IFINDEX, [0; 4]), binding);
                    }
                    "zero-peer-teid" => {
                        let far = state
                            .far
                            .get_mut(&(S2BU_IFINDEX, ue_ip))
                            .expect("installed default FAR");
                        let mut decoded = UplinkFar::decode(far);
                        decoded.o_teid = [0; 4];
                        *far = decoded.encode();
                    }
                    "unspecified-ue" => {
                        state
                            .pdr
                            .get_mut(&(S2BU_IFINDEX, local_teid))
                            .expect("installed default PDR")
                            .copy_from_slice(&[0; 4]);
                        let far = state
                            .far
                            .remove(&(S2BU_IFINDEX, ue_ip))
                            .expect("installed default FAR");
                        state.far.insert((S2BU_IFINDEX, [0; 4]), far);
                    }
                    "ue-is-managed-local-ip" => {
                        let managed_local_ip = [192, 0, 2, 1];
                        state
                            .pdr
                            .get_mut(&(S2BU_IFINDEX, local_teid))
                            .expect("installed default PDR")
                            .copy_from_slice(&managed_local_ip);
                        let far = state
                            .far
                            .remove(&(S2BU_IFINDEX, ue_ip))
                            .expect("installed default FAR");
                        state.far.insert((S2BU_IFINDEX, managed_local_ip), far);
                    }
                    _ => unreachable!(),
                }
            }

            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            assert!(
                matches!(
                    restarted.resolve_device("s2bu").await.unwrap_err(),
                    GtpuError::StateIndeterminate {
                        operation: "ebpf_marked_owner_rebuild"
                    }
                ),
                "{case}"
            );
            let state = runtime.state();
            assert_eq!(state.operations, vec!["adopt"], "{case}");
            assert!(!state.attached.contains_key(&S2BU_IFINDEX), "{case}");
            assert!(!state.uplink_filter_ready.contains(&S2BU_IFINDEX), "{case}");
            assert!(
                !state.downlink_filter_ready.contains(&S2BU_IFINDEX),
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn adoption_rejects_every_non_authoritative_owner_graph_before_attachment() {
        for case in [
            "invalid-format",
            "duplicate-teid",
            "unowned-resource",
            "incomplete-active",
            "selector-is-local-ip",
            "far-local-ip-mismatch",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: 0x1001_u32.to_be_bytes(),
            }
            .encode();
            let make_owner = |local_ip, phase| {
                MarkedBearerOwner::new(
                    0x1000_0002_u32.to_be_bytes(),
                    UplinkFar {
                        peer_ip: [192, 0, 2, 10],
                        local_ip,
                        o_teid: 0x2000_0002_u32.to_be_bytes(),
                    },
                    None,
                    DownlinkEndpointBinding::new(
                        GtpuEndpointAddress::Ipv4([192, 0, 2, 10]),
                        GtpuEndpointAddress::Ipv4(local_ip),
                        S2BU_IFINDEX,
                        crate::GtpuSourcePortPolicy::Any,
                    )
                    .unwrap(),
                    phase,
                )
            };
            {
                let mut state = runtime.state();
                state.attached.clear();
                state.marked_owner_by_teid.clear();
                match case {
                    "invalid-format" => {
                        let mut encoded =
                            make_owner([192, 0, 2, 1], MarkedBearerOwnerPhase::Pending).encode();
                        encoded[17] = 1;
                        state.marked_owner.insert((S2BU_IFINDEX, selector), encoded);
                    }
                    "duplicate-teid" => {
                        let owner =
                            make_owner([192, 0, 2, 1], MarkedBearerOwnerPhase::Pending).encode();
                        let second_selector = UplinkFarKey {
                            ue_ip: [10, 45, 0, 3],
                            bearer_mark: 0x1002_u32.to_be_bytes(),
                        }
                        .encode();
                        state.marked_owner.insert((S2BU_IFINDEX, selector), owner);
                        state
                            .marked_owner
                            .insert((S2BU_IFINDEX, second_selector), owner);
                    }
                    "unowned-resource" => {
                        state.marked_far.insert(
                            (S2BU_IFINDEX, selector),
                            make_owner([192, 0, 2, 1], MarkedBearerOwnerPhase::Pending)
                                .uplink_far
                                .encode(),
                        );
                    }
                    "incomplete-active" => {
                        state.marked_owner.insert(
                            (S2BU_IFINDEX, selector),
                            make_owner([192, 0, 2, 1], MarkedBearerOwnerPhase::Active).encode(),
                        );
                    }
                    "selector-is-local-ip" => {
                        let local_selector = UplinkFarKey {
                            ue_ip: [192, 0, 2, 1],
                            bearer_mark: 0x1001_u32.to_be_bytes(),
                        }
                        .encode();
                        state.marked_owner.insert(
                            (S2BU_IFINDEX, local_selector),
                            make_owner([192, 0, 2, 1], MarkedBearerOwnerPhase::Pending).encode(),
                        );
                    }
                    _ => {
                        state.marked_owner.insert(
                            (S2BU_IFINDEX, selector),
                            make_owner([198, 51, 100, 1], MarkedBearerOwnerPhase::Pending).encode(),
                        );
                    }
                }
            }
            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            assert!(
                matches!(
                    restarted.resolve_device("s2bu").await.unwrap_err(),
                    GtpuError::StateIndeterminate {
                        operation: "ebpf_marked_owner_rebuild"
                    }
                ),
                "{case}"
            );
            assert!(
                !runtime.state().attached.contains_key(&S2BU_IFINDEX),
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn adopted_v5_required_map_loss_is_not_silently_recreated_on_restart() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        {
            let mut state = runtime.state();
            state.attached.clear();
            state.dscp_map_ready.clear();
            assert_eq!(
                state
                    .schema
                    .get(&PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu")),
                Some(&FakeSchema::PmtuV5)
            );
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::Io {
                operation: "ebpf_bearer_schema",
                ..
            }
        ));
        let state = runtime.state();
        assert!(!state.dscp_map_ready.contains(&S2BU_IFINDEX));
        assert!(!state.attached.contains_key(&S2BU_IFINDEX));
    }

    #[tokio::test]
    async fn runtime_dscp_map_loss_is_reported_and_blocks_new_routing() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        runtime.state().dscp_map_ready.clear();

        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.egress_dscp_marking, GtpuCapability::Missing);
        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        assert!(matches!(
            backend.install_pdp_context(marked).await.unwrap_err(),
            GtpuError::Io {
                operation: "ebpf_dscp_datapath",
                ..
            }
        ));
        let state = runtime.state();
        assert!(state.far.is_empty());
        assert!(state.pdr.is_empty());
    }

    #[tokio::test]
    async fn live_uplink_filter_loss_is_reported_and_blocks_marked_mutation() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        runtime.state().uplink_filter_ready.clear();

        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.egress_dscp_marking, GtpuCapability::Missing);
        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        assert!(matches!(
            backend.install_pdp_context(marked).await.unwrap_err(),
            GtpuError::Io {
                operation: "ebpf_dscp_datapath",
                ..
            }
        ));
        let state = runtime.state();
        assert!(state.far.is_empty());
        assert!(state.pdr.is_empty());
        assert!(state.dscp.is_empty());
    }

    #[tokio::test]
    async fn either_live_filter_loss_blocks_bidirectional_bearer_marking() {
        for missing_hook in ["uplink", "downlink"] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            if missing_hook == "uplink" {
                runtime.state().uplink_filter_ready.clear();
            } else {
                runtime.state().downlink_filter_ready.clear();
            }
            assert_eq!(
                backend.probe().await.unwrap().per_bearer_marking,
                GtpuCapability::Missing
            );
            let error = backend
                .install_pdp_context(marked_context(0x1001, 0x1000_0002, 0x2000_0002))
                .await
                .unwrap_err();
            let expected_operation = if missing_hook == "downlink" {
                "ebpf_downlink_endpoint_datapath"
            } else {
                "ebpf_bearer_mark_datapath"
            };
            assert!(
                matches!(
                    error,
                    GtpuError::Io { operation, .. } if operation == expected_operation
                ),
                "{missing_hook}"
            );
            let state = runtime.state();
            assert!(state.marked_far.is_empty());
            assert!(state.marked_pdr.is_empty());
        }
    }

    #[tokio::test]
    async fn either_absent_live_filter_still_allows_marked_cleanup() {
        for missing_hook in ["uplink", "downlink"] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            backend.install_pdp_context(marked.clone()).await.unwrap();
            if missing_hook == "uplink" {
                runtime.state().uplink_filter_ready.clear();
            } else {
                runtime.state().downlink_filter_ready.clear();
            }

            backend
                .remove_pdp_context(RemovePdpContextRequest::from_context(&marked))
                .await
                .unwrap();
            let state = runtime.state();
            assert!(state.marked_far.is_empty());
            assert!(state.marked_dscp.is_empty());
            assert!(state.marked_pdr.is_empty());
        }
    }

    #[tokio::test]
    async fn foreign_hook_or_pin_identity_blocks_cleanup_without_mutation() {
        for conflict in ["uplink", "downlink", "pin"] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            backend.install_pdp_context(marked.clone()).await.unwrap();
            let before = {
                let state = runtime.state();
                (
                    state.marked_far.clone(),
                    state.marked_dscp.clone(),
                    state.marked_pdr.clone(),
                )
            };
            match conflict {
                "uplink" => {
                    runtime.state().uplink_filter_foreign.insert(S2BU_IFINDEX);
                }
                "downlink" => {
                    runtime.state().downlink_filter_foreign.insert(S2BU_IFINDEX);
                }
                "pin" => {
                    runtime.state().pin_identity_invalid.insert(S2BU_IFINDEX);
                }
                _ => unreachable!(),
            }

            assert!(matches!(
                backend
                    .remove_pdp_context(RemovePdpContextRequest::from_context(&marked))
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context"
                }
            ));
            let state = runtime.state();
            assert_eq!(
                (
                    state.marked_far.clone(),
                    state.marked_dscp.clone(),
                    state.marked_pdr.clone(),
                ),
                before
            );
        }
    }

    #[tokio::test]
    async fn multiple_bearers_share_paa_without_collapsing_marked_state() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let default = context();
        let first = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        let second = marked_context(u32::MAX, 0x1000_0003, 0x2000_0003);

        backend.install_pdp_context(default.clone()).await.unwrap();
        backend.install_pdp_context(first.clone()).await.unwrap();
        backend.install_pdp_context(second.clone()).await.unwrap();
        backend.install_pdp_context(first.clone()).await.unwrap();

        let state = runtime.state();
        assert_eq!(state.far.len(), 1);
        assert_eq!(state.pdr.len(), 1);
        assert_eq!(state.marked_far.len(), 2);
        assert_eq!(state.marked_pdr.len(), 2);
        let max_key = UplinkFarKey {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: [0xff; 4],
        }
        .encode();
        assert_eq!(max_key, [10, 45, 0, 2, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            UplinkFar::decode(
                state
                    .marked_far
                    .get(&(S2BU_IFINDEX, max_key))
                    .expect("maximum mark FAR")
            )
            .o_teid,
            0x2000_0003_u32.to_be_bytes()
        );
        let pdr = MarkedDownlinkPdr::decode(
            state
                .marked_pdr
                .get(&(S2BU_IFINDEX, 0x1000_0003_u32.to_be_bytes()))
                .expect("maximum mark PDR"),
        );
        assert_eq!(pdr.ue_ip, [10, 45, 0, 2]);
        assert_eq!(pdr.bearer_mark, [0xff; 4]);
    }

    #[tokio::test]
    async fn marked_installs_reject_duplicate_selector_and_cross_schema_teid() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let default = context();
        let first = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        backend.install_pdp_context(default.clone()).await.unwrap();
        backend.install_pdp_context(first.clone()).await.unwrap();

        let same_selector = marked_context(0x1001, 0x1000_0003, 0x2000_0003);
        assert!(matches!(
            backend
                .install_pdp_context(same_selector)
                .await
                .unwrap_err(),
            GtpuError::AlreadyExists
        ));
        let cross_schema_teid = marked_context(0x1002, default.local_teid.get(), 0x2000_0004);
        assert!(matches!(
            backend
                .install_pdp_context(cross_schema_teid)
                .await
                .unwrap_err(),
            GtpuError::AlreadyExists
        ));
        let mut default_on_marked_teid = default.clone();
        default_on_marked_teid.local_teid = first.local_teid;
        default_on_marked_teid.peer_teid = teid(0x2000_0005);
        assert!(matches!(
            backend
                .install_pdp_context(default_on_marked_teid)
                .await
                .unwrap_err(),
            GtpuError::AlreadyExists
        ));
        let marked_on_marked_teid = marked_context(0x1002, first.local_teid.get(), 0x2000_0006);
        assert!(matches!(
            backend
                .install_pdp_context(marked_on_marked_teid)
                .await
                .unwrap_err(),
            GtpuError::AlreadyExists
        ));

        // Externally corrupted dual ownership is never reconciled by picking
        // one schema.
        runtime.state().pdr.insert(
            (S2BU_IFINDEX, first.local_teid.get().to_be_bytes()),
            DownlinkPdr {
                ue_ip: [10, 45, 0, 2],
            }
            .encode(),
        );
        assert!(matches!(
            backend
                .remove_pdp_context(RemovePdpContextRequest::from_context(&first))
                .await
                .unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context"
            }
        ));
    }

    #[tokio::test]
    async fn marked_install_retains_pending_and_exact_retry_converges_after_each_cut() {
        for failure in [
            "marked_owner_insert_pending",
            "marked_dscp_insert",
            "marked_far_insert",
            "downlink_binding_insert",
            "marked_pdr_insert",
            "marked_owner_insert_active",
            "marked_sport_insert_active",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            runtime.fail_in_order([failure]);
            assert!(matches!(
                backend
                    .install_pdp_context(marked.clone())
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_install_pdp_context"
                }
            ));
            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: 0x1001_u32.to_be_bytes(),
            }
            .encode();
            {
                let mut state = runtime.state();
                let commit = PdpContextCommit::decode(
                    state
                        .marked_sport
                        .get(&(S2BU_IFINDEX, selector))
                        .expect("Pending commit must survive every post-reservation cut"),
                );
                assert_eq!(commit.phase(), MarkedBearerOwnerPhase::Pending, "{failure}");
                state.attached.clear();
                state.marked_owner_by_teid.clear();
            }

            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            restarted.resolve_device("s2bu").await.unwrap();
            restarted.install_pdp_context(marked.clone()).await.unwrap();
            let state = runtime.state();
            let owner = MarkedBearerOwner::decode(
                state
                    .marked_owner
                    .get(&(S2BU_IFINDEX, selector))
                    .expect("exact retry commits the owner"),
            );
            assert_eq!(owner.phase, MarkedBearerOwnerPhase::Active, "{failure}");
            assert!(state.marked_far.contains_key(&(S2BU_IFINDEX, selector)));
            assert!(state.marked_dscp.contains_key(&(S2BU_IFINDEX, selector)));
            assert!(state.marked_sport.contains_key(&(S2BU_IFINDEX, selector)));
            assert!(state
                .marked_pdr
                .contains_key(&(S2BU_IFINDEX, marked.local_teid.get().to_be_bytes())));
        }
    }

    #[tokio::test]
    async fn pending_owner_without_pdr_reserves_teid_against_default_install() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        runtime.fail_in_order(["marked_far_insert"]);
        let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        assert!(matches!(
            backend
                .install_pdp_context(marked.clone())
                .await
                .unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context"
            }
        ));
        assert!(runtime.state().marked_pdr.is_empty());

        let mut default = context();
        default.local_teid = marked.local_teid;
        assert!(matches!(
            backend.install_pdp_context(default).await.unwrap_err(),
            GtpuError::AlreadyExists
        ));
    }

    #[tokio::test]
    async fn failed_marked_update_retains_old_active_identity_and_retry_converges() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        marked.egress_dscp = Some(crate::DscpCodepoint::new(10).unwrap());
        backend.install_pdp_context(marked.clone()).await.unwrap();

        let selector = UplinkFarKey {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: 0x1001_u32.to_be_bytes(),
        }
        .encode();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        runtime.fail_in_order(["marked_dscp_insert"]);
        assert!(matches!(
            backend
                .install_pdp_context(marked.clone())
                .await
                .unwrap_err(),
            GtpuError::Io {
                operation: "marked_dscp_insert",
                ..
            }
        ));
        {
            let mut state = runtime.state();
            let owner = MarkedBearerOwner::decode(
                state.marked_owner.get(&(S2BU_IFINDEX, selector)).unwrap(),
            );
            assert_eq!(owner.phase, MarkedBearerOwnerPhase::Active);
            assert_eq!(owner.egress_dscp(), Some(10));
            assert_eq!(
                state.marked_dscp.get(&(S2BU_IFINDEX, selector)),
                Some(&[10])
            );
            state.attached.clear();
            state.marked_owner_by_teid.clear();
        }
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        restarted.resolve_device("s2bu").await.unwrap();
        restarted.install_pdp_context(marked).await.unwrap();

        let state = runtime.state();
        let owner =
            MarkedBearerOwner::decode(state.marked_owner.get(&(S2BU_IFINDEX, selector)).unwrap());
        assert_eq!(owner.phase, MarkedBearerOwnerPhase::Active);
        assert_eq!(
            state.marked_dscp.get(&(S2BU_IFINDEX, selector)),
            Some(&[46])
        );
    }

    #[tokio::test]
    async fn marked_remove_restarts_from_removing_owner_after_each_resource_cut() {
        for failure in [
            "marked_far_remove",
            "marked_dscp_remove",
            "marked_pdr_remove",
            "marked_owner_remove",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let first = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            let mut second = marked_context(0x1002, 0x1000_0003, 0x2000_0003);
            second.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            backend.install_pdp_context(first.clone()).await.unwrap();
            backend.install_pdp_context(second.clone()).await.unwrap();
            runtime.fail_in_order([failure]);
            assert!(matches!(
                backend
                    .remove_pdp_context(RemovePdpContextRequest::from_context(&second))
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context"
                }
            ));
            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: 0x1002_u32.to_be_bytes(),
            }
            .encode();
            {
                let mut state = runtime.state();
                let owner = MarkedBearerOwner::decode(
                    state.marked_owner.get(&(S2BU_IFINDEX, selector)).unwrap(),
                );
                assert_eq!(owner.phase, MarkedBearerOwnerPhase::Removing, "{failure}");
                state.attached.clear();
                state.marked_owner_by_teid.clear();
            }
            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            restarted.resolve_device("s2bu").await.unwrap();
            restarted
                .remove_pdp_context(RemovePdpContextRequest::from_context(&second))
                .await
                .unwrap();
            restarted
                .remove_pdp_context(RemovePdpContextRequest::from_context(&second))
                .await
                .unwrap();
            let state = runtime.state();
            assert!(!state.marked_owner.contains_key(&(S2BU_IFINDEX, selector)));
            assert_eq!(state.marked_far.len(), 1);
            assert_eq!(state.marked_pdr.len(), 1);
            assert!(state
                .marked_owner_by_teid
                .contains_key(&(S2BU_IFINDEX, first.local_teid.get().to_be_bytes())));
        }
    }

    #[tokio::test]
    async fn install_after_each_removal_cut_finishes_tombstone_before_retrying() {
        for failure in [
            "marked_far_remove",
            "marked_dscp_remove",
            "marked_pdr_remove",
            "marked_owner_remove",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            backend.install_pdp_context(marked.clone()).await.unwrap();
            runtime.fail_in_order([failure]);
            assert!(matches!(
                backend
                    .remove_pdp_context(RemovePdpContextRequest::from_context(&marked))
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context"
                }
            ));

            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: 0x1001_u32.to_be_bytes(),
            }
            .encode();
            assert_eq!(
                MarkedBearerOwner::decode(
                    runtime
                        .state()
                        .marked_owner
                        .get(&(S2BU_IFINDEX, selector))
                        .unwrap(),
                )
                .phase,
                MarkedBearerOwnerPhase::Removing,
                "{failure}"
            );

            assert!(matches!(
                backend
                    .install_pdp_context(marked.clone())
                    .await
                    .unwrap_err(),
                GtpuError::RetryRequired {
                    operation: "ebpf_install_after_removal"
                }
            ));
            {
                let state = runtime.state();
                assert!(state.marked_far.is_empty(), "{failure}");
                assert!(state.marked_dscp.is_empty(), "{failure}");
                assert!(state.marked_pdr.is_empty(), "{failure}");
                assert!(state.marked_owner.is_empty(), "{failure}");
                assert!(state.marked_owner_by_teid.is_empty(), "{failure}");
            }

            backend.install_pdp_context(marked.clone()).await.unwrap();
            let state = runtime.state();
            let owner = MarkedBearerOwner::decode(
                state.marked_owner.get(&(S2BU_IFINDEX, selector)).unwrap(),
            );
            assert_eq!(owner.phase, MarkedBearerOwnerPhase::Active, "{failure}");
            assert!(state.marked_far.contains_key(&(S2BU_IFINDEX, selector)));
            assert!(state.marked_dscp.contains_key(&(S2BU_IFINDEX, selector)));
            assert!(state
                .marked_pdr
                .contains_key(&(S2BU_IFINDEX, marked.local_teid.get().to_be_bytes())));
        }
    }

    #[tokio::test]
    async fn restart_converges_after_every_default_install_crash_cut() {
        for cut in [
            "sport_insert_pending",
            "dscp_insert",
            "far_insert",
            "downlink_binding_insert",
            "pdr_insert",
            "sport_insert_active",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut desired = context();
            desired.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            desired.uplink_source_port_policy = selected_source_port(40_000);
            runtime.crash_after_in_order([cut]);
            assert!(
                backend.install_pdp_context(desired.clone()).await.is_err(),
                "{cut}"
            );
            {
                let mut state = runtime.state();
                assert!(state.crashes_after.is_empty(), "{cut}");
                state.attached.clear();
                state.default_teid_by_ue.clear();
                state.marked_owner_by_teid.clear();
            }

            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            restarted.resolve_device("s2bu").await.unwrap();
            restarted
                .install_pdp_context(desired.clone())
                .await
                .unwrap();
            assert_eq!(
                restarted
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Present(desired),
                "{cut}"
            );
        }
    }

    #[tokio::test]
    async fn restart_converges_after_every_marked_install_crash_cut() {
        for cut in [
            "marked_sport_insert_pending",
            "marked_owner_insert_pending",
            "marked_dscp_insert",
            "marked_far_insert",
            "downlink_binding_insert",
            "marked_pdr_insert",
            "marked_owner_insert_active",
            "marked_sport_insert_active",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut desired = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            desired.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            desired.uplink_source_port_policy = selected_source_port(40_001);
            runtime.crash_after_in_order([cut]);
            assert!(
                backend.install_pdp_context(desired.clone()).await.is_err(),
                "{cut}"
            );
            {
                let mut state = runtime.state();
                assert!(state.crashes_after.is_empty(), "{cut}");
                state.attached.clear();
                state.default_teid_by_ue.clear();
                state.marked_owner_by_teid.clear();
            }

            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            restarted.resolve_device("s2bu").await.unwrap();
            restarted
                .install_pdp_context(desired.clone())
                .await
                .unwrap();
            assert_eq!(
                restarted
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Present(desired),
                "{cut}"
            );
        }
    }

    #[tokio::test]
    async fn restart_converges_after_every_removal_crash_cut() {
        let default_cuts = [
            "sport_insert_removing",
            "far_remove",
            "dscp_remove",
            "downlink_binding_remove",
            "pdr_remove",
            "sport_remove",
        ];
        for cut in default_cuts {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut desired = context();
            desired.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            backend.install_pdp_context(desired.clone()).await.unwrap();
            runtime.crash_after_in_order([cut]);
            assert!(
                backend.remove_pdp_context(remove_request()).await.is_err(),
                "{cut}"
            );
            {
                let mut state = runtime.state();
                assert!(state.crashes_after.is_empty(), "{cut}");
                state.attached.clear();
                state.default_teid_by_ue.clear();
                state.marked_owner_by_teid.clear();
            }
            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            restarted.resolve_device("s2bu").await.unwrap();
            assert_eq!(
                restarted
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Absent,
                "{cut}"
            );
        }

        for cut in [
            "marked_sport_insert_removing",
            "marked_owner_insert_removing",
            "marked_far_remove",
            "marked_dscp_remove",
            "downlink_binding_remove",
            "marked_pdr_remove",
            "marked_owner_remove",
            "marked_sport_remove",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut desired = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            desired.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            backend.install_pdp_context(desired.clone()).await.unwrap();
            runtime.crash_after_in_order([cut]);
            assert!(
                backend
                    .remove_pdp_context(RemovePdpContextRequest::from_context(&desired))
                    .await
                    .is_err(),
                "{cut}"
            );
            {
                let mut state = runtime.state();
                assert!(state.crashes_after.is_empty(), "{cut}");
                state.attached.clear();
                state.default_teid_by_ue.clear();
                state.marked_owner_by_teid.clear();
            }
            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            restarted.resolve_device("s2bu").await.unwrap();
            assert_eq!(
                restarted
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Absent,
                "{cut}"
            );
        }
    }

    #[tokio::test]
    async fn interrupted_restart_cleanup_resumes_at_every_boundary() {
        for (install_cut, recovery_cut) in [
            ("dscp_insert", "recover_default_far_remove"),
            ("dscp_insert", "recover_default_dscp_remove"),
            ("far_insert", "recover_default_binding_remove"),
            ("downlink_binding_insert", "recover_default_pdr_remove"),
            ("pdr_insert", "recover_default_commit_remove"),
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut desired = context();
            desired.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            runtime.crash_after_in_order([install_cut]);
            assert!(backend.install_pdp_context(desired).await.is_err());
            runtime.state().attached.clear();
            runtime.crash_after_in_order([recovery_cut]);
            let first_restart = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            assert!(
                first_restart.resolve_device("s2bu").await.is_err(),
                "{recovery_cut}"
            );
            assert!(runtime.state().crashes_after.is_empty(), "{recovery_cut}");
            let second_restart = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            second_restart.resolve_device("s2bu").await.unwrap();
            let state = runtime.state();
            assert!(state.sport.is_empty(), "{recovery_cut}");
            assert!(state.far.is_empty(), "{recovery_cut}");
            assert!(state.pdr.is_empty(), "{recovery_cut}");
            assert!(state.downlink_binding.is_empty(), "{recovery_cut}");
        }

        for recovery_cut in [
            "recover_marked_far_remove",
            "recover_marked_dscp_remove",
            "recover_marked_binding_remove",
            "recover_marked_pdr_remove",
            "recover_marked_owner_remove",
            "recover_marked_commit_remove",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut desired = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            desired.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            runtime.crash_after_in_order(["marked_pdr_insert"]);
            assert!(backend.install_pdp_context(desired).await.is_err());
            runtime.state().attached.clear();
            runtime.crash_after_in_order([recovery_cut]);
            let first_restart = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            assert!(
                first_restart.resolve_device("s2bu").await.is_err(),
                "{recovery_cut}"
            );
            assert!(runtime.state().crashes_after.is_empty(), "{recovery_cut}");
            let second_restart = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            second_restart.resolve_device("s2bu").await.unwrap();
            let state = runtime.state();
            assert!(state.marked_sport.is_empty(), "{recovery_cut}");
            assert!(state.marked_far.is_empty(), "{recovery_cut}");
            assert!(state.marked_pdr.is_empty(), "{recovery_cut}");
            assert!(state.marked_owner.is_empty(), "{recovery_cut}");
            assert!(state.downlink_binding.is_empty(), "{recovery_cut}");
        }
    }

    #[tokio::test]
    async fn restart_rejects_mismatched_transitional_owner_without_cleanup() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        backend.install_pdp_context(marked).await.unwrap();
        let selector = UplinkFarKey {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: 0x1001_u32.to_be_bytes(),
        }
        .encode();
        let before = {
            let mut state = runtime.state();
            let active = PdpContextCommit::decode(
                state
                    .marked_sport
                    .get(&(S2BU_IFINDEX, selector))
                    .expect("active test commit"),
            );
            let mismatched = PdpContextCommit::new(
                0x1000_00fe_u32.to_be_bytes(),
                active.uplink_far(),
                active.egress_dscp(),
                active.downlink_binding(),
                active.uplink_source_port_policy(),
                MarkedBearerOwnerPhase::Pending,
            )
            .expect("canonical mismatched test commit");
            state
                .marked_sport
                .insert((S2BU_IFINDEX, selector), mismatched.encode());
            state.attached.clear();
            state.default_teid_by_ue.clear();
            state.marked_owner_by_teid.clear();
            state.operations.clear();
            (
                state.marked_far.clone(),
                state.marked_dscp.clone(),
                state.downlink_binding.clone(),
                state.marked_pdr.clone(),
                state.marked_owner.clone(),
                state.marked_sport.clone(),
            )
        };

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_pdp_recovery"
            }
        ));
        let state = runtime.state();
        assert_eq!(
            before,
            (
                state.marked_far.clone(),
                state.marked_dscp.clone(),
                state.downlink_binding.clone(),
                state.marked_pdr.clone(),
                state.marked_owner.clone(),
                state.marked_sport.clone(),
            ),
            "corrupt mixed ownership must fail before destructive recovery"
        );
        assert!(
            state
                .operations
                .iter()
                .all(|operation| !operation.starts_with("recover_")),
            "no recovery mutation may precede ownership proof"
        );
    }

    #[tokio::test]
    async fn restart_cleans_removing_marked_transaction_before_reinstall() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        backend.install_pdp_context(marked.clone()).await.unwrap();
        runtime.fail_in_order(["marked_owner_remove"]);
        assert!(matches!(
            backend
                .remove_pdp_context(RemovePdpContextRequest::from_context(&marked))
                .await
                .unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context"
            }
        ));
        let selector = UplinkFarKey {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: 0x1001_u32.to_be_bytes(),
        }
        .encode();
        {
            let mut state = runtime.state();
            let encoded = state
                .marked_owner
                .get(&(S2BU_IFINDEX, selector))
                .copied()
                .expect("Removing owner remains after the injected final cut");
            assert_eq!(&encoded[16..20], &[0xff, 2, 3, 0]);
            assert_eq!(
                MarkedBearerOwner::decode(&encoded).phase,
                MarkedBearerOwnerPhase::Removing
            );
            assert!(state.marked_far.is_empty());
            assert!(state.marked_dscp.is_empty());
            assert!(state.marked_pdr.is_empty());
            state.attached.clear();
            state.marked_owner_by_teid.clear();
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        restarted.resolve_device("s2bu").await.unwrap();
        {
            let state = runtime.state();
            assert!(state.marked_far.is_empty());
            assert!(state.marked_pdr.is_empty());
            assert!(state.marked_owner.is_empty());
            assert!(state.marked_sport.is_empty());
        }

        restarted.install_pdp_context(marked.clone()).await.unwrap();
        let state = runtime.state();
        let owner =
            MarkedBearerOwner::decode(state.marked_owner.get(&(S2BU_IFINDEX, selector)).unwrap());
        assert_eq!(owner.phase, MarkedBearerOwnerPhase::Active);
        assert!(state.marked_far.contains_key(&(S2BU_IFINDEX, selector)));
        assert!(state
            .marked_pdr
            .contains_key(&(S2BU_IFINDEX, marked.local_teid.get().to_be_bytes())));
    }

    #[tokio::test]
    async fn install_cleanup_failure_keeps_removing_gate_until_retry_completes() {
        for failure in [
            "marked_far_remove",
            "marked_dscp_remove",
            "marked_pdr_remove",
            "marked_owner_remove",
        ] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            backend.install_pdp_context(marked.clone()).await.unwrap();
            runtime.fail_in_order(["marked_far_remove"]);
            assert!(matches!(
                backend
                    .remove_pdp_context(RemovePdpContextRequest::from_context(&marked))
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context"
                }
            ));

            runtime.fail_in_order([failure]);
            assert!(matches!(
                backend
                    .install_pdp_context(marked.clone())
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context"
                }
            ));
            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: 0x1001_u32.to_be_bytes(),
            }
            .encode();
            assert_eq!(
                MarkedBearerOwner::decode(
                    runtime
                        .state()
                        .marked_owner
                        .get(&(S2BU_IFINDEX, selector))
                        .unwrap(),
                )
                .phase,
                MarkedBearerOwnerPhase::Removing,
                "{failure}"
            );

            assert!(matches!(
                backend
                    .install_pdp_context(marked.clone())
                    .await
                    .unwrap_err(),
                GtpuError::RetryRequired {
                    operation: "ebpf_install_after_removal"
                }
            ));
            {
                let state = runtime.state();
                assert!(state.marked_far.is_empty(), "{failure}");
                assert!(state.marked_dscp.is_empty(), "{failure}");
                assert!(state.marked_pdr.is_empty(), "{failure}");
                assert!(state.marked_owner.is_empty(), "{failure}");
            }

            backend.install_pdp_context(marked.clone()).await.unwrap();
            let state = runtime.state();
            let owner = MarkedBearerOwner::decode(
                state.marked_owner.get(&(S2BU_IFINDEX, selector)).unwrap(),
            );
            assert_eq!(owner.phase, MarkedBearerOwnerPhase::Active, "{failure}");
            assert!(state.marked_far.contains_key(&(S2BU_IFINDEX, selector)));
        }
    }

    #[tokio::test]
    async fn install_drift_finishes_removing_owner_without_false_already_exists() {
        for drift in ["far", "dscp", "local_teid", "selector"] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut original = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            original.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            backend.install_pdp_context(original.clone()).await.unwrap();
            runtime.fail_in_order(["marked_owner_remove"]);
            assert!(matches!(
                backend
                    .remove_pdp_context(RemovePdpContextRequest::from_context(&original))
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context"
                }
            ));

            let mut desired = original.clone();
            match drift {
                "far" => desired.peer_teid = teid(0x2000_0003),
                "dscp" => desired.egress_dscp = Some(crate::DscpCodepoint::new(10).unwrap()),
                "local_teid" => desired.local_teid = teid(0x1000_0003),
                _ => desired.bearer_mark = GtpBearerMark::new(0x1002),
            }
            assert!(matches!(
                backend
                    .install_pdp_context(desired.clone())
                    .await
                    .unwrap_err(),
                GtpuError::RetryRequired {
                    operation: "ebpf_install_after_removal"
                }
            ));
            {
                let state = runtime.state();
                assert!(state.marked_far.is_empty(), "{drift}");
                assert!(state.marked_dscp.is_empty(), "{drift}");
                assert!(state.marked_pdr.is_empty(), "{drift}");
                assert!(state.marked_owner.is_empty(), "{drift}");
            }

            backend.install_pdp_context(desired.clone()).await.unwrap();
            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: desired
                    .bearer_mark
                    .expect("test desired context is marked")
                    .get()
                    .to_be_bytes(),
            }
            .encode();
            let state = runtime.state();
            let owner = MarkedBearerOwner::decode(
                state.marked_owner.get(&(S2BU_IFINDEX, selector)).unwrap(),
            );
            assert_eq!(owner.phase, MarkedBearerOwnerPhase::Active, "{drift}");
            assert_eq!(owner.local_teid, desired.local_teid.get().to_be_bytes());
            assert_eq!(
                owner.uplink_far.o_teid,
                desired.peer_teid.get().to_be_bytes()
            );
            assert_eq!(
                owner.egress_dscp(),
                desired.egress_dscp.map(crate::DscpCodepoint::get)
            );
        }
    }

    #[tokio::test]
    async fn removing_owner_corruption_blocks_install_cleanup_without_mutation() {
        for corruption in ["legacy_pdr"] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
            backend.install_pdp_context(marked.clone()).await.unwrap();
            runtime.fail_in_order(["marked_far_remove"]);
            assert!(matches!(
                backend
                    .remove_pdp_context(RemovePdpContextRequest::from_context(&marked))
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context"
                }
            ));
            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: 0x1001_u32.to_be_bytes(),
            }
            .encode();
            {
                let mut state = runtime.state();
                state.pdr.insert(
                    (S2BU_IFINDEX, marked.local_teid.get().to_be_bytes()),
                    DownlinkPdr {
                        ue_ip: [10, 45, 0, 2],
                    }
                    .encode(),
                );
            }
            let before = {
                let state = runtime.state();
                (
                    state.marked_far.clone(),
                    state.marked_dscp.clone(),
                    state.marked_pdr.clone(),
                    state.marked_owner.clone(),
                )
            };
            assert!(matches!(
                backend
                    .install_pdp_context(marked.clone())
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context"
                }
            ));
            let state = runtime.state();
            assert_eq!(state.marked_far, before.0, "{corruption}");
            assert_eq!(state.marked_dscp, before.1, "{corruption}");
            assert_eq!(state.marked_pdr, before.2, "{corruption}");
            assert_eq!(state.marked_owner, before.3, "{corruption}");
            assert_eq!(
                MarkedBearerOwner::decode(
                    state.marked_owner.get(&(S2BU_IFINDEX, selector)).unwrap(),
                )
                .phase,
                MarkedBearerOwnerPhase::Removing
            );
        }
    }

    #[tokio::test]
    async fn zero_mark_in_marked_pdr_blocks_removal_without_mutation() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        backend.install_pdp_context(marked.clone()).await.unwrap();
        runtime.state().marked_pdr.insert(
            (S2BU_IFINDEX, marked.local_teid.get().to_be_bytes()),
            MarkedDownlinkPdr {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: [0; 4],
            }
            .encode(),
        );
        assert!(matches!(
            backend
                .remove_pdp_context(RemovePdpContextRequest::from_context(&marked))
                .await
                .unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context"
            }
        ));
        let state = runtime.state();
        assert_eq!(state.marked_far.len(), 1);
        assert_eq!(state.marked_pdr.len(), 1);
    }

    #[tokio::test]
    async fn resolve_device_without_prior_provisioning_reports_not_found() {
        let (backend, _runtime) = backend_with_fake();
        assert!(matches!(
            backend.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::NotFound
        ));
    }

    #[tokio::test]
    async fn remove_device_detaches_and_forgets_state() {
        let (backend, runtime) = backend_with_fake();
        let device = backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();
        backend.remove_device(&device).await.unwrap();

        {
            let state = runtime.state();
            assert!(state.attached.is_empty());
            assert!(state.pinned_config.is_empty());
        }
        // The interface is no longer managed.
        assert!(matches!(
            backend.install_pdp_context(context()).await.unwrap_err(),
            GtpuError::NotFound
        ));
    }

    #[tokio::test]
    async fn probe_transitions_from_unprovisioned_unknown_to_attached_available() {
        let ready = EbpfGtpuDataplaneBackend::with_runtime(Arc::new(FakeRuntime::new()));
        let probe = ready.probe().await.unwrap();
        assert_eq!(probe.egress_dscp_marking, GtpuCapability::Unknown);
        ready.create_device(create_request()).await.unwrap();
        let probe = ready.probe().await.unwrap();
        assert_eq!(probe.kind, GtpuBackendKind::LinuxEbpf);
        assert!(probe.platform_supported);
        assert!(probe.net_admin_capable);
        assert!(probe.bpf_capable);
        assert!(probe.btf_present);
        assert!(probe.mutation_ready);
        assert_eq!(probe.egress_dscp_marking, GtpuCapability::Available);
        assert!(!probe.gtp_module_present);

        for missing in ["bpffs", "btf", "net_admin", "bpf"] {
            let mut environment = EbpfEnvironment {
                platform_supported: true,
                bpffs_present: true,
                btf_present: true,
                net_admin_capable: true,
                bpf_capable: true,
            };
            match missing {
                "bpffs" => environment.bpffs_present = false,
                "btf" => environment.btf_present = false,
                "net_admin" => environment.net_admin_capable = false,
                _ => environment.bpf_capable = false,
            }
            let backend = EbpfGtpuDataplaneBackend::with_runtime(Arc::new(
                FakeRuntime::with_environment(environment),
            ));
            let probe = backend.probe().await.unwrap();
            assert!(!probe.mutation_ready, "{missing} must gate mutation_ready");
            assert!(probe.details.is_some());
            assert_eq!(
                probe.egress_dscp_marking,
                if matches!(missing, "net_admin" | "bpf") {
                    GtpuCapability::PermissionDenied
                } else {
                    GtpuCapability::Missing
                }
            );
        }
    }

    #[tokio::test]
    async fn reconciliation_readback_survives_restart_for_default_and_marked_contexts() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut default = context();
        default.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        marked.egress_dscp = Some(crate::DscpCodepoint::new(34).unwrap());

        for desired in [&default, &marked] {
            assert_eq!(
                backend
                    .install_pdp_context_classified(desired.clone())
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::Installed
            );
        }
        {
            let mut state = runtime.state();
            state.attached.clear();
            state.default_teid_by_ue.clear();
            state.marked_owner_by_teid.clear();
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime);
        restarted.resolve_device("s2bu").await.unwrap();
        for desired in [&default, &marked] {
            assert_eq!(
                restarted
                    .install_pdp_context_classified(desired.clone())
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::ExactAlreadyPresent
            );
            assert_eq!(
                restarted
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Present(desired.clone())
            );
            assert_eq!(
                restarted
                    .read_pdp_context(PdpContextSelector::Uplink(
                        PdpContextUplinkSelector::from_context(desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Present(desired.clone())
            );
        }
        assert_eq!(
            restarted.pdp_context_reconciliation_capabilities(),
            PdpContextReconciliationCapabilities {
                readback: GtpuCapability::Available,
                classified_install: GtpuCapability::Available,
                exact_removal: GtpuCapability::Available,
            }
        );
    }

    #[tokio::test]
    async fn strict_reconciliation_classifies_both_collision_axes_without_relocation() {
        let (backend, _runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let installed = context();
        assert_eq!(
            backend
                .install_pdp_context_classified(installed.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Installed
        );

        let mut same_uplink = installed.clone();
        same_uplink.local_teid = teid(0x1000_0002);
        same_uplink.peer_teid = teid(0x2000_0002);
        assert!(matches!(
            backend
                .install_pdp_context_classified(same_uplink.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == crate::PdpContextSelectorOccupancy::Uplink
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::LocalTeid)
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::PeerTeid)
        ));

        let mut same_local = installed.clone();
        same_local.ms_address = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 3));
        same_local.peer_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        same_local.bearer_mark = GtpBearerMark::new(0x1001);
        same_local.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        assert!(matches!(
            backend
                .install_pdp_context_classified(same_local)
                .await
                .unwrap(),
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == crate::PdpContextSelectorOccupancy::LocalTeid
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::MsAddress)
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::PeerAddress)
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::BearerMark)
                    && conflict.mismatches().contains(&crate::PdpContextMismatchField::EgressDscp)
        ));

        assert!(matches!(
            backend.remove_pdp_context_exact(same_uplink).await.unwrap(),
            PdpContextRemovalOutcome::Conflict(_)
        ));
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&installed).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(installed.clone())
        );
        assert_eq!(
            backend
                .remove_pdp_context_exact(installed.clone())
                .await
                .unwrap(),
            PdpContextRemovalOutcome::Removed
        );
        assert_eq!(
            backend.remove_pdp_context_exact(installed).await.unwrap(),
            PdpContextRemovalOutcome::AlreadyAbsent
        );
    }

    #[tokio::test]
    async fn reconciliation_fails_closed_for_each_partial_default_graph_shape() {
        for cut in ["far", "pdr", "binding", "reverse_index", "dscp"] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut desired = context();
            desired.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
            backend
                .install_pdp_context_classified(desired.clone())
                .await
                .unwrap();
            {
                let mut state = runtime.state();
                match cut {
                    "far" => {
                        state.far.remove(&(S2BU_IFINDEX, [10, 45, 0, 2]));
                    }
                    "pdr" => {
                        state
                            .pdr
                            .remove(&(S2BU_IFINDEX, desired.local_teid.get().to_be_bytes()));
                    }
                    "binding" => {
                        state
                            .downlink_binding
                            .remove(&(S2BU_IFINDEX, desired.local_teid.get().to_be_bytes()));
                    }
                    "reverse_index" => {
                        state
                            .default_teid_by_ue
                            .remove(&(S2BU_IFINDEX, [10, 45, 0, 2]));
                    }
                    _ => {
                        state.dscp.insert((S2BU_IFINDEX, [10, 45, 0, 2]), [64]);
                    }
                }
            }
            assert!(matches!(
                backend
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
                    ))
                    .await
                    .unwrap_err(),
                GtpuError::StateIndeterminate { .. }
            ));
            assert_eq!(
                backend
                    .install_pdp_context_classified(desired)
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::Indeterminate(
                    PdpContextIndeterminateReason::IncompleteState
                ),
                "cut={cut}"
            );
        }
    }

    #[tokio::test]
    async fn reconciliation_rejects_transitional_owner_and_lost_authority() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        backend
            .install_pdp_context_classified(marked.clone())
            .await
            .unwrap();
        let selector = UplinkFarKey {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: 0x1001_u32.to_be_bytes(),
        }
        .encode();
        {
            let mut state = runtime.state();
            let encoded = state
                .marked_owner
                .get(&(S2BU_IFINDEX, selector))
                .copied()
                .unwrap();
            let mut owner = MarkedBearerOwner::decode(&encoded);
            owner.phase = MarkedBearerOwnerPhase::Pending;
            state
                .marked_owner
                .insert((S2BU_IFINDEX, selector), owner.encode());
        }
        assert_eq!(
            backend
                .install_pdp_context_classified(marked.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Indeterminate(PdpContextIndeterminateReason::IncompleteState)
        );

        runtime.state().pin_identity_invalid.insert(S2BU_IFINDEX);
        assert_eq!(
            backend.remove_pdp_context_exact(marked).await.unwrap(),
            PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable
            )
        );
    }

    #[tokio::test]
    async fn cancelled_classified_install_converges_by_authoritative_retry() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut desired = context();
        desired.uplink_source_port_policy = selected_source_port(40_000);
        let task = tokio::spawn({
            let backend = backend.clone();
            let desired = desired.clone();
            async move { backend.install_pdp_context_classified(desired).await }
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;

        assert!(matches!(
            backend
                .install_pdp_context_classified(desired.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Installed | PdpContextInstallOutcome::ExactAlreadyPresent
        ));
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(desired.clone())
        );
        assert_eq!(
            runtime.state().sport.get(&(S2BU_IFINDEX, [10, 45, 0, 2])),
            Some(&commit_for_context(&desired, MarkedBearerOwnerPhase::Active).encode())
        );
    }

    #[tokio::test]
    async fn backend_is_trait_object_safe_and_debug_redacts() {
        let (backend, _runtime) = backend_with_fake();
        let debug = format!("{backend:?}");
        assert!(debug.contains("EbpfGtpuDataplaneBackend"));

        let boxed: Box<dyn GtpuDataplaneBackend> = Box::new(backend);
        let probe = boxed.probe().await.unwrap();
        assert_eq!(probe.kind, GtpuBackendKind::LinuxEbpf);
    }

    fn selected_source_port(port: u16) -> crate::GtpuUplinkSourcePortPolicy {
        crate::GtpuUplinkSourcePortPolicy::selected(port).unwrap()
    }

    #[tokio::test]
    async fn install_persists_selected_source_port_and_reads_back_effective_port() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut default = context();
        default.uplink_source_port_policy = selected_source_port(40_000);
        backend.install_pdp_context(default.clone()).await.unwrap();
        {
            let state = runtime.state();
            assert_eq!(
                state.sport.get(&(S2BU_IFINDEX, [10, 45, 0, 2])),
                Some(&commit_for_context(&default, MarkedBearerOwnerPhase::Active).encode())
            );
        }
        // Exact re-install of the same policy is idempotent.
        backend.install_pdp_context(default.clone()).await.unwrap();
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&default).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(default.clone())
        );

        let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        marked.uplink_source_port_policy = selected_source_port(40_001);
        backend.install_pdp_context(marked.clone()).await.unwrap();
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&marked).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(marked.clone())
        );
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::Uplink(
                    PdpContextUplinkSelector::from_context(&marked).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(marked)
        );
    }

    #[tokio::test]
    async fn legacy_policy_persists_explicit_source_port_map_entries() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let default = context();
        backend.install_pdp_context(default.clone()).await.unwrap();
        let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        backend.install_pdp_context(marked.clone()).await.unwrap();
        {
            let state = runtime.state();
            assert_eq!(
                state.sport.get(&(S2BU_IFINDEX, [10, 45, 0, 2])),
                Some(&commit_for_context(&default, MarkedBearerOwnerPhase::Active).encode())
            );
            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: 0x1001_u32.to_be_bytes(),
            }
            .encode();
            assert_eq!(
                state.marked_sport.get(&(S2BU_IFINDEX, selector)),
                Some(&commit_for_context(&marked, MarkedBearerOwnerPhase::Active).encode())
            );
        }
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&default).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(default)
        );
    }

    #[tokio::test]
    async fn source_port_policy_reconciles_exactly_for_default_and_marked_sessions() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut desired = context();
        desired.uplink_source_port_policy = selected_source_port(40_000);
        backend.install_pdp_context(desired.clone()).await.unwrap();

        // A selected-port-only change reconciles through the exact-session
        // relocation path without disturbing the downlink identity.
        desired.uplink_source_port_policy = selected_source_port(40_002);
        backend.install_pdp_context(desired.clone()).await.unwrap();
        assert_eq!(
            runtime.state().sport.get(&(S2BU_IFINDEX, [10, 45, 0, 2])),
            Some(&commit_for_context(&desired, MarkedBearerOwnerPhase::Active).encode())
        );
        // Returning to the explicit legacy policy writes its canonical 2152
        // entry rather than making absence carry policy meaning.
        desired.uplink_source_port_policy = crate::GtpuUplinkSourcePortPolicy::LegacyServicePort;
        backend.install_pdp_context(desired.clone()).await.unwrap();
        assert_eq!(
            runtime.state().sport.get(&(S2BU_IFINDEX, [10, 45, 0, 2])),
            Some(&commit_for_context(&desired, MarkedBearerOwnerPhase::Active).encode())
        );

        let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        marked.uplink_source_port_policy = selected_source_port(40_003);
        backend.install_pdp_context(marked.clone()).await.unwrap();
        // A selected-port-only change on an Active marked owner reuses the
        // exact staged replacement without re-publishing the journal.
        marked.uplink_source_port_policy = selected_source_port(40_004);
        backend.install_pdp_context(marked.clone()).await.unwrap();
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&marked).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(marked)
        );
    }

    #[tokio::test]
    async fn remove_deletes_selected_source_port_state() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut default = context();
        default.uplink_source_port_policy = selected_source_port(40_000);
        backend.install_pdp_context(default).await.unwrap();
        let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        marked.uplink_source_port_policy = selected_source_port(40_001);
        backend.install_pdp_context(marked.clone()).await.unwrap();

        backend.remove_pdp_context(remove_request()).await.unwrap();
        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&marked))
            .await
            .unwrap();
        {
            let state = runtime.state();
            assert!(state.sport.is_empty());
            assert!(state.marked_sport.is_empty());
        }
    }

    #[tokio::test]
    async fn missing_committed_policy_never_reads_back_or_reconciles_as_legacy() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut default = context();
        default.uplink_source_port_policy = selected_source_port(40_000);
        let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        marked.uplink_source_port_policy = selected_source_port(40_001);
        backend.install_pdp_context(default.clone()).await.unwrap();
        backend.install_pdp_context(marked.clone()).await.unwrap();

        runtime
            .state()
            .sport
            .remove(&(S2BU_IFINDEX, [10, 45, 0, 2]));
        for selector in [
            PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&default).unwrap(),
            ),
            PdpContextSelector::Uplink(PdpContextUplinkSelector::from_context(&default).unwrap()),
        ] {
            assert!(matches!(
                backend.read_pdp_context(selector).await.unwrap_err(),
                GtpuError::StateIndeterminate { .. }
            ));
        }
        assert_eq!(
            backend
                .install_pdp_context_classified(default.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Indeterminate(PdpContextIndeterminateReason::IncompleteState)
        );
        runtime.state().sport.insert(
            (S2BU_IFINDEX, [10, 45, 0, 2]),
            commit_for_context(&default, MarkedBearerOwnerPhase::Active).encode(),
        );

        let marked_selector = UplinkFarKey {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: 0x1001_u32.to_be_bytes(),
        }
        .encode();
        runtime
            .state()
            .marked_sport
            .remove(&(S2BU_IFINDEX, marked_selector));
        for selector in [
            PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&marked).unwrap(),
            ),
            PdpContextSelector::Uplink(PdpContextUplinkSelector::from_context(&marked).unwrap()),
        ] {
            assert!(matches!(
                backend.read_pdp_context(selector).await.unwrap_err(),
                GtpuError::StateIndeterminate { .. }
            ));
        }
        assert_eq!(
            backend
                .install_pdp_context_classified(marked)
                .await
                .unwrap(),
            PdpContextInstallOutcome::Indeterminate(PdpContextIndeterminateReason::IncompleteState)
        );
    }

    #[tokio::test]
    async fn restart_rejects_each_active_graph_missing_its_explicit_policy() {
        for marked_bearer in [false, true] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let desired = if marked_bearer {
                marked_context(0x1001, 0x1000_0002, 0x2000_0002)
            } else {
                context()
            };
            backend.install_pdp_context(desired).await.unwrap();
            {
                let mut state = runtime.state();
                if marked_bearer {
                    let selector = UplinkFarKey {
                        ue_ip: [10, 45, 0, 2],
                        bearer_mark: 0x1001_u32.to_be_bytes(),
                    }
                    .encode();
                    state.marked_sport.remove(&(S2BU_IFINDEX, selector));
                } else {
                    state.sport.remove(&(S2BU_IFINDEX, [10, 45, 0, 2]));
                }
                state.attached.clear();
                state.default_teid_by_ue.clear();
                state.marked_owner_by_teid.clear();
            }

            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            assert!(matches!(
                restarted.resolve_device("s2bu").await.unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_marked_owner_rebuild"
                }
            ));
            assert!(!runtime.state().attached.contains_key(&S2BU_IFINDEX));
        }
    }

    #[tokio::test]
    async fn unowned_default_source_port_state_fails_closed_on_adoption() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        {
            let mut state = runtime.state();
            let mut orphan = context();
            orphan.local_teid = teid(0x1000_0099);
            orphan.ms_address = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 99));
            orphan.uplink_source_port_policy = selected_source_port(40_000);
            state.sport.insert(
                (S2BU_IFINDEX, [10, 45, 0, 99]),
                commit_for_context(&orphan, MarkedBearerOwnerPhase::Active).encode(),
            );
            state.attached.clear();
            state.default_teid_by_ue.clear();
            state.marked_owner_by_teid.clear();
        }
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_marked_owner_rebuild"
            }
        ));
    }

    #[tokio::test]
    async fn selected_policy_install_failure_rolls_back_explicit_state() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut desired = context();
        desired.uplink_source_port_policy = selected_source_port(40_000);
        runtime.fail_in_order(["far_insert"]);
        assert!(matches!(
            backend
                .install_pdp_context(desired.clone())
                .await
                .unwrap_err(),
            GtpuError::Io {
                operation: "far_insert",
                ..
            }
        ));
        {
            let state = runtime.state();
            assert!(state.sport.is_empty());
            assert!(state.far.is_empty());
            assert!(state.pdr.is_empty());
            assert!(state.default_teid_by_ue.is_empty());
        }
        backend.install_pdp_context(desired.clone()).await.unwrap();
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(desired)
        );
    }

    #[tokio::test]
    async fn missing_source_port_capability_fails_closed_and_is_reported() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        assert_eq!(
            backend.probe().await.unwrap().uplink_source_port_selection,
            GtpuCapability::Available
        );
        runtime.state().sport_map_ready.clear();

        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.uplink_source_port_selection, GtpuCapability::Missing);
        let mut selected = context();
        selected.uplink_source_port_policy = selected_source_port(40_000);
        // Every policy, including legacy 2152, requires the explicit map and
        // is rejected at the capability boundary when it is unavailable.
        assert!(matches!(
            backend.install_pdp_context(selected).await.unwrap_err(),
            GtpuError::Io {
                operation: "ebpf_source_port_datapath",
                ..
            }
        ));
        assert!(matches!(
            backend.install_pdp_context(context()).await.unwrap_err(),
            GtpuError::Io {
                operation: "ebpf_source_port_datapath",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn selected_source_port_survives_restart_adoption_and_readback() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut default = context();
        default.uplink_source_port_policy = selected_source_port(40_000);
        let mut marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        marked.uplink_source_port_policy = selected_source_port(40_001);
        for desired in [&default, &marked] {
            assert_eq!(
                backend
                    .install_pdp_context_classified(desired.clone())
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::Installed
            );
        }
        {
            let mut state = runtime.state();
            state.attached.clear();
            state.default_teid_by_ue.clear();
            state.marked_owner_by_teid.clear();
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime);
        restarted.resolve_device("s2bu").await.unwrap();
        assert_eq!(
            restarted
                .probe()
                .await
                .unwrap()
                .uplink_source_port_selection,
            GtpuCapability::Available
        );
        for desired in [&default, &marked] {
            assert_eq!(
                restarted
                    .install_pdp_context_classified(desired.clone())
                    .await
                    .unwrap(),
                PdpContextInstallOutcome::ExactAlreadyPresent
            );
            assert_eq!(
                restarted
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Present(desired.clone())
            );
        }
    }

    #[tokio::test]
    async fn corrupt_zero_source_port_fails_closed_on_adoption_and_readback() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let mut default = context();
        default.uplink_source_port_policy = selected_source_port(40_000);
        backend.install_pdp_context(default.clone()).await.unwrap();
        {
            let mut state = runtime.state();
            state.sport.insert((S2BU_IFINDEX, [10, 45, 0, 2]), [0; 68]);
        }
        assert!(matches!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&default).unwrap(),
                ))
                .await
                .unwrap_err(),
            GtpuError::StateIndeterminate { .. }
        ));
        {
            let mut state = runtime.state();
            state.attached.clear();
            state.default_teid_by_ue.clear();
            state.marked_owner_by_teid.clear();
        }
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_pdp_recovery"
            }
        ));
    }

    #[tokio::test]
    async fn unowned_marked_source_port_state_fails_closed_on_adoption() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let selector = UplinkFarKey {
            ue_ip: [10, 45, 0, 2],
            bearer_mark: 0x1001_u32.to_be_bytes(),
        }
        .encode();
        {
            let mut state = runtime.state();
            let mut orphan = marked_context(0x1001, 0x1000_0099, 0x2000_0099);
            orphan.uplink_source_port_policy = selected_source_port(40_000);
            state.marked_sport.insert(
                (S2BU_IFINDEX, selector),
                commit_for_context(&orphan, MarkedBearerOwnerPhase::Active).encode(),
            );
            state.attached.clear();
            state.default_teid_by_ue.clear();
            state.marked_owner_by_teid.clear();
        }
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "ebpf_marked_owner_rebuild"
            }
        ));
    }

    #[tokio::test]
    async fn committed_v3_adopts_directly_to_pmtu_v5() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let default = context();
        let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        backend.install_pdp_context(default.clone()).await.unwrap();
        backend.install_pdp_context(marked.clone()).await.unwrap();
        let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
        {
            // A committed v3 pin set has neither source-port nor MTU policy
            // maps; the additive migrations must create the source-port maps,
            // materialize a complete Active commit with explicit legacy
            // policy for every retained graph, create the MTU policy maps,
            // and only then commit v5.
            let mut state = runtime.state();
            state.attached.clear();
            state.schema.insert(pin_dir.clone(), FakeSchema::EndpointV3);
            state.sport.clear();
            state.marked_sport.clear();
            state.sport_map_ready.clear();
            state.marked_sport_map_ready.clear();
            state.default_teid_by_ue.clear();
            state.marked_owner_by_teid.clear();
            state.pmtu_map_ready.clear();
            state.pmtu_counters_map_ready.clear();
        }
        runtime.fail_in_order(["source_port_schema_marked_insert"]);
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::Io {
                operation: "source_port_schema_marked_insert",
                ..
            }
        ));
        {
            let state = runtime.state();
            assert_eq!(state.schema.get(&pin_dir), Some(&FakeSchema::EndpointV3));
            assert!(!state.attached.contains_key(&S2BU_IFINDEX));
            assert_eq!(
                state.sport.get(&(S2BU_IFINDEX, [10, 45, 0, 2])),
                Some(&commit_for_context(&default, MarkedBearerOwnerPhase::Active).encode())
            );
            assert!(state.marked_sport.is_empty());
        }
        // A retry validates the partial entry, writes the remaining policy,
        // and only then publishes the v4 attachment and marker.
        restarted.resolve_device("s2bu").await.unwrap();
        assert_eq!(
            restarted.probe().await.unwrap().uplink_pmtu_enforcement,
            GtpuCapability::Available
        );
        assert_eq!(
            runtime.state().schema.get(&pin_dir),
            Some(&FakeSchema::PmtuV5)
        );
        {
            let state = runtime.state();
            assert_eq!(
                state.sport.get(&(S2BU_IFINDEX, [10, 45, 0, 2])),
                Some(&commit_for_context(&default, MarkedBearerOwnerPhase::Active).encode())
            );
            let selector = UplinkFarKey {
                ue_ip: [10, 45, 0, 2],
                bearer_mark: 0x1001_u32.to_be_bytes(),
            }
            .encode();
            assert_eq!(
                state.marked_sport.get(&(S2BU_IFINDEX, selector)),
                Some(&commit_for_context(&marked, MarkedBearerOwnerPhase::Active).encode())
            );
        }
        for desired in [&default, &marked] {
            assert_eq!(
                restarted
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(desired).unwrap(),
                    ))
                    .await
                    .unwrap(),
                PdpContextReadback::Present(desired.clone())
            );
        }

        // A committed v5 pin set that loses an MTU policy map must not be
        // silently recreated on the next restart.
        {
            let mut state = runtime.state();
            state.attached.clear();
            state.pmtu_map_ready.clear();
        }
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::Io {
                operation: "ebpf_bearer_schema",
                ..
            }
        ));
        assert!(!runtime.state().attached.contains_key(&S2BU_IFINDEX));
    }

    #[tokio::test]
    async fn pre_v4_migration_rejects_nonlegacy_or_unowned_partial_policy() {
        for corrupt in ["selected-active", "legacy-orphan"] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            backend.install_pdp_context(context()).await.unwrap();
            let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
            {
                let mut state = runtime.state();
                state.attached.clear();
                state.schema.insert(pin_dir.clone(), FakeSchema::EndpointV3);
                state.sport.clear();
                if corrupt == "selected-active" {
                    let mut selected = context();
                    selected.uplink_source_port_policy = selected_source_port(40_000);
                    state.sport.insert(
                        (S2BU_IFINDEX, [10, 45, 0, 2]),
                        commit_for_context(&selected, MarkedBearerOwnerPhase::Active).encode(),
                    );
                } else {
                    let mut orphan = context();
                    orphan.local_teid = teid(0x1000_0099);
                    orphan.ms_address = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 99));
                    state.sport.insert(
                        (S2BU_IFINDEX, [10, 45, 0, 99]),
                        commit_for_context(&orphan, MarkedBearerOwnerPhase::Active).encode(),
                    );
                }
                state.sport_map_ready.clear();
                state.marked_sport_map_ready.clear();
                state.default_teid_by_ue.clear();
                state.marked_owner_by_teid.clear();
            }

            let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
            assert!(matches!(
                restarted.resolve_device("s2bu").await.unwrap_err(),
                GtpuError::StateIndeterminate {
                    operation: "ebpf_marked_owner_rebuild"
                }
            ));
            let state = runtime.state();
            assert_eq!(state.schema.get(&pin_dir), Some(&FakeSchema::EndpointV3));
            assert!(!state.attached.contains_key(&S2BU_IFINDEX));
        }
    }

    #[tokio::test]
    async fn committed_v4_adopts_to_pmtu_v5_and_v5_map_loss_fails_closed() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
        {
            // A committed v4 pin set has complete source-port commit records
            // but no MTU policy maps yet; the additive migration must create
            // them and commit v5.
            let mut state = runtime.state();
            state.attached.clear();
            state
                .schema
                .insert(pin_dir.clone(), FakeSchema::SourcePortV4);
            state.pmtu_map_ready.clear();
            state.pmtu_counters_map_ready.clear();
        }
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        restarted.resolve_device("s2bu").await.unwrap();
        assert_eq!(
            restarted.probe().await.unwrap().uplink_pmtu_enforcement,
            GtpuCapability::Available
        );
        assert_eq!(
            runtime.state().schema.get(&pin_dir),
            Some(&FakeSchema::PmtuV5)
        );

        // A committed v5 pin set that loses an MTU policy map must not be
        // silently recreated on the next restart.
        {
            let mut state = runtime.state();
            state.attached.clear();
            state.pmtu_map_ready.clear();
        }
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::Io {
                operation: "ebpf_bearer_schema",
                ..
            }
        ));
        assert!(!runtime.state().attached.contains_key(&S2BU_IFINDEX));
    }
    fn mtu_request(
        link_mtu: u16,
        fragmentation: crate::GtpuOuterFragmentPolicy,
    ) -> CreateGtpDeviceRequest {
        let mut request = create_request();
        request.uplink_mtu_policy =
            Some(GtpuUplinkMtuPolicy::new(link_mtu, fragmentation).unwrap());
        request
    }

    #[tokio::test]
    async fn create_device_persists_uplink_mtu_policy_and_reads_back_effective_policy() {
        let (backend, runtime) = backend_with_fake();
        let device = backend
            .create_device(mtu_request(
                1400,
                crate::GtpuOuterFragmentPolicy::SignalPacketTooBig,
            ))
            .await
            .unwrap();
        let policy =
            GtpuUplinkMtuPolicy::new(1400, crate::GtpuOuterFragmentPolicy::SignalPacketTooBig)
                .unwrap();
        assert_eq!(
            runtime.state().pmtu_policy.get(&S2BU_IFINDEX),
            Some(&policy.map_value())
        );
        assert_eq!(
            backend.probe().await.unwrap().uplink_pmtu_enforcement,
            GtpuCapability::Available
        );
        assert_eq!(
            backend.effective_uplink_mtu_policy(&device).await.unwrap(),
            Some(policy)
        );
        assert_eq!(
            backend
                .effective_uplink_mtu_policy(&device)
                .await
                .unwrap()
                .unwrap()
                .inner_mtu(),
            1400 - 36
        );
    }

    #[tokio::test]
    async fn device_without_policy_persists_unset_and_reads_back_none() {
        let (backend, runtime) = backend_with_fake();
        let device = backend.create_device(create_request()).await.unwrap();
        assert_eq!(
            runtime.state().pmtu_policy.get(&S2BU_IFINDEX),
            Some(&[0; UPLINK_PMTU_VALUE_LEN])
        );
        assert_eq!(
            backend.effective_uplink_mtu_policy(&device).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn mtu_policy_survives_restart_adoption_and_readback() {
        let (backend, runtime) = backend_with_fake();
        let device = backend
            .create_device(mtu_request(
                1280,
                crate::GtpuOuterFragmentPolicy::FragmentOuter,
            ))
            .await
            .unwrap();
        runtime.state().attached.clear();

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        let adopted = restarted.resolve_device("s2bu").await.unwrap();
        assert_eq!(adopted.ifindex, device.ifindex);
        assert_eq!(
            restarted
                .effective_uplink_mtu_policy(&adopted)
                .await
                .unwrap(),
            Some(
                GtpuUplinkMtuPolicy::new(1280, crate::GtpuOuterFragmentPolicy::FragmentOuter)
                    .unwrap()
            )
        );
    }

    #[tokio::test]
    async fn corrupt_pmtu_policy_fails_closed_on_readback() {
        let (backend, runtime) = backend_with_fake();
        let device = backend
            .create_device(mtu_request(
                1400,
                crate::GtpuOuterFragmentPolicy::SignalPacketTooBig,
            ))
            .await
            .unwrap();
        // Unknown flag bits are corrupt adopted state.
        runtime
            .state()
            .pmtu_policy
            .insert(S2BU_IFINDEX, [0x05, 0x78, 0x02, 0]);
        assert!(matches!(
            backend.effective_uplink_mtu_policy(&device).await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pmtu_policy_readback"
            })
        ));
    }

    #[tokio::test]
    async fn lost_pmtu_map_fails_capability_and_readback_closed() {
        let (backend, runtime) = backend_with_fake();
        let device = backend
            .create_device(mtu_request(
                1400,
                crate::GtpuOuterFragmentPolicy::SignalPacketTooBig,
            ))
            .await
            .unwrap();
        runtime.state().pmtu_map_ready.clear();
        assert_eq!(
            backend.probe().await.unwrap().uplink_pmtu_enforcement,
            GtpuCapability::Missing
        );
        assert!(matches!(
            backend.effective_uplink_mtu_policy(&device).await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pmtu_policy_readback"
            })
        ));
    }

    #[tokio::test]
    async fn failed_policy_publication_rolls_back_the_attachment() {
        let (backend, runtime) = backend_with_fake();
        runtime.fail_in_order(["pmtu_policy_write"]);
        assert!(matches!(
            backend
                .create_device(mtu_request(
                    1400,
                    crate::GtpuOuterFragmentPolicy::SignalPacketTooBig
                ))
                .await,
            Err(GtpuError::Io {
                operation: "pmtu_policy_write",
                ..
            })
        ));
        let state = runtime.state();
        assert!(!state.attached.contains_key(&S2BU_IFINDEX));
        assert!(state.operations.contains(&"detach"));
    }

    #[tokio::test]
    async fn set_policy_updates_live_device_and_converges_drift() {
        let (backend, runtime) = backend_with_fake();
        let device = backend
            .create_device(mtu_request(
                1400,
                crate::GtpuOuterFragmentPolicy::SignalPacketTooBig,
            ))
            .await
            .unwrap();
        let fragment =
            GtpuUplinkMtuPolicy::new(1280, crate::GtpuOuterFragmentPolicy::FragmentOuter).unwrap();
        backend
            .set_uplink_mtu_policy(&device, Some(fragment))
            .await
            .unwrap();
        assert_eq!(
            backend.effective_uplink_mtu_policy(&device).await.unwrap(),
            Some(fragment)
        );

        // Out-of-band drift converges through the same supported mutation.
        runtime.state().pmtu_policy.insert(
            S2BU_IFINDEX,
            GtpuUplinkMtuPolicy::new(9000, crate::GtpuOuterFragmentPolicy::SignalPacketTooBig)
                .unwrap()
                .map_value(),
        );
        let strict =
            GtpuUplinkMtuPolicy::new(1400, crate::GtpuOuterFragmentPolicy::SignalPacketTooBig)
                .unwrap();
        backend
            .set_uplink_mtu_policy(&device, Some(strict))
            .await
            .unwrap();
        assert_eq!(
            backend.effective_uplink_mtu_policy(&device).await.unwrap(),
            Some(strict)
        );

        // None restores the explicit unset (legacy) state.
        backend.set_uplink_mtu_policy(&device, None).await.unwrap();
        assert_eq!(
            backend.effective_uplink_mtu_policy(&device).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn create_without_policy_preserves_persisted_policy() {
        let (backend, runtime) = backend_with_fake();
        backend
            .create_device(mtu_request(
                1400,
                crate::GtpuOuterFragmentPolicy::SignalPacketTooBig,
            ))
            .await
            .unwrap();
        let strict =
            GtpuUplinkMtuPolicy::new(1400, crate::GtpuOuterFragmentPolicy::SignalPacketTooBig)
                .unwrap();
        runtime.state().attached.clear();

        // A recreate that leaves the policy unspecified must not silently
        // reset the persisted strict policy to the legacy behavior.
        let recreated = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        let device = recreated.create_device(create_request()).await.unwrap();
        assert_eq!(
            recreated
                .effective_uplink_mtu_policy(&device)
                .await
                .unwrap(),
            Some(strict)
        );
    }

    #[tokio::test]
    async fn corrupt_policy_fails_adoption_closed() {
        let (backend, runtime) = backend_with_fake();
        backend
            .create_device(mtu_request(
                1400,
                crate::GtpuOuterFragmentPolicy::SignalPacketTooBig,
            ))
            .await
            .unwrap();
        {
            let mut state = runtime.state();
            state.attached.clear();
            state
                .pmtu_policy
                .insert(S2BU_IFINDEX, [0x05, 0x78, 0x02, 0]);
        }
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await,
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_pmtu_policy_adopt"
            })
        ));
        assert!(!runtime.state().attached.contains_key(&S2BU_IFINDEX));
    }
}
