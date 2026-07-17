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
    DownlinkPdr, MarkedBearerOwner, MarkedBearerOwnerPhase, MarkedDownlinkPdr, UplinkFar,
    UplinkFarKey, DOWNLINK_PDR_VALUE_LEN, MARKED_BEARER_OWNER_VALUE_LEN,
    MARKED_DOWNLINK_PDR_VALUE_LEN, UPLINK_DSCP_VALUE_LEN, UPLINK_FAR_VALUE_LEN,
    UPLINK_MARK_KEY_LEN,
};

use crate::{
    CreateGtpDeviceRequest, GtpDevice, GtpPdpContext, GtpVersion, GtpuBackendKind, GtpuCapability,
    GtpuDataplaneBackend, GtpuError, GtpuProbe, RemovePdpContextRequest,
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

    /// Read counters only after proving the live hooks and exact named pins.
    fn datapath_snapshot(&self, ifindex: u32) -> Result<EbpfGtpuDatapathSnapshot, GtpuError>;

    /// Probe the environment for eBPF datapath readiness.
    fn probe_environment(&self) -> EbpfEnvironment;

    /// Return whether the target interface's live uplink filter is the exact
    /// loaded program and references the exact pinned DSCP map.
    fn dscp_datapath_usable(&self, ifindex: u32) -> bool;

    /// Return whether both live filters are the exact loaded programs and
    /// reference every exact pinned per-bearer mark map.
    fn bearer_mark_datapath_usable(&self, ifindex: u32) -> bool;

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

    fn rollback_dscp_insert(
        &self,
        ifindex: u32,
        key: [u8; 4],
        dscp_was_inserted: bool,
        source: GtpuError,
    ) -> Result<(), GtpuError> {
        if !dscp_was_inserted || self.inner.runtime.dscp_remove(ifindex, key).is_ok() {
            Err(source)
        } else {
            Err(GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            })
        }
    }

    fn install_marked_pdp_context(
        &self,
        ifindex: u32,
        far_key: [u8; UPLINK_MARK_KEY_LEN],
        far_value: [u8; UPLINK_FAR_VALUE_LEN],
        pdr_key: [u8; 4],
        pdr_value: [u8; MARKED_DOWNLINK_PDR_VALUE_LEN],
        dscp_value: Option<[u8; UPLINK_DSCP_VALUE_LEN]>,
    ) -> Result<(), GtpuError> {
        let owner_dscp = dscp_value.map(|value| value[0]);
        let pending_owner = MarkedBearerOwner::new(
            pdr_key,
            UplinkFar::decode(&far_value),
            owner_dscp,
            MarkedBearerOwnerPhase::Pending,
        );
        let active_owner = MarkedBearerOwner::new(
            pdr_key,
            UplinkFar::decode(&far_value),
            owner_dscp,
            MarkedBearerOwnerPhase::Active,
        );
        let selector_value = UplinkFarKey::decode(&far_key);
        let decoded_pdr = MarkedDownlinkPdr::decode(&pdr_value);
        if !pending_owner.is_valid()
            || selector_value.encode() != far_key
            || decoded_pdr.encode() != pdr_value
            || decoded_pdr.ue_ip != selector_value.ue_ip
            || decoded_pdr.bearer_mark != selector_value.bearer_mark
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context",
            });
        }

        let existing_owner = self.inner.runtime.marked_owner_get(ifindex, far_key)?;
        if let Some(encoded) = existing_owner {
            let owner = MarkedBearerOwner::decode(&encoded);
            if !owner.is_valid() {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_install_pdp_context",
                });
            }
            if owner.phase == MarkedBearerOwnerPhase::Removing {
                self.finish_marked_pdp_context_removal(ifindex, far_key, owner)?;
                // Removal already won its publication race. This call
                // completes that committed transaction, but must not
                // resurrect the bearer in the same install attempt: a
                // delayed pre-removal retry is indistinguishable from a new
                // desired install without a caller transaction ID.
                return Err(GtpuError::RetryRequired {
                    operation: "ebpf_install_after_removal",
                });
            }
        }

        // A local TEID is globally unique across default PDRs and every
        // journal phase, including a crash before marked PDR publication.
        if self.inner.runtime.pdr_get(ifindex, pdr_key)?.is_some() {
            return Err(GtpuError::AlreadyExists);
        }
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
                    self.finish_marked_pdp_context_removal(ifindex, selector, owner)?;
                    return Err(GtpuError::RetryRequired {
                        operation: "ebpf_install_after_removal",
                    });
                }
                return Err(GtpuError::AlreadyExists);
            }
        }

        let existing_far = self.inner.runtime.marked_far_get(ifindex, far_key)?;
        let existing_pdr = self.inner.runtime.marked_pdr_get(ifindex, pdr_key)?;
        let existing_dscp = self.inner.runtime.marked_dscp_get(ifindex, far_key)?;
        match existing_owner {
            None => {
                // This schema has never shipped without the owner journal.
                // Unowned forwarding state is corruption, not a recoverable
                // partial install, and must not be claimed by a new request.
                if existing_far.is_some() || existing_pdr.is_some() || existing_dscp.is_some() {
                    return Err(GtpuError::StateIndeterminate {
                        operation: "ebpf_install_pdp_context",
                    });
                }
                self.inner
                    .runtime
                    .marked_owner_insert(ifindex, far_key, pending_owner.encode())?;
            }
            Some(encoded) => {
                let existing_owner = MarkedBearerOwner::decode(&encoded);
                if existing_owner.local_teid != pdr_key {
                    return Err(GtpuError::AlreadyExists);
                }
                if existing_owner.uplink_far != pending_owner.uplink_far {
                    return Err(GtpuError::AlreadyExists);
                }
                if existing_owner.phase == MarkedBearerOwnerPhase::Active {
                    let old_dscp = existing_owner.egress_dscp().map(|value| [value]);
                    let complete = existing_far == Some(far_value)
                        && existing_pdr == Some(pdr_value)
                        && existing_dscp == old_dscp;
                    if !complete {
                        return Err(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        });
                    }
                    if existing_owner.egress_dscp() == owner_dscp {
                        return Ok(());
                    }
                    // Phase-gate a DSCP-only update before changing its map.
                    self.inner.runtime.marked_owner_insert(
                        ifindex,
                        far_key,
                        pending_owner.encode(),
                    )?;
                } else if existing_owner != pending_owner {
                    // Only the exact request that published Pending may
                    // resume it after a crash.
                    return Err(GtpuError::AlreadyExists);
                }
            }
        }

        let publish = (|| {
            // Pending blocks both classifiers. Reconcile only exact identity
            // state, publish the PDR last, then atomically commit Active.
            if existing_far.is_some_and(|value| value != far_value)
                || existing_pdr.is_some_and(|value| value != pdr_value)
            {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_install_pdp_context",
                });
            }
            match existing_dscp {
                Some(existing) if Some(existing) == dscp_value => {}
                Some(_) if dscp_value.is_none() => {
                    self.inner.runtime.marked_dscp_remove(ifindex, far_key)?;
                }
                _ => {
                    if let Some(value) = dscp_value {
                        self.inner
                            .runtime
                            .marked_dscp_insert(ifindex, far_key, value)?;
                    }
                }
            }
            if existing_far.is_none() {
                self.inner
                    .runtime
                    .marked_far_insert(ifindex, far_key, far_value)?;
            }
            if existing_pdr.is_none() {
                self.inner
                    .runtime
                    .marked_pdr_insert(ifindex, pdr_key, pdr_value)?;
            }
            self.inner
                .runtime
                .marked_owner_insert(ifindex, far_key, active_owner.encode())
        })();
        publish.map_err(|_| GtpuError::StateIndeterminate {
            operation: "ebpf_install_pdp_context",
        })
    }

    fn finish_marked_pdp_context_removal(
        &self,
        ifindex: u32,
        selector: [u8; UPLINK_MARK_KEY_LEN],
        owner: MarkedBearerOwner,
    ) -> Result<(), GtpuError> {
        let owner_key = UplinkFarKey::decode(&selector);
        let expected_pdr = MarkedDownlinkPdr {
            ue_ip: owner_key.ue_ip,
            bearer_mark: owner_key.bearer_mark,
        }
        .encode();
        let legacy_pdr = self.inner.runtime.pdr_get(ifindex, owner.local_teid)?;
        let indexed_selector = self
            .inner
            .runtime
            .marked_owner_for_teid(ifindex, owner.local_teid)?;
        let marked_pdr = self
            .inner
            .runtime
            .marked_pdr_get(ifindex, owner.local_teid)?;
        if !owner.is_valid()
            || owner_key.ue_ip == [0; 4]
            || owner_key.bearer_mark == [0; 4]
            || legacy_pdr.is_some()
            || indexed_selector != Some(selector)
            || marked_pdr.is_some_and(|value| value != expected_pdr)
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        let far = self.inner.runtime.marked_far_get(ifindex, selector)?;
        let dscp = self.inner.runtime.marked_dscp_get(ifindex, selector)?;
        if far.is_some_and(|value| value != owner.uplink_far.encode())
            || dscp.is_some_and(|value| value[0] > 63)
            || owner.phase == MarkedBearerOwnerPhase::Active
                && dscp.map(|value| value[0]) != owner.egress_dscp()
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        if owner.phase != MarkedBearerOwnerPhase::Removing {
            let removing = MarkedBearerOwner::new(
                owner.local_teid,
                owner.uplink_far,
                owner.egress_dscp(),
                MarkedBearerOwnerPhase::Removing,
            );
            self.inner
                .runtime
                .marked_owner_insert(ifindex, selector, removing.encode())?;
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
                .marked_pdr_remove(ifindex, owner.local_teid)
                .is_err()
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }
        match self.inner.runtime.marked_owner_remove(ifindex, selector) {
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

    fn install_pdp_context_sync(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
        let _operation = self.operation_guard()?;
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

        let far_value = UplinkFar {
            peer_ip: peer_address.octets(),
            local_ip: local_ip.octets(),
            o_teid: request.peer_teid.get().to_be_bytes(),
        }
        .encode();
        let pdr_key = request.local_teid.get().to_be_bytes();
        let dscp_value = request.egress_dscp.map(|value| [value.get()]);
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
                far_key,
                far_value,
                pdr_key,
                pdr_value,
                dscp_value,
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

        let existing_far = self.inner.runtime.far_get(request.link_ifindex, far_key)?;
        let existing_pdr = self.inner.runtime.pdr_get(request.link_ifindex, pdr_key)?;
        let existing_dscp = self.inner.runtime.dscp_get(request.link_ifindex, far_key)?;
        match (existing_far, existing_pdr, existing_dscp) {
            // Exact re-install of the same session state is idempotent.
            (Some(far), Some(pdr), dscp)
                if far == far_value && pdr == pdr_value && dscp == dscp_value =>
            {
                Ok(())
            }
            // DSCP is an independently keyed one-byte subresource. When the
            // session's FAR/PDR identity is unchanged, reconcile only that
            // map entry with one atomic BPF hash operation.
            (Some(far), Some(pdr), _existing_dscp) if far == far_value && pdr == pdr_value => {
                match dscp_value {
                    Some(dscp) => {
                        self.inner
                            .runtime
                            .dscp_insert(request.link_ifindex, far_key, dscp)
                    }
                    None => self
                        .inner
                        .runtime
                        .dscp_remove(request.link_ifindex, far_key)
                        .map(|_| ()),
                }
            }
            (None, None, existing_dscp) => {
                // DSCP is published before FAR/PDR so a packet can never see
                // new routing without its requested marking. A process crash
                // in that first step can therefore leave a DSCP-only orphan.
                // With both identity maps absent, that orphan claims no live
                // session and is safe to reconcile before retrying the exact
                // install. Any one-sided FAR/PDR state remains ambiguous and
                // is rejected by the catch-all arm below.
                match (existing_dscp, dscp_value) {
                    (Some(existing), Some(requested)) if existing == requested => {}
                    (_, Some(requested)) => {
                        self.inner
                            .runtime
                            .dscp_insert(request.link_ifindex, far_key, requested)?
                    }
                    (Some(_), None) => {
                        self.inner
                            .runtime
                            .dscp_remove(request.link_ifindex, far_key)?;
                    }
                    (None, None) => {}
                }
                if let Err(error) =
                    self.inner
                        .runtime
                        .far_insert(request.link_ifindex, far_key, far_value)
                {
                    return self.rollback_dscp_insert(
                        request.link_ifindex,
                        far_key,
                        dscp_value.is_some(),
                        error,
                    );
                }
                if let Err(error) =
                    self.inner
                        .runtime
                        .pdr_insert(request.link_ifindex, pdr_key, pdr_value)
                {
                    let far_rolled_back = self
                        .inner
                        .runtime
                        .far_remove(request.link_ifindex, far_key)
                        .is_ok();
                    let dscp_rolled_back = dscp_value.is_none()
                        || self
                            .inner
                            .runtime
                            .dscp_remove(request.link_ifindex, far_key)
                            .is_ok();
                    return if far_rolled_back && dscp_rolled_back {
                        Err(error)
                    } else {
                        Err(GtpuError::StateIndeterminate {
                            operation: "ebpf_install_pdp_context",
                        })
                    };
                }
                Ok(())
            }
            // A different session already claims this UE PAA or TEID.
            _ => Err(GtpuError::AlreadyExists),
        }
    }

    fn remove_pdp_context_sync(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        let _operation = self.operation_guard()?;
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
        let legacy_pdr = self.inner.runtime.pdr_get(request.link_ifindex, pdr_key)?;
        let marked_pdr = self
            .inner
            .runtime
            .marked_pdr_get(request.link_ifindex, pdr_key)?;
        if owner_selector.is_some() && legacy_pdr.is_some()
            || owner_selector.is_none() && marked_pdr.is_some()
            || legacy_pdr.is_some() && marked_pdr.is_some()
        {
            return Err(GtpuError::StateIndeterminate {
                operation: "ebpf_remove_pdp_context",
            });
        }

        if let Some(selector) = owner_selector {
            let encoded_owner = self
                .inner
                .runtime
                .marked_owner_get(request.link_ifindex, selector)?
                .ok_or(GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context",
                })?;
            let owner = MarkedBearerOwner::decode(&encoded_owner);
            if owner.local_teid != pdr_key {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context",
                });
            }
            return self.finish_marked_pdp_context_removal(request.link_ifindex, selector, owner);
        }

        let Some(legacy_pdr) = legacy_pdr else {
            // Removal is idempotent when neither schema owns the TEID.
            return Ok(());
        };
        let ue_ip = DownlinkPdr::decode(&legacy_pdr).ue_ip;
        let far_existed = self.inner.runtime.far_remove(request.link_ifindex, ue_ip)?;
        let dscp_result = self.inner.runtime.dscp_remove(request.link_ifindex, ue_ip);
        let dscp_existed = match dscp_result {
            Ok(existed) => existed,
            Err(error) => {
                return if far_existed {
                    Err(GtpuError::StateIndeterminate {
                        operation: "ebpf_remove_pdp_context",
                    })
                } else {
                    Err(error)
                };
            }
        };
        let pdr_result = self.inner.runtime.pdr_remove(request.link_ifindex, pdr_key);
        if let Err(error) = pdr_result {
            return if far_existed || dscp_existed {
                Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_remove_pdp_context",
                })
            } else {
                Err(error)
            };
        }
        Ok(())
    }

    fn probe_sync(&self) -> GtpuProbe {
        let env = self.inner.runtime.probe_environment();
        let (has_attached_device, dscp_datapath_usable, bearer_mark_datapath_usable) = self
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
                            self.inner.runtime.bearer_mark_datapath_usable(*ifindex)
                        }),
                )
            })
            .unwrap_or((false, false, false));
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

fn poisoned_lock() -> io::Error {
    io::Error::other("gtpu ebpf backend mutex poisoned")
}

#[cfg(target_os = "linux")]
mod aya_runtime {
    //! aya-based kernel runtime: loads the committed CO-RE object, attaches
    //! tc clsact filters, and performs pinned BPF map operations.

    use std::collections::HashMap;
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
    use opc_linux_gtpu_sys as sys;

    use opc_gtpu_ebpf_common::{
        MarkedBearerOwner, MarkedBearerOwnerPhase, MarkedDownlinkPdr, UplinkFarKey,
        COUNTER_DL_DECAP, COUNTER_DL_DST_MISMATCH, COUNTER_DL_MALFORMED, COUNTER_DL_UNKNOWN_TEID,
        COUNTER_UL_ENCAP, COUNTER_UL_FAR_MISS, DOWNLINK_PDR_VALUE_LEN, MAP_CONFIG, MAP_COUNTERS,
        MAP_DOWNLINK_MARK_PDR, MAP_DOWNLINK_PDR, MAP_MARKED_BEARER_OWNER, MAP_UPLINK_DSCP,
        MAP_UPLINK_FAR, MAP_UPLINK_MARK_DSCP, MAP_UPLINK_MARK_FAR, MARKED_BEARER_OWNER_VALUE_LEN,
        MARKED_DOWNLINK_PDR_VALUE_LEN, PROG_DOWNLINK, PROG_UPLINK,
        UPLINK_BEARER_SCHEMA_MARKER_VALUE, UPLINK_DSCP_SCHEMA_MARKER_KEY,
        UPLINK_DSCP_SCHEMA_MARKER_VALUE, UPLINK_DSCP_VALUE_LEN, UPLINK_FAR_VALUE_LEN,
        UPLINK_MARK_KEY_LEN,
    };

    use super::{
        EbpfEnvironment, EbpfGtpuDatapathCounters, EbpfGtpuDatapathSnapshot, EbpfGtpuRuntime,
    };
    use crate::GtpuError;

    /// The committed CO-RE datapath object built by
    /// `scripts/build-gtpu-ebpf.sh` from `crates/opc-gtpu-dataplane-ebpf`.
    const DATAPATH_OBJECT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf/opc-gtpu-datapath.bpf.o"
    ));
    /// Frozen pre-bearer-mark object used only to prove exact live v1 filter
    /// ownership during the bounded v1-to-v2 pin-schema migration.
    const LEGACY_V1_DATAPATH_OBJECT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf/opc-gtpu-datapath-v1.bpf.o"
    ));

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
                .field("tc_priority", &self.tc_priority)
                .field("datapath_identity", &self.datapath_identity)
                .finish_non_exhaustive()
        }
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
        downlink_pdr: u32,
        downlink_mark_pdr: u32,
        marked_owner: u32,
        counters: u32,
        config: u32,
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
                MAP_DOWNLINK_PDR,
                MAP_DOWNLINK_MARK_PDR,
                MAP_MARKED_BEARER_OWNER,
                MAP_COUNTERS,
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

        /// Determine which additive map schema this pin set has committed.
        /// The marker lives in the pre-existing FAR map so it remains
        /// available when a required additive pin is accidentally removed.
        /// This check must run before `load_pinned`, because Aya otherwise
        /// creates a missing pinned-by-name map and conceals durable state
        /// loss.
        fn bearer_schema_preflight(pin_dir: &Path) -> Result<BearerSchemaState, GtpuError> {
            let far_pin = pin_dir.join(MAP_UPLINK_FAR);
            if !far_pin
                .try_exists()
                .map_err(|error| GtpuError::io("ebpf_bearer_schema", error))?
            {
                for other_pin in [
                    MAP_UPLINK_DSCP,
                    MAP_UPLINK_MARK_FAR,
                    MAP_UPLINK_MARK_DSCP,
                    MAP_DOWNLINK_PDR,
                    MAP_DOWNLINK_MARK_PDR,
                    MAP_MARKED_BEARER_OWNER,
                    MAP_COUNTERS,
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
                UPLINK_BEARER_SCHEMA_MARKER_VALUE,
                0,
            )
            .map_err(|error| map_error("ebpf_bearer_schema", error))
        }

        /// Validate the durable marked-bearer journal and build its bounded
        /// local-TEID uniqueness index before either tc hook can be changed.
        fn marked_owner_index(
            ebpf: &Ebpf,
            local_ip: [u8; 4],
        ) -> Result<HashMap<[u8; 4], [u8; UPLINK_MARK_KEY_LEN]>, GtpuError> {
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

            let mut by_teid = HashMap::new();
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
                    || by_teid.insert(owner.local_teid, selector).is_some()
                {
                    return Err(invalid());
                }

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
                let pdr = match marked_pdr.get(&owner.local_teid, 0) {
                    Ok(value) => Some(value),
                    Err(MapError::KeyNotFound) => None,
                    Err(error) => {
                        return Err(map_error("ebpf_marked_owner_rebuild", error));
                    }
                };
                let expected_far = owner.uplink_far.encode();
                let expected_dscp = owner.egress_dscp().map(|value| [value]);
                let expected_pdr = MarkedDownlinkPdr {
                    ue_ip: selector_value.ue_ip,
                    bearer_mark: selector_value.bearer_mark,
                }
                .encode();
                let resources_match = far.is_none_or(|value| value == expected_far)
                    && dscp.is_none_or(|value| value[0] <= 63)
                    && pdr.is_none_or(|value| value == expected_pdr);
                let complete =
                    far == Some(expected_far) && dscp == expected_dscp && pdr == Some(expected_pdr);
                if !resources_match || (owner.phase == MarkedBearerOwnerPhase::Active && !complete)
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
            Ok(by_teid)
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
                        MAP_MARKED_BEARER_OWNER,
                        MAP_COUNTERS,
                    ],
                )?,
                pins: Self::pinned_map_identity(pin_dir)?,
            })
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
                downlink_pdr: id(MAP_DOWNLINK_PDR)?,
                downlink_mark_pdr: id(MAP_DOWNLINK_MARK_PDR)?,
                marked_owner: id(MAP_MARKED_BEARER_OWNER)?,
                counters: id(MAP_COUNTERS)?,
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
            let downlink_pdr = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(
                ebpf.map(MAP_DOWNLINK_PDR).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let downlink_mark_pdr =
                BpfHashMap::<_, [u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>::try_from(
                    ebpf.map(MAP_DOWNLINK_MARK_PDR).ok_or_else(missing)?,
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
            let config = Array::<_, [u8; 4]>::try_from(ebpf.map(MAP_CONFIG).ok_or_else(missing)?)
                .map_err(|error| map_error("ebpf_map_identity", error))?;
            Ok(PinnedMapIdentity {
                uplink_far: info_id(uplink_far.map())?,
                uplink_mark_far: info_id(uplink_mark_far.map())?,
                uplink_dscp: info_id(uplink_dscp.map())?,
                uplink_mark_dscp: info_id(uplink_mark_dscp.map())?,
                downlink_pdr: info_id(downlink_pdr.map())?,
                downlink_mark_pdr: info_id(downlink_mark_pdr.map())?,
                marked_owner: info_id(marked_owner.map())?,
                counters: info_id(counters.map())?,
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
        let socket = sys::open_route_netlink_socket()
            .map_err(|error| GtpuError::io("tc_filter_dump", error))?;

        // struct tcmsg (20 bytes) + netlink header, RTM_GETTFILTER dump.
        let ifindex = i32::try_from(ifindex).map_err(|_| {
            GtpuError::invalid_config("device.ifindex", "ifindex exceeds i32 range")
        })?;
        let mut request = Vec::with_capacity(36);
        request.extend_from_slice(&36_u32.to_ne_bytes()); // nlmsg_len
        request.extend_from_slice(&sys::RTM_GETTFILTER.to_ne_bytes());
        request.extend_from_slice(&(sys::NLM_F_REQUEST | sys::NLM_F_DUMP).to_ne_bytes());
        request.extend_from_slice(&1_u32.to_ne_bytes()); // sequence
        request.extend_from_slice(&0_u32.to_ne_bytes()); // port id
        request.push(0); // tcm_family = AF_UNSPEC
        request.extend_from_slice(&[0; 3]); // padding
        request.extend_from_slice(&ifindex.to_ne_bytes());
        request.extend_from_slice(&0_u32.to_ne_bytes()); // tcm_handle: all
        request.extend_from_slice(&clsact_parent(attach_type).to_ne_bytes());
        request.extend_from_slice(&0_u32.to_ne_bytes()); // tcm_info: all

        sys::send_message(&socket, &request)
            .map_err(|error| GtpuError::io("tc_filter_dump", error))?;

        let mut buffer = vec![0_u8; 65536];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let length = match sys::receive_message(&socket, &mut buffer) {
                Ok(0) => continue,
                Ok(length) => length,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    if std::time::Instant::now() >= deadline {
                        return Err(GtpuError::io(
                            "tc_filter_dump",
                            io::Error::new(io::ErrorKind::TimedOut, "tc dump timeout"),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Err(error) => return Err(GtpuError::io("tc_filter_dump", error)),
            };
            match parse_tfilter_dump(&buffer[..length], tc_priority)? {
                DumpOutcome::Found(name) => return Ok(Some(name)),
                DumpOutcome::Done => return Ok(None),
                DumpOutcome::More => {}
            }
        }
    }

    enum DumpOutcome {
        Found(FilterOwner),
        Done,
        More,
    }

    /// Walk one datagram of an RTM_GETTFILTER dump looking for the filter at
    /// our handle/priority and return its `TCA_BPF_NAME` when it is a
    /// cls_bpf filter.
    fn parse_tfilter_dump(datagram: &[u8], tc_priority: u16) -> Result<DumpOutcome, GtpuError> {
        const NL_HDR: usize = 16;
        const TCMSG: usize = 20;
        let malformed =
            || GtpuError::io("tc_filter_dump", invalid_data("malformed tc dump response"));

        let mut offset = 0;
        while offset + NL_HDR <= datagram.len() {
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
            match message_type {
                t if t == sys::NLMSG_DONE => return Ok(DumpOutcome::Done),
                t if t == sys::NLMSG_ERROR => return Err(malformed()),
                t if t == sys::NLMSG_NOOP => {}
                t if t == sys::RTM_NEWTFILTER && length >= NL_HDR + TCMSG => {
                    let body = offset + NL_HDR;
                    let handle = read_u32(body + 8)?;
                    let info = read_u32(body + 16)?;
                    let priority = (info >> 16) as u16;
                    if handle == u32::from(TC_HANDLE) && priority == tc_priority {
                        if let Some(owner) =
                            bpf_filter_owner(&datagram[body + TCMSG..offset + length])
                        {
                            return Ok(DumpOutcome::Found(owner));
                        }
                        // Occupied by a non-BPF filter: report a foreign
                        // owner so callers refuse to touch the slot.
                        return Ok(DumpOutcome::Found(FilterOwner {
                            name: String::from("<non-bpf-filter>"),
                            program_id: None,
                        }));
                    }
                }
                _ => {}
            }
            offset += sys::align_to_netlink(length).ok_or_else(malformed)?;
        }
        Ok(DumpOutcome::More)
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
                let marked_owner_by_teid = Self::marked_owner_index(&ebpf, local_ip)?;
                let attached = self.attach_programs(
                    &mut ebpf,
                    interface,
                    ifindex,
                    &canonical_pin_dir,
                    tc_priority,
                    schema_state,
                )?;
                if schema_state != BearerSchemaState::BearerV2 {
                    if let Err(error) = Self::write_bearer_schema_marker(&mut ebpf) {
                        if attached.replaced_existing {
                            // Both exact v2 hooks remain live. Retaining them
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
                Ok((attached, marked_owner_by_teid))
            })();
            let (attached, marked_owner_by_teid) = match provisioned {
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
                    marked_owner_by_teid,
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
            let marked_owner_by_teid = Self::marked_owner_index(&ebpf, local_ip)?;
            let attached = self.attach_programs(
                &mut ebpf,
                interface,
                ifindex,
                &canonical_pin_dir,
                tc_priority,
                schema_state,
            )?;
            if schema_state != BearerSchemaState::BearerV2 {
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
                    marked_owner_by_teid,
                    links: attached.links,
                    pin_dir: canonical_pin_dir,
                    tc_priority,
                    datapath_identity: attached.identity,
                    _reconciler_ownership: reconciler_ownership,
                },
            );
            Ok(local_ip)
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
                if key.ue_ip == [0; 4] || key.bearer_mark == [0; 4] || !owner.is_valid() {
                    return Err(state_indeterminate("ebpf_marked_owner_insert"));
                }
                if device
                    .marked_owner_by_teid
                    .get(&owner.local_teid)
                    .is_some_and(|existing| *existing != selector)
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
                device.marked_owner_by_teid.remove(&owner.local_teid);
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
            let snapshot = EbpfGtpuDatapathSnapshot {
                uplink_program_id: device.datapath_identity.uplink.program_id,
                downlink_program_id: device.datapath_identity.downlink.program_id,
                counters_map_id: device.datapath_identity.pins.counters,
                counters: EbpfGtpuDatapathCounters {
                    uplink_encapsulated: aggregate(COUNTER_UL_ENCAP)?,
                    uplink_far_misses: aggregate(COUNTER_UL_FAR_MISS)?,
                    downlink_decapsulated: aggregate(COUNTER_DL_DECAP)?,
                    downlink_unknown_teid: aggregate(COUNTER_DL_UNKNOWN_TEID)?,
                    downlink_malformed: aggregate(COUNTER_DL_MALFORMED)?,
                    downlink_destination_mismatches: aggregate(COUNTER_DL_DST_MISMATCH)?,
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

        fn bearer_mark_datapath_usable(&self, ifindex: u32) -> bool {
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
                downlink_pdr: 5,
                downlink_mark_pdr: 6,
                marked_owner: 7,
                counters: 8,
                config: 9,
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

        #[test]
        fn exact_slot_non_bpf_filter_is_foreign_not_absent() {
            const NL_HDR: usize = 16;
            const TCMSG: usize = 20;
            let length = NL_HDR + TCMSG;
            let mut message = vec![0_u8; length];
            message[..4].copy_from_slice(&(length as u32).to_ne_bytes());
            message[4..6].copy_from_slice(&sys::RTM_NEWTFILTER.to_ne_bytes());
            let body = NL_HDR;
            message[body + 8..body + 12].copy_from_slice(&u32::from(TC_HANDLE).to_ne_bytes());
            message[body + 16..body + 20].copy_from_slice(
                &(u32::from(crate::ebpf::DEFAULT_TC_PRIORITY) << 16).to_ne_bytes(),
            );

            match parse_tfilter_dump(&message, crate::ebpf::DEFAULT_TC_PRIORITY).unwrap() {
                DumpOutcome::Found(owner) => {
                    assert_eq!(owner.name, "<non-bpf-filter>");
                    assert_eq!(owner.program_id, None);
                }
                DumpOutcome::Done | DumpOutcome::More => {
                    panic!("an occupied exact slot must not be reported absent")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::net::Ipv6Addr;
    use std::sync::{Barrier, Mutex};

    use crate::model::{GtpBearerMark, Teid};
    use crate::GtpAddressFamily;

    use super::*;

    const S2BU_IFINDEX: u32 = 7;

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
        pdr: HashMap<(u32, [u8; 4]), [u8; DOWNLINK_PDR_VALUE_LEN]>,
        marked_pdr: HashMap<(u32, [u8; 4]), [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]>,
        marked_owner:
            HashMap<(u32, [u8; UPLINK_MARK_KEY_LEN]), [u8; MARKED_BEARER_OWNER_VALUE_LEN]>,
        marked_owner_by_teid: HashMap<(u32, [u8; 4]), [u8; UPLINK_MARK_KEY_LEN]>,
        datapath_snapshot: EbpfGtpuDatapathSnapshot,
        dscp_map_ready: HashSet<u32>,
        marked_far_map_ready: HashSet<u32>,
        marked_dscp_map_ready: HashSet<u32>,
        marked_pdr_map_ready: HashSet<u32>,
        marked_owner_map_ready: HashSet<u32>,
        uplink_filter_ready: HashSet<u32>,
        downlink_filter_ready: HashSet<u32>,
        uplink_filter_foreign: HashSet<u32>,
        downlink_filter_foreign: HashSet<u32>,
        pin_identity_invalid: HashSet<u32>,
        // One durable marker state per pin directory, mirroring the single
        // reserved FAR entry used by production.
        schema: HashMap<PathBuf, FakeSchema>,
        operations: Vec<&'static str>,
        failures: VecDeque<&'static str>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeSchema {
        LegacyV0,
        V1Uncommitted,
        DscpV1,
        BearerV2,
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

        fn validate_schema(
            state: &FakeState,
            pin_dir: &Path,
            ifindex: u32,
        ) -> Result<(), GtpuError> {
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
                Some(FakeSchema::BearerV2) => {
                    if state.dscp_map_ready.contains(&ifindex)
                        && state.marked_far_map_ready.contains(&ifindex)
                        && state.marked_dscp_map_ready.contains(&ifindex)
                        && state.marked_pdr_map_ready.contains(&ifindex)
                        && state.marked_owner_map_ready.contains(&ifindex)
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
            }
        }

        fn rebuild_owner_index(
            state: &mut FakeState,
            ifindex: u32,
            local_ip: [u8; 4],
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
                    || state.pdr.contains_key(&(ifindex, owner.local_teid))
                    || rebuilt.insert(owner.local_teid, selector).is_some()
                {
                    return Err(invalid());
                }
                let expected_far = owner.uplink_far.encode();
                let expected_dscp = owner.egress_dscp().map(|value| [value]);
                let expected_pdr = MarkedDownlinkPdr {
                    ue_ip: key.ue_ip,
                    bearer_mark: key.bearer_mark,
                }
                .encode();
                let far = state.marked_far.get(&(ifindex, selector)).copied();
                let dscp = state.marked_dscp.get(&(ifindex, selector)).copied();
                let pdr = state.marked_pdr.get(&(ifindex, owner.local_teid)).copied();
                let resources_match = far.is_none_or(|value| value == expected_far)
                    && dscp.is_none_or(|value| value[0] <= 63)
                    && pdr.is_none_or(|value| value == expected_pdr);
                let complete =
                    far == Some(expected_far) && dscp == expected_dscp && pdr == Some(expected_pdr);
                if !resources_match || (owner.phase == MarkedBearerOwnerPhase::Active && !complete)
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
            state
                .marked_owner_by_teid
                .retain(|(index, _), _| *index != ifindex);
            state.marked_owner_by_teid.extend(
                rebuilt
                    .into_iter()
                    .map(|(teid, selector)| ((ifindex, teid), selector)),
            );
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
            Self::rebuild_owner_index(&mut state, ifindex, local_ip)?;
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
            state.marked_pdr_map_ready.insert(ifindex);
            state.marked_owner_map_ready.insert(ifindex);
            state.uplink_filter_ready.insert(ifindex);
            state.downlink_filter_ready.insert(ifindex);
            state
                .schema
                .insert(pin_dir.to_path_buf(), FakeSchema::BearerV2);
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
            let local_ip = *state
                .pinned_config
                .get(pin_dir)
                .ok_or(GtpuError::NotFound)?;
            Self::validate_schema(&state, pin_dir, ifindex)?;
            Self::rebuild_owner_index(&mut state, ifindex, local_ip)?;
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
            state.marked_pdr_map_ready.insert(ifindex);
            state.marked_owner_map_ready.insert(ifindex);
            state.uplink_filter_ready.insert(ifindex);
            state.downlink_filter_ready.insert(ifindex);
            state
                .schema
                .insert(pin_dir.to_path_buf(), FakeSchema::BearerV2);
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
            state.marked_pdr_map_ready.remove(&ifindex);
            state.marked_owner_map_ready.remove(&ifindex);
            state.uplink_filter_ready.remove(&ifindex);
            state.downlink_filter_ready.remove(&ifindex);
            state.uplink_filter_foreign.remove(&ifindex);
            state.downlink_filter_foreign.remove(&ifindex);
            state.pin_identity_invalid.remove(&ifindex);
            state.schema.remove(pin_dir);
            state.pinned_config.remove(pin_dir);
            state.far.retain(|(index, _), _| *index != ifindex);
            state.marked_far.retain(|(index, _), _| *index != ifindex);
            state.dscp.retain(|(index, _), _| *index != ifindex);
            state.marked_dscp.retain(|(index, _), _| *index != ifindex);
            state.pdr.retain(|(index, _), _| *index != ifindex);
            state.marked_pdr.retain(|(index, _), _| *index != ifindex);
            state.marked_owner.retain(|(index, _), _| *index != ifindex);
            state
                .marked_owner_by_teid
                .retain(|(index, _), _| *index != ifindex);
            Ok(())
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
            Ok(())
        }

        fn far_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            state.operations.push("far_remove");
            Self::fail_if_requested(&mut state, "far_remove")?;
            Ok(state.far.remove(&(ifindex, key)).is_some())
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
            Ok(state.marked_far.remove(&(ifindex, key)).is_some())
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
            Ok(state.dscp.remove(&(ifindex, key)).is_some())
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
            Ok(state.marked_dscp.remove(&(ifindex, key)).is_some())
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
            Ok(())
        }

        fn pdr_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            state.operations.push("pdr_remove");
            Self::fail_if_requested(&mut state, "pdr_remove")?;
            Ok(state.pdr.remove(&(ifindex, key)).is_some())
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
            Ok(state.marked_pdr.remove(&(ifindex, key)).is_some())
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
            if key.ue_ip == [0; 4] || key.bearer_mark == [0; 4] || !owner.is_valid() {
                return Err(GtpuError::StateIndeterminate {
                    operation: "ebpf_marked_owner_insert",
                });
            }
            if state
                .marked_owner_by_teid
                .get(&(ifindex, owner.local_teid))
                .is_some_and(|existing| *existing != selector)
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
            state
                .marked_owner_by_teid
                .remove(&(ifindex, owner.local_teid));
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

        fn datapath_snapshot(&self, ifindex: u32) -> Result<EbpfGtpuDatapathSnapshot, GtpuError> {
            let mut state = self.state();
            let exact = state.attached.contains_key(&ifindex)
                && state.dscp_map_ready.contains(&ifindex)
                && state.marked_far_map_ready.contains(&ifindex)
                && state.marked_dscp_map_ready.contains(&ifindex)
                && state.marked_pdr_map_ready.contains(&ifindex)
                && state.marked_owner_map_ready.contains(&ifindex)
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

        fn probe_environment(&self) -> EbpfEnvironment {
            self.environment
        }

        fn dscp_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.dscp_map_ready.contains(&ifindex)
                && state.uplink_filter_ready.contains(&ifindex)
        }

        fn bearer_mark_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.marked_far_map_ready.contains(&ifindex)
                && state.marked_dscp_map_ready.contains(&ifindex)
                && state.marked_pdr_map_ready.contains(&ifindex)
                && state.marked_owner_map_ready.contains(&ifindex)
                && state.uplink_filter_ready.contains(&ifindex)
                && state.downlink_filter_ready.contains(&ifindex)
        }

        fn pdp_cleanup_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.dscp_map_ready.contains(&ifindex)
                && state.marked_far_map_ready.contains(&ifindex)
                && state.marked_dscp_map_ready.contains(&ifindex)
                && state.marked_pdr_map_ready.contains(&ifindex)
                && state.marked_owner_map_ready.contains(&ifindex)
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
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
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

    fn backend_with_fake() -> (EbpfGtpuDataplaneBackend, Arc<FakeRuntime>) {
        let runtime = Arc::new(FakeRuntime::new());
        let backend = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        (backend, runtime)
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
            counters: EbpfGtpuDatapathCounters {
                uplink_encapsulated: 11,
                uplink_far_misses: 12,
                downlink_decapsulated: 13,
                downlink_unknown_teid: 14,
                downlink_malformed: 15,
                downlink_destination_mismatches: 16,
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
            vec!["dscp_insert", "far_insert", "pdr_insert"]
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
            vec!["dscp_insert", "far_insert", "pdr_insert"]
        );
        assert_eq!(state.dscp.get(&(S2BU_IFINDEX, [10, 45, 0, 2])), Some(&[46]));
        assert_eq!(state.far.len(), 1);
        assert_eq!(state.pdr.len(), 1);
    }

    #[tokio::test]
    async fn one_sided_far_or_pdr_state_remains_an_ambiguous_conflict() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();

        runtime.state().pdr.clear();
        assert!(matches!(
            backend.install_pdp_context(context()).await.unwrap_err(),
            GtpuError::AlreadyExists
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
            GtpuError::AlreadyExists
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
            vec!["dscp_insert", "dscp_insert", "dscp_remove"]
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
                "dscp_insert",
                "far_insert",
                "pdr_insert",
                "far_remove",
                "dscp_remove"
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
    async fn install_conflicting_state_reports_already_exists() {
        let (backend, _runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        backend.install_pdp_context(context()).await.unwrap();

        // Same UE PAA, different peer TEID.
        let mut conflicting_teid = context();
        conflicting_teid.peer_teid = teid(0x3000_0003);
        assert!(matches!(
            backend
                .install_pdp_context(conflicting_teid)
                .await
                .unwrap_err(),
            GtpuError::AlreadyExists
        ));

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
            assert_eq!(
                state.operations,
                vec!["far_remove", "dscp_remove", "pdr_remove"]
            );
        }
        // Removing an absent context is idempotent success.
        backend.remove_pdp_context(remove).await.unwrap();
    }

    #[tokio::test]
    async fn failed_dscp_remove_retains_pdr_journal_for_restart_retry() {
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
            state.attached.clear();
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        restarted.resolve_device("s2bu").await.unwrap();
        restarted
            .remove_pdp_context(remove_request())
            .await
            .unwrap();

        let state = runtime.state();
        assert!(state.far.is_empty());
        assert!(state.dscp.is_empty());
        assert!(state.pdr.is_empty());
        assert_eq!(
            state.operations,
            vec![
                "far_remove",
                "dscp_remove",
                "adopt",
                "far_remove",
                "dscp_remove",
                "pdr_remove"
            ]
        );
    }

    #[tokio::test]
    async fn concurrent_conflicting_installs_never_publish_mixed_subresources() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();

        let mut first = context();
        first.egress_dscp = Some(crate::DscpCodepoint::new(10).unwrap());
        let mut second = context();
        second.peer_teid = teid(0x3000_0003);
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
        assert_eq!(
            usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
            1
        );
        assert!(matches!(
            first_result.as_ref().err().or(second_result.as_ref().err()),
            Some(GtpuError::AlreadyExists)
        ));

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
        assert!(
            (far.o_teid == 0x2000_0001_u32.to_be_bytes() && dscp == 10)
                || (far.o_teid == 0x3000_0003_u32.to_be_bytes() && dscp == 46)
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
    async fn legacy_v0_pin_adoption_commits_full_bearer_schema() {
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
        assert_eq!(probe.per_bearer_marking, GtpuCapability::Available);
        let marked = marked_context(0x1001, 0x1000_0002, 0x2000_0002);
        restarted.install_pdp_context(marked).await.unwrap();
        let state = runtime.state();
        let pin_dir = PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu");
        assert_eq!(state.schema.get(&pin_dir), Some(&FakeSchema::BearerV2));
    }

    #[tokio::test]
    async fn uncommitted_v1_and_committed_v1_adopt_to_bearer_v2() {
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
    async fn committed_v2_fails_closed_when_each_marked_map_is_missing() {
        for missing in ["far", "dscp", "pdr", "owner"] {
            let (backend, runtime) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            {
                let mut state = runtime.state();
                state.attached.clear();
                match missing {
                    "far" => state.marked_far_map_ready.clear(),
                    "dscp" => state.marked_dscp_map_ready.clear(),
                    "pdr" => state.marked_pdr_map_ready.clear(),
                    _ => state.marked_owner_map_ready.clear(),
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
                        encoded[17] = 2;
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
    async fn adopted_v2_required_map_loss_is_not_silently_recreated_on_restart() {
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
                Some(&FakeSchema::BearerV2)
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
            assert!(matches!(
                backend
                    .install_pdp_context(marked_context(0x1001, 0x1000_0002, 0x2000_0002,))
                    .await
                    .unwrap_err(),
                GtpuError::Io {
                    operation: "ebpf_bearer_mark_datapath",
                    ..
                }
            ));
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
            "marked_dscp_insert",
            "marked_far_insert",
            "marked_pdr_insert",
            "marked_owner_insert_active",
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
                let owner = MarkedBearerOwner::decode(
                    state
                        .marked_owner
                        .get(&(S2BU_IFINDEX, selector))
                        .expect("Pending owner must survive every post-reservation cut"),
                );
                assert_eq!(owner.phase, MarkedBearerOwnerPhase::Pending, "{failure}");
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
    async fn dscp_update_cut_restarts_with_pending_old_value_and_converges() {
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
            GtpuError::StateIndeterminate {
                operation: "ebpf_install_pdp_context"
            }
        ));
        {
            let mut state = runtime.state();
            let owner = MarkedBearerOwner::decode(
                state.marked_owner.get(&(S2BU_IFINDEX, selector)).unwrap(),
            );
            assert_eq!(owner.phase, MarkedBearerOwnerPhase::Pending);
            assert_eq!(owner.egress_dscp(), Some(46));
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
    async fn restarted_install_recovers_the_live_owned_without_far_signature() {
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
            assert_eq!(&encoded[16..], &[0xff, 1, 3, 0]);
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
        assert!(matches!(
            restarted
                .install_pdp_context(marked.clone())
                .await
                .unwrap_err(),
            GtpuError::RetryRequired {
                operation: "ebpf_install_after_removal"
            }
        ));
        {
            let state = runtime.state();
            assert!(state.marked_far.is_empty());
            assert!(state.marked_pdr.is_empty());
            assert!(state.marked_owner.is_empty());
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
        for corruption in ["legacy_pdr", "owner_index"] {
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
                if corruption == "legacy_pdr" {
                    state.pdr.insert(
                        (S2BU_IFINDEX, marked.local_teid.get().to_be_bytes()),
                        DownlinkPdr {
                            ue_ip: [10, 45, 0, 2],
                        }
                        .encode(),
                    );
                } else {
                    state.marked_owner_by_teid.clear();
                }
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
    async fn backend_is_trait_object_safe_and_debug_redacts() {
        let (backend, _runtime) = backend_with_fake();
        let debug = format!("{backend:?}");
        assert!(debug.contains("EbpfGtpuDataplaneBackend"));

        let boxed: Box<dyn GtpuDataplaneBackend> = Box::new(backend);
        let probe = boxed.probe().await.unwrap();
        assert_eq!(probe.kind, GtpuBackendKind::LinuxEbpf);
    }
}
