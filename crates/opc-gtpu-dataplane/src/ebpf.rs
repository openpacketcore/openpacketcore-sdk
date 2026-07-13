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
    DownlinkPdr, UplinkFar, DOWNLINK_PDR_VALUE_LEN, UPLINK_DSCP_VALUE_LEN, UPLINK_FAR_VALUE_LEN,
};

use crate::{
    CreateGtpDeviceRequest, GtpDevice, GtpPdpContext, GtpVersion, GtpuBackendKind, GtpuCapability,
    GtpuDataplaneBackend, GtpuError, GtpuProbe, RemovePdpContextRequest,
};

/// Default bpffs directory under which per-interface map pins are created.
pub const DEFAULT_BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/opc-gtpu";
/// Default tc filter priority for the datapath programs.
pub const DEFAULT_TC_PRIORITY: u16 = 50;

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

    /// Probe the environment for eBPF datapath readiness.
    fn probe_environment(&self) -> EbpfEnvironment;

    /// Return whether the target interface's live uplink filter is the exact
    /// loaded program and references the exact pinned DSCP map.
    fn dscp_datapath_usable(&self, ifindex: u32) -> bool;
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

        let far_key = ms_address.octets();
        let far_value = UplinkFar {
            peer_ip: peer_address.octets(),
            local_ip: local_ip.octets(),
            o_teid: request.peer_teid.get().to_be_bytes(),
        }
        .encode();
        let pdr_key = request.local_teid.get().to_be_bytes();
        let pdr_value = DownlinkPdr {
            ue_ip: ms_address.octets(),
        }
        .encode();
        let dscp_value = request.egress_dscp.map(|value| [value.get()]);
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
        let pdr_key = request.local_teid.get().to_be_bytes();
        // Removal is idempotent: an absent context is success.
        let Some(pdr_value) = self.inner.runtime.pdr_get(request.link_ifindex, pdr_key)? else {
            return Ok(());
        };
        let far_key = DownlinkPdr::decode(&pdr_value).ue_ip;
        let far_existed = self
            .inner
            .runtime
            .far_remove(request.link_ifindex, far_key)?;
        let dscp_existed = match self
            .inner
            .runtime
            .dscp_remove(request.link_ifindex, far_key)
        {
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
        if let Err(error) = self.inner.runtime.pdr_remove(request.link_ifindex, pdr_key) {
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
        let (has_attached_device, dscp_datapath_usable) = self
            .devices()
            .map(|devices| {
                (
                    !devices.is_empty(),
                    !devices.is_empty()
                        && devices
                            .keys()
                            .all(|ifindex| self.inner.runtime.dscp_datapath_usable(*ifindex)),
                )
            })
            .unwrap_or((false, false));
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
        DOWNLINK_PDR_VALUE_LEN, MAP_CONFIG, MAP_COUNTERS, MAP_DOWNLINK_PDR, MAP_UPLINK_DSCP,
        MAP_UPLINK_FAR, PROG_DOWNLINK, PROG_UPLINK, UPLINK_DSCP_SCHEMA_MARKER_KEY,
        UPLINK_DSCP_SCHEMA_MARKER_VALUE, UPLINK_DSCP_VALUE_LEN, UPLINK_FAR_VALUE_LEN,
    };

    use super::{EbpfEnvironment, EbpfGtpuRuntime};
    use crate::GtpuError;

    /// The committed CO-RE datapath object built by
    /// `scripts/build-gtpu-ebpf.sh` from `crates/opc-gtpu-dataplane-ebpf`.
    const DATAPATH_OBJECT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf/opc-gtpu-datapath.bpf.o"
    ));

    const TC_HANDLE: TcHandle = TcHandle::new(0, 1);
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_BPF: u32 = 39;

    #[derive(Debug, Default)]
    pub(super) struct AyaGtpuRuntime {
        devices: Mutex<HashMap<u32, LoadedDevice>>,
    }

    #[derive(Debug)]
    struct LoadedDevice {
        ebpf: Ebpf,
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
        uplink_dscp: u32,
        downlink_pdr: u32,
        counters: u32,
        config: u32,
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
                MAP_UPLINK_DSCP,
                MAP_DOWNLINK_PDR,
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

        /// Determine whether this pin set has already adopted the DSCP map
        /// schema. The marker lives in the pre-existing FAR map so it remains
        /// available when the additive DSCP pin is accidentally removed.
        /// This check must run before `load_pinned`, because Aya otherwise
        /// creates a missing pinned-by-name map and conceals durable state
        /// loss.
        fn dscp_schema_preflight(pin_dir: &Path) -> Result<bool, GtpuError> {
            let far_pin = pin_dir.join(MAP_UPLINK_FAR);
            if !far_pin
                .try_exists()
                .map_err(|error| GtpuError::io("ebpf_dscp_schema", error))?
            {
                return Ok(false);
            }

            let map_data = MapData::from_pin(&far_pin)
                .map_err(|error| map_error("ebpf_dscp_schema", error))?;
            let map = Map::from_map_data(map_data)
                .map_err(|error| map_error("ebpf_dscp_schema", error))?;
            let far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
                .map_err(|error| map_error("ebpf_dscp_schema", error))?;
            let marker_present = match far.get(&UPLINK_DSCP_SCHEMA_MARKER_KEY, 0) {
                Ok(value) if value == UPLINK_DSCP_SCHEMA_MARKER_VALUE => true,
                Ok(_) => {
                    return Err(GtpuError::io(
                        "ebpf_dscp_schema",
                        invalid_data("invalid DSCP schema marker"),
                    ));
                }
                Err(MapError::KeyNotFound) => false,
                Err(error) => return Err(map_error("ebpf_dscp_schema", error)),
            };

            if marker_present
                && !pin_dir
                    .join(MAP_UPLINK_DSCP)
                    .try_exists()
                    .map_err(|error| GtpuError::io("ebpf_dscp_schema", error))?
            {
                return Err(GtpuError::io(
                    "ebpf_dscp_schema",
                    io::Error::new(io::ErrorKind::NotFound, "adopted DSCP map pin is missing"),
                ));
            }
            Ok(marker_present)
        }

        fn write_dscp_schema_marker(ebpf: &mut Ebpf) -> Result<(), GtpuError> {
            let map = ebpf
                .map_mut(MAP_UPLINK_FAR)
                .ok_or_else(|| GtpuError::io("ebpf_dscp_schema", invalid_data("map missing")))?;
            let mut far = BpfHashMap::<_, [u8; 4], [u8; UPLINK_FAR_VALUE_LEN]>::try_from(map)
                .map_err(|error| map_error("ebpf_dscp_schema", error))?;
            far.insert(
                UPLINK_DSCP_SCHEMA_MARKER_KEY,
                UPLINK_DSCP_SCHEMA_MARKER_VALUE,
                0,
            )
            .map_err(|error| map_error("ebpf_dscp_schema", error))
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
                    &[MAP_UPLINK_FAR, MAP_UPLINK_DSCP, MAP_COUNTERS, MAP_CONFIG],
                )?,
                downlink: Self::program_identity(
                    ebpf,
                    pin_dir,
                    PROG_DOWNLINK,
                    &[MAP_DOWNLINK_PDR, MAP_COUNTERS],
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
                uplink_dscp: id(MAP_UPLINK_DSCP)?,
                downlink_pdr: id(MAP_DOWNLINK_PDR)?,
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
            let uplink_dscp = BpfHashMap::<_, [u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]>::try_from(
                ebpf.map(MAP_UPLINK_DSCP).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let downlink_pdr = BpfHashMap::<_, [u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]>::try_from(
                ebpf.map(MAP_DOWNLINK_PDR).ok_or_else(missing)?,
            )
            .map_err(|error| map_error("ebpf_map_identity", error))?;
            let counters =
                PerCpuArray::<_, u64>::try_from(ebpf.map(MAP_COUNTERS).ok_or_else(missing)?)
                    .map_err(|error| map_error("ebpf_map_identity", error))?;
            let config = Array::<_, [u8; 4]>::try_from(ebpf.map(MAP_CONFIG).ok_or_else(missing)?)
                .map_err(|error| map_error("ebpf_map_identity", error))?;
            Ok(PinnedMapIdentity {
                uplink_far: info_id(uplink_far.map())?,
                uplink_dscp: info_id(uplink_dscp.map())?,
                downlink_pdr: info_id(downlink_pdr.map())?,
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

        fn attach_programs(
            &self,
            ebpf: &mut Ebpf,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            tc_priority: u16,
        ) -> Result<AttachedDatapath, GtpuError> {
            // clsact may already exist (EEXIST); that is fine.
            if let Err(error) = tc::qdisc_add_clsact(interface) {
                if !is_qdisc_already_present(&error) {
                    return Err(tc_error("ebpf_qdisc_add_clsact", &error));
                }
            }
            let uplink_artifact = load_program(ebpf, PROG_UPLINK)?;
            let downlink_artifact = load_program(ebpf, PROG_DOWNLINK)?;
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
            )?;
            let downlink_slot = preflight_program_slot(
                ifindex,
                PROG_DOWNLINK,
                TcAttachType::Ingress,
                tc_priority,
                &downlink_artifact,
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
                    // The first hook was created by this call. Roll it back
                    // only if its exact program ID still occupies the slot;
                    // an external replacement must survive this failure.
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
                        matches!(uplink_slot, SlotDisposition::ReplaceExact { .. }),
                        "ebpf_tc_attach_rollback",
                    ));
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
    ) -> Result<SlotDisposition, GtpuError> {
        match slot_owner(ifindex, attach_type, tc_priority)? {
            None => Ok(SlotDisposition::Empty),
            Some(owner) if owner_matches_artifact(&owner, name, artifact)? => {
                Ok(SlotDisposition::ReplaceExact {
                    current_program_id: owner.program_id.ok_or_else(|| {
                        GtpuError::io(
                            "ebpf_program_info",
                            invalid_data("tc filter did not report a program id"),
                        )
                    })?,
                })
            }
            Some(_) => Err(GtpuError::AlreadyExists),
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
        if let SlotDisposition::ReplaceExact { current_program_id } = slot {
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
            let link = SchedClassifierLink::attached(
                interface,
                hook.attach_type,
                tc_priority,
                TC_HANDLE,
                None,
            )
            .map_err(|error| GtpuError::io("ebpf_tc_replace", error))?;
            mutation_or_indeterminate(link.detach(), "ebpf_tc_replace")?;
        }
        let options = || {
            TcAttachOptions::Netlink(NlOptions {
                priority: tc_priority,
                handle: TC_HANDLE,
                classid: None,
            })
        };
        let link_id = match program.attach_with_options(interface, hook.attach_type, options()) {
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

    /// Return the BPF program name of the tc filter occupying our exact
    /// (hook, priority, handle) slot, or `None` when the slot is empty or
    /// holds a non-BPF filter whose kind carries no program name.
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
            let dscp_schema_present = Self::dscp_schema_preflight(&canonical_pin_dir)?;
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
                // Record the local address before the programs can see traffic.
                self.config_write(&mut ebpf, local_ip)?;
                let attached = self.attach_programs(
                    &mut ebpf,
                    interface,
                    ifindex,
                    &canonical_pin_dir,
                    tc_priority,
                )?;
                if !dscp_schema_present {
                    if let Err(error) = Self::write_dscp_schema_marker(&mut ebpf) {
                        let replaced_existing = attached.replaced_existing;
                        let rollback = detach_datapath_if_current(
                            attached.links,
                            &attached.identity,
                            ifindex,
                            tc_priority,
                        );
                        return Err(error_after_rollback(
                            error,
                            rollback,
                            replaced_existing,
                            "ebpf_tc_attach_rollback",
                        ));
                    }
                }
                Ok(attached)
            })();
            let attached = match provisioned {
                Ok(attached) => attached,
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
                    let replaced_existing = attached.replaced_existing;
                    let rollback = detach_datapath_if_current(
                        attached.links,
                        &attached.identity,
                        ifindex,
                        tc_priority,
                    );
                    let error = error_after_rollback(
                        GtpuError::io("ebpf_attach", super::poisoned_lock()),
                        rollback,
                        replaced_existing,
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
            let dscp_schema_present = Self::dscp_schema_preflight(&canonical_pin_dir)?;
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
            let attached = self.attach_programs(
                &mut ebpf,
                interface,
                ifindex,
                &canonical_pin_dir,
                tc_priority,
            )?;
            if !dscp_schema_present {
                if let Err(error) = Self::write_dscp_schema_marker(&mut ebpf) {
                    let replaced_existing = attached.replaced_existing;
                    let rollback = detach_datapath_if_current(
                        attached.links,
                        &attached.identity,
                        ifindex,
                        tc_priority,
                    );
                    return Err(error_after_rollback(
                        error,
                        rollback,
                        replaced_existing,
                        "ebpf_tc_attach_rollback",
                    ));
                }
            }
            let mut devices = match self.devices.lock() {
                Ok(devices) => devices,
                Err(_) => {
                    let replaced_existing = attached.replaced_existing;
                    let rollback = detach_datapath_if_current(
                        attached.links,
                        &attached.identity,
                        ifindex,
                        tc_priority,
                    );
                    return Err(error_after_rollback(
                        GtpuError::io("ebpf_adopt", super::poisoned_lock()),
                        rollback,
                        replaced_existing,
                        "ebpf_tc_attach_rollback",
                    ));
                }
            };
            devices.insert(
                ifindex,
                LoadedDevice {
                    ebpf,
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
                match hash.remove(&key) {
                    Ok(()) => Ok(true),
                    Err(MapError::KeyNotFound) => Ok(false),
                    Err(error) => Err(map_error("ebpf_far_remove", error)),
                }
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
                match hash.remove(&key) {
                    Ok(()) => Ok(true),
                    Err(MapError::KeyNotFound) => Ok(false),
                    Err(error) => Err(map_error("ebpf_dscp_remove", error)),
                }
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
                match hash.remove(&key) {
                    Ok(()) => Ok(true),
                    Err(MapError::KeyNotFound) => Ok(false),
                    Err(error) => Err(map_error("ebpf_pdr_remove", error)),
                }
            })
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

    fn invalid_data(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    #[cfg(test)]
    mod race_tests {
        use super::*;

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
                uplink_dscp: 2,
                downlink_pdr: 3,
                counters: 4,
                config: 5,
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
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::net::Ipv6Addr;
    use std::sync::{Barrier, Mutex};

    use crate::model::Teid;
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
        dscp: HashMap<(u32, [u8; 4]), [u8; UPLINK_DSCP_VALUE_LEN]>,
        pdr: HashMap<(u32, [u8; 4]), [u8; DOWNLINK_PDR_VALUE_LEN]>,
        dscp_map_ready: HashSet<u32>,
        uplink_filter_ready: HashSet<u32>,
        // Durable evidence that this pin directory has adopted the additive
        // DSCP schema. Unlike loaded-device state, it survives a simulated
        // process restart and therefore distinguishes legacy adoption from
        // post-adoption map loss.
        dscp_schema_markers: HashSet<PathBuf>,
        operations: Vec<&'static str>,
        failures: VecDeque<&'static str>,
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
            if state.dscp_schema_markers.contains(pin_dir)
                && !state.dscp_map_ready.contains(&ifindex)
            {
                return Err(GtpuError::io(
                    "ebpf_dscp_schema",
                    io::Error::new(io::ErrorKind::NotFound, "adopted DSCP map pin is missing"),
                ));
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
            state.uplink_filter_ready.insert(ifindex);
            state.dscp_schema_markers.insert(pin_dir.to_path_buf());
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
            if state.dscp_schema_markers.contains(pin_dir)
                && !state.dscp_map_ready.contains(&ifindex)
            {
                return Err(GtpuError::io(
                    "ebpf_dscp_schema",
                    io::Error::new(io::ErrorKind::NotFound, "adopted DSCP map pin is missing"),
                ));
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
            state.uplink_filter_ready.insert(ifindex);
            state.dscp_schema_markers.insert(pin_dir.to_path_buf());
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
            state.uplink_filter_ready.remove(&ifindex);
            state.dscp_schema_markers.remove(pin_dir);
            state.pinned_config.remove(pin_dir);
            state.far.retain(|(index, _), _| *index != ifindex);
            state.dscp.retain(|(index, _), _| *index != ifindex);
            state.pdr.retain(|(index, _), _| *index != ifindex);
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

        fn probe_environment(&self) -> EbpfEnvironment {
            self.environment
        }

        fn dscp_datapath_usable(&self, ifindex: u32) -> bool {
            let state = self.state();
            state.attached.contains_key(&ifindex)
                && state.dscp_map_ready.contains(&ifindex)
                && state.uplink_filter_ready.contains(&ifindex)
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
    async fn legacy_pin_adoption_adds_and_validates_the_dscp_map() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        {
            let mut state = runtime.state();
            // Model a pre-DSCP process/object: provisioning pins survive but
            // no loaded device, additive DSCP map, or adoption marker does.
            state.attached.clear();
            state.dscp_map_ready.clear();
            state.dscp_schema_markers.clear();
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        restarted.resolve_device("s2bu").await.unwrap();
        let probe = restarted.probe().await.unwrap();
        assert_eq!(
            probe.egress_dscp_marking,
            GtpuCapability::Available,
            "adopt must create and validate the additive DSCP map"
        );
        let mut marked = context();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        restarted.install_pdp_context(marked).await.unwrap();
    }

    #[tokio::test]
    async fn adopted_dscp_map_loss_is_not_silently_recreated_on_restart() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        {
            let mut state = runtime.state();
            state.attached.clear();
            state.dscp_map_ready.clear();
            assert!(state
                .dscp_schema_markers
                .contains(&PathBuf::from(DEFAULT_BPFFS_PIN_ROOT).join("s2bu")));
        }

        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        assert!(matches!(
            restarted.resolve_device("s2bu").await.unwrap_err(),
            GtpuError::Io {
                operation: "ebpf_dscp_schema",
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
