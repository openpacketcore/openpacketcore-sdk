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
use opc_gtpu_ebpf_common::{DownlinkPdr, UplinkFar, DOWNLINK_PDR_VALUE_LEN, UPLINK_FAR_VALUE_LEN};

use crate::{
    CreateGtpDeviceRequest, GtpDevice, GtpPdpContext, GtpVersion, GtpuBackendKind,
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
}

#[derive(Debug, Clone)]
struct ManagedDevice {
    name: String,
    local_ip: Ipv4Addr,
}

struct EbpfGtpuDataplaneBackendInner {
    runtime: Arc<dyn EbpfGtpuRuntime>,
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

    fn create_device_sync(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError> {
        validate_interface_name(&request.name)?;
        let local_ip = require_ipv4(request.bind_address, "device.bind_address")?;
        if local_ip.is_unspecified() {
            return Err(GtpuError::invalid_config(
                "device.bind_address",
                "eBPF backend needs the concrete S2b-U IPv4 as the outer encapsulation source",
            ));
        }
        let ifindex = self.inner.runtime.ifindex_by_name(&request.name)?;
        if self.devices()?.contains_key(&ifindex) {
            return Err(GtpuError::AlreadyExists);
        }
        self.inner.runtime.attach(
            &request.name,
            ifindex,
            &self.pin_dir(&request.name),
            self.inner.config.tc_priority,
            local_ip.octets(),
        )?;
        self.devices()?.insert(
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
        validate_interface_name(&name)?;
        let ifindex = self.inner.runtime.ifindex_by_name(&name)?;
        if let Some(device) = self.devices()?.get(&ifindex) {
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
        self.devices()?.insert(
            ifindex,
            ManagedDevice {
                name: name.clone(),
                local_ip: Ipv4Addr::from(local_ip),
            },
        );
        Ok(GtpDevice { name, ifindex })
    }

    fn remove_device_sync(&self, device: GtpDevice) -> Result<(), GtpuError> {
        validate_interface_name(&device.name)?;
        self.inner.runtime.detach(
            &device.name,
            device.ifindex,
            &self.pin_dir(&device.name),
            self.inner.config.tc_priority,
        )?;
        self.devices()?.remove(&device.ifindex);
        Ok(())
    }

    fn install_pdp_context_sync(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
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

        let existing_far = self.inner.runtime.far_get(request.link_ifindex, far_key)?;
        let existing_pdr = self.inner.runtime.pdr_get(request.link_ifindex, pdr_key)?;
        match (existing_far, existing_pdr) {
            // Exact re-install of the same session state is idempotent.
            (Some(far), Some(pdr)) if far == far_value && pdr == pdr_value => Ok(()),
            (None, None) => {
                self.inner
                    .runtime
                    .far_insert(request.link_ifindex, far_key, far_value)?;
                self.inner
                    .runtime
                    .pdr_insert(request.link_ifindex, pdr_key, pdr_value)?;
                Ok(())
            }
            // A different session already claims this UE PAA or TEID.
            _ => Err(GtpuError::AlreadyExists),
        }
    }

    fn remove_pdp_context_sync(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
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
        let _ = self
            .inner
            .runtime
            .far_remove(request.link_ifindex, far_key)?;
        let _ = self
            .inner
            .runtime
            .pdr_remove(request.link_ifindex, pdr_key)?;
        Ok(())
    }

    fn probe_sync(&self) -> GtpuProbe {
        let env = self.inner.runtime.probe_environment();
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
    use std::path::Path;
    use std::sync::Mutex;

    use aya::maps::{Array, HashMap as BpfHashMap, MapError};
    use aya::programs::links::Link;
    use aya::programs::tc::{NlOptions, SchedClassifierLink, TcAttachOptions, TcError, TcHandle};
    use aya::programs::{tc, ProgramError, SchedClassifier, TcAttachType};
    use aya::{Ebpf, EbpfLoader};
    use opc_linux_gtpu_sys as sys;

    use opc_gtpu_ebpf_common::{
        DOWNLINK_PDR_VALUE_LEN, MAP_CONFIG, MAP_COUNTERS, MAP_DOWNLINK_PDR, MAP_UPLINK_FAR,
        PROG_DOWNLINK, PROG_UPLINK, UPLINK_FAR_VALUE_LEN,
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
    }

    impl AyaGtpuRuntime {
        pub(super) fn new() -> Self {
            Self::default()
        }

        /// Remove the map pins and their directory; absence is tolerated.
        fn unpin(pin_dir: &Path) -> Result<(), GtpuError> {
            for map_name in [MAP_UPLINK_FAR, MAP_DOWNLINK_PDR, MAP_COUNTERS, MAP_CONFIG] {
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

        fn attach_programs(
            &self,
            ebpf: &mut Ebpf,
            interface: &str,
            ifindex: u32,
            tc_priority: u16,
        ) -> Result<(), GtpuError> {
            // clsact may already exist (EEXIST); that is fine.
            if let Err(error) = tc::qdisc_add_clsact(interface) {
                if !is_qdisc_already_present(&error) {
                    return Err(tc_error("ebpf_qdisc_add_clsact", &error));
                }
            }
            attach_program(
                ebpf,
                interface,
                ifindex,
                PROG_UPLINK,
                TcAttachType::Egress,
                tc_priority,
            )?;
            attach_program(
                ebpf,
                interface,
                ifindex,
                PROG_DOWNLINK,
                TcAttachType::Ingress,
                tc_priority,
            )?;
            Ok(())
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

    fn attach_program(
        ebpf: &mut Ebpf,
        interface: &str,
        ifindex: u32,
        name: &str,
        attach_type: TcAttachType,
        tc_priority: u16,
    ) -> Result<(), GtpuError> {
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
        let options = || {
            TcAttachOptions::Netlink(NlOptions {
                priority: tc_priority,
                handle: TC_HANDLE,
                classid: None,
            })
        };
        match program.attach_with_options(interface, attach_type, options()) {
            Ok(_) => Ok(()),
            Err(first_error) => {
                // The priority/handle slot may be occupied. Replace the
                // filter only when it is provably one of ours (same datapath
                // program name, e.g. left behind by a previous process
                // incarnation). A foreign filter is never touched.
                match slot_owner(ifindex, attach_type, tc_priority)? {
                    Some(owner) if owner == name => {}
                    Some(_) => return Err(GtpuError::AlreadyExists),
                    None => return Err(program_error("ebpf_tc_attach", &first_error)),
                }
                let replaced = SchedClassifierLink::attached(
                    interface,
                    attach_type,
                    tc_priority,
                    TC_HANDLE,
                    None,
                )
                .map_err(|error| GtpuError::io("ebpf_tc_replace", error))
                .and_then(|link| {
                    link.detach()
                        .map_err(|error| program_error("ebpf_tc_replace", &error))
                });
                if replaced.is_err() {
                    return Err(program_error("ebpf_tc_attach", &first_error));
                }
                program
                    .attach_with_options(interface, attach_type, options())
                    .map(|_| ())
                    .map_err(|error| program_error("ebpf_tc_attach", &error))
            }
        }
    }

    /// Remove a filter left behind by a previous process incarnation — and
    /// only then. The slot's occupant is read back from the kernel first and
    /// the filter is detached only when its BPF program name is the expected
    /// datapath program; an empty slot or a foreign filter is left alone.
    fn detach_stale(interface: &str, ifindex: u32, attach_type: TcAttachType, tc_priority: u16) {
        let ours = matches!(
            slot_owner(ifindex, attach_type, tc_priority),
            Ok(Some(owner)) if owner == expected_program(attach_type)
        );
        if !ours {
            return;
        }
        if let Ok(link) =
            SchedClassifierLink::attached(interface, attach_type, tc_priority, TC_HANDLE, None)
        {
            let _ = link.detach();
        }
    }

    const fn expected_program(attach_type: TcAttachType) -> &'static str {
        match attach_type {
            TcAttachType::Egress => PROG_UPLINK,
            _ => PROG_DOWNLINK,
        }
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
    ) -> Result<Option<String>, GtpuError> {
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
        Found(String),
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
                        if let Some(name) =
                            bpf_filter_name(&datagram[body + TCMSG..offset + length])
                        {
                            return Ok(DumpOutcome::Found(name));
                        }
                        // Occupied by a non-BPF filter: report a foreign
                        // owner so callers refuse to touch the slot.
                        return Ok(DumpOutcome::Found(String::from("<non-bpf-filter>")));
                    }
                }
                _ => {}
            }
            offset += sys::align_to_netlink(length).ok_or_else(malformed)?;
        }
        Ok(DumpOutcome::More)
    }

    /// Extract `TCA_BPF_NAME` from a filter message's attribute block when
    /// its `TCA_KIND` is `bpf`.
    fn bpf_filter_name(attributes: &[u8]) -> Option<String> {
        let kind = find_attribute(attributes, sys::TCA_KIND)?;
        if kind != b"bpf\0" {
            return None;
        }
        let options = find_attribute(attributes, sys::TCA_OPTIONS)?;
        let name = find_attribute(options, sys::TCA_BPF_NAME)?;
        let name = name.strip_suffix(b"\0").unwrap_or(name);
        Some(String::from_utf8_lossy(name).into_owned())
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
            let mut ebpf = self.load_pinned(pin_dir)?;
            let provisioned = (|| {
                // Record the local address before the programs can see traffic.
                self.config_write(&mut ebpf, local_ip)?;
                self.attach_programs(&mut ebpf, interface, ifindex, tc_priority)
            })();
            if let Err(error) = provisioned {
                // Do not leave half-provisioned pins behind on a fresh attach;
                // dropping `ebpf` detaches whatever was already attached.
                drop(ebpf);
                if !pins_preexisted {
                    let _ = Self::unpin(pin_dir);
                }
                return Err(error);
            }
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| GtpuError::io("ebpf_attach", super::poisoned_lock()))?;
            devices.insert(ifindex, LoadedDevice { ebpf });
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
            let mut ebpf = self.load_pinned(pin_dir)?;
            let local_ip = self.config_read(&ebpf)?;
            if local_ip == [0, 0, 0, 0] {
                // Pins exist but were never provisioned through
                // create_device; drop the maps this load may have freshly
                // pinned instead of leaving empty state behind.
                drop(ebpf);
                let _ = Self::unpin(pin_dir);
                return Err(GtpuError::NotFound);
            }
            self.attach_programs(&mut ebpf, interface, ifindex, tc_priority)?;
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| GtpuError::io("ebpf_adopt", super::poisoned_lock()))?;
            devices.insert(ifindex, LoadedDevice { ebpf });
            Ok(local_ip)
        }

        fn detach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
            tc_priority: u16,
        ) -> Result<(), GtpuError> {
            // Dropping our loaded state detaches the links this process
            // attached; the explicit stale-detach only matters for filters
            // attached by a previous process incarnation.
            let held = {
                let mut devices = self
                    .devices
                    .lock()
                    .map_err(|_| GtpuError::io("ebpf_detach", super::poisoned_lock()))?;
                devices.remove(&ifindex)
            };
            if held.is_none() {
                detach_stale(interface, ifindex, TcAttachType::Egress, tc_priority);
                detach_stale(interface, ifindex, TcAttachType::Ingress, tc_priority);
            }
            drop(held);
            Self::unpin(pin_dir)
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
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv6Addr;
    use std::sync::Mutex;

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
        pdr: HashMap<(u32, [u8; 4]), [u8; DOWNLINK_PDR_VALUE_LEN]>,
        operations: Vec<&'static str>,
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
            state.pinned_config.insert(pin_dir.to_path_buf(), local_ip);
            state.attached.insert(
                ifindex,
                FakeAttachment {
                    interface: interface.to_string(),
                    pin_dir: pin_dir.to_path_buf(),
                    tc_priority,
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
            let mut state = self.state();
            state.operations.push("adopt");
            let local_ip = *state
                .pinned_config
                .get(pin_dir)
                .ok_or(GtpuError::NotFound)?;
            state.attached.insert(
                ifindex,
                FakeAttachment {
                    interface: interface.to_string(),
                    pin_dir: pin_dir.to_path_buf(),
                    tc_priority,
                },
            );
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
            state.pinned_config.remove(pin_dir);
            state.far.retain(|(index, _), _| *index != ifindex);
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
            state.far.insert((ifindex, key), value);
            Ok(())
        }

        fn far_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            state.operations.push("far_remove");
            Ok(state.far.remove(&(ifindex, key)).is_some())
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
            state.pdr.insert((ifindex, key), value);
            Ok(())
        }

        fn pdr_remove(&self, ifindex: u32, key: [u8; 4]) -> Result<bool, GtpuError> {
            let mut state = self.state();
            state.operations.push("pdr_remove");
            Ok(state.pdr.remove(&(ifindex, key)).is_some())
        }

        fn probe_environment(&self) -> EbpfEnvironment {
            self.environment
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
        backend.install_pdp_context(context()).await.unwrap();

        let remove = RemovePdpContextRequest {
            local_teid: teid(0x1000_0001),
            link_ifindex: S2BU_IFINDEX,
            gtp_version: GtpVersion::V1,
            address_family: GtpAddressFamily::Ipv4,
        };
        backend.remove_pdp_context(remove.clone()).await.unwrap();
        {
            let state = runtime.state();
            assert!(state.far.is_empty());
            assert!(state.pdr.is_empty());
        }
        // Removing an absent context is idempotent success.
        backend.remove_pdp_context(remove).await.unwrap();
    }

    #[tokio::test]
    async fn resolve_device_adopts_restored_state_and_reuses_local_ip() {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();

        // Simulate a process restart with surviving pinned state: a fresh
        // backend over the same runtime pins.
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
    async fn probe_reports_ready_only_when_all_capabilities_hold() {
        let ready = EbpfGtpuDataplaneBackend::with_runtime(Arc::new(FakeRuntime::new()));
        let probe = ready.probe().await.unwrap();
        assert_eq!(probe.kind, GtpuBackendKind::LinuxEbpf);
        assert!(probe.platform_supported);
        assert!(probe.net_admin_capable);
        assert!(probe.bpf_capable);
        assert!(probe.btf_present);
        assert!(probe.mutation_ready);
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
