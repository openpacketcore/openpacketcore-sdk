//! Safe Linux GTP-U backend over the raw netlink sys boundary.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use opc_linux_gtpu_sys::{
    align_to_netlink, ifindex_by_name as linux_ifindex_by_name, open_generic_netlink_socket,
    open_gtpu_udp_socket, open_route_netlink_socket, receive_kernel_message, send_message,
    GtpuIpAddress, GtpuUdpBind, GtpuUdpSocket, AF_INET, AF_INET6, AF_UNSPEC, CTRL_ATTR_FAMILY_ID,
    CTRL_ATTR_FAMILY_NAME, CTRL_CMD_GETFAMILY, CTRL_VERSION, GENL_ID_CTRL, GTPA_FAMILY, GTPA_I_TEI,
    GTPA_LINK, GTPA_MS_ADDR6, GTPA_MS_ADDRESS, GTPA_O_TEI, GTPA_PEER_ADDR6, GTPA_PEER_ADDRESS,
    GTPA_VERSION, GTP_CMD_DELPDP, GTP_CMD_GETPDP, GTP_CMD_NEWPDP, GTP_GENL_NAME, GTP_GENL_VERSION,
    GTP_ROLE_GGSN, GTP_ROLE_SGSN, GTP_V1, IFF_UP, IFLA_GTP_FD1, IFLA_GTP_LOCAL, IFLA_GTP_LOCAL6,
    IFLA_GTP_PDP_HASHSIZE, IFLA_GTP_ROLE, IFLA_IFALIAS, IFLA_IFNAME, IFLA_INFO_DATA,
    IFLA_INFO_KIND, IFLA_LINKINFO, NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_EXCL, NLM_F_REQUEST, RTM_DELLINK, RTM_GETLINK, RTM_NEWLINK,
};

use crate::backend::error_proves_no_requested_mutation;
use crate::model::{classify_dual_selector_state, DualSelectorState};
use crate::{
    CreateGtpDeviceRequest, GtpAddressFamily, GtpDevice, GtpPdpContext, GtpRole, GtpVersion,
    GtpuBackendKind, GtpuCapability, GtpuDataplaneBackend, GtpuDownlinkFragmentContract, GtpuError,
    GtpuProbe, PdpContextIndeterminateReason, PdpContextInstallOutcome,
    PdpContextLocalTeidSelector, PdpContextReadback, PdpContextReconciliationCapabilities,
    PdpContextRemovalOutcome, PdpContextRepairReason, PdpContextSelector, PdpContextUplinkSelector,
    PdpDeviceIncarnation, PdpRestartRecoveryRequest, RemovePdpContextRequest,
    RetainedDeviceConflictReason, RetainedDeviceIdentityOutcome, RetainedDeviceIdentityRequest,
    RetainedDeviceIndeterminateReason, RetainedDeviceRepairReason, Teid, GTPU_PORT,
};

const NETLINK_HEADER_LEN: usize = 16;
const ROUTE_ATTRIBUTE_HEADER_LEN: usize = 4;
const IF_INFO_MESSAGE_LEN: usize = 16;
const GENERIC_NETLINK_HEADER_LEN: usize = 4;
const IFNAMSIZ: usize = 16;
const CAP_NET_ADMIN: u32 = 12;
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const ENODEV: i32 = 19;
#[cfg(target_os = "linux")]
const PDP_TOPOLOGY_LEASE_NAME: &str = "pdp-recovery-topology.lock";
const PDP_DEVICE_ALIAS_PREFIX: &str = "opc-pdp-recovery-v1:";

/// Runtime behavior for the safe Linux GTP-U backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxGtpuDataplaneBackendConfig {
    /// Number of nonblocking receive attempts before returning a timeout.
    pub receive_attempts: u16,
    /// Netlink receive buffer size in bytes.
    pub receive_buffer_len: usize,
    /// Delay between nonblocking receive attempts.
    pub retry_delay: Duration,
}

impl Default for LinuxGtpuDataplaneBackendConfig {
    fn default() -> Self {
        Self {
            receive_attempts: 32,
            receive_buffer_len: 8192,
            retry_delay: Duration::from_millis(1),
        }
    }
}

/// Production Linux kernel GTP-U dataplane backend.
///
/// This backend opens raw route/generic netlink sockets through
/// `opc-linux-gtpu-sys`, encodes SDK request models into Linux GTP UAPI
/// messages, and maps ACK/error responses back into redaction-safe
/// [`GtpuError`] values.
#[derive(Clone)]
pub struct LinuxGtpuDataplaneBackend {
    inner: Arc<LinuxGtpuDataplaneBackendInner>,
}

struct LinuxGtpuDataplaneBackendInner {
    transport: Arc<dyn LinuxGtpuTransport>,
    next_sequence: AtomicU32,
    /// Serializes PDP read/compare/mutate transactions across backend clones.
    pdp_operation_lock: Mutex<()>,
    device_sockets: Mutex<HashMap<u32, GtpuSocketHandle>>,
    config: LinuxGtpuDataplaneBackendConfig,
    /// Durable directory anchoring cross-process PDP restart-recovery leases.
    ///
    /// `None` until [`LinuxGtpuDataplaneBackend::with_pdp_recovery_root`]
    /// binds one; exact restart recovery stays unsupported until it is set.
    pdp_recovery_root: OnceLock<PathBuf>,
}

impl fmt::Debug for LinuxGtpuDataplaneBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxGtpuDataplaneBackend")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl Default for LinuxGtpuDataplaneBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxGtpuDataplaneBackend {
    /// Create a backend using the default netlink transport and configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(LinuxGtpuDataplaneBackendConfig::default())
    }

    /// Create a backend using the default netlink transport and custom config.
    #[must_use]
    pub fn with_config(config: LinuxGtpuDataplaneBackendConfig) -> Self {
        Self {
            inner: Arc::new(LinuxGtpuDataplaneBackendInner {
                transport: Arc::new(NetlinkGtpuTransport),
                next_sequence: AtomicU32::new(1),
                pdp_operation_lock: Mutex::new(()),
                device_sockets: Mutex::new(HashMap::new()),
                config,
                pdp_recovery_root: OnceLock::new(),
            }),
        }
    }

    /// Bind the durable directory that anchors cross-process PDP
    /// restart-recovery leases.
    ///
    /// [`Self::recover_pdp_context_exact`] is unsupported until a recovery
    /// root is bound. The generationless trait method
    /// [`GtpuDataplaneBackend::remove_pdp_context_exact`] remains unsupported
    /// even after binding. The root must be a durable directory shared by
    /// every process that may mutate the same GTP devices; the backend creates
    /// permanent topology and per-device lease files beneath it.
    ///
    /// The path must be absolute and free of parent-directory components so
    /// every process resolves one authority namespace. Bind it before any
    /// operation on any cooperating backend instance. Binding is
    /// shared by every existing and future clone of this backend and cannot be
    /// changed to a different root. Every cooperating SDK, operator, and
    /// maintenance writer of the bound GTP devices must bind the same root;
    /// uncoordinated privileged mutation is outside the supported model.
    ///
    /// The root and its ancestors are trusted security surface: they must have
    /// stable identity and must not be writable or pre-creatable by an
    /// untrusted principal. The supported safety model does not include an
    /// actor that can replace authority files/directories or mutate links and
    /// PDP contexts outside this shared writer boundary. Avoid a world-writable
    /// location such as an unhardened shared `/tmp`.
    pub fn with_pdp_recovery_root(self, root: impl Into<PathBuf>) -> Result<Self, GtpuError> {
        let root = root.into();
        validate_pdp_recovery_root(&root)?;
        // Serialize the authority transition with every operation on all
        // existing clones. Once this returns, a clone cannot still be running
        // an operation admitted before the shared root became visible.
        {
            let _operation = self.pdp_operation_guard()?;
            if let Some(bound) = self.inner.pdp_recovery_root.get() {
                if bound != &root {
                    return Err(GtpuError::invalid_config(
                        "pdp_recovery.root",
                        "recovery root is already bound to a different path",
                    ));
                }
            } else if self.inner.pdp_recovery_root.set(root).is_err() {
                return Err(GtpuError::invalid_config(
                    "pdp_recovery.root",
                    "recovery root binding failed",
                ));
            }
        }
        Ok(self)
    }

    /// Create a Linux GTP device whose durable restart identity is bound to
    /// kernel-observable link metadata.
    ///
    /// The caller must generate and durably commit `incarnation` before this
    /// effect, then persist it beside every
    /// [`PdpRestartRecoveryRequest`] for the device. The recovery root must
    /// already be bound. Creation holds the shared topology authority and
    /// first proves the requested name absent. It stamps and verifies the
    /// incarnation in `IFLA_IFALIAS` before publishing the device; an
    /// ambiguous create acknowledgement is reconciled under that same
    /// authority. Exact restart recovery later proves the alias together with
    /// the device name and ifindex. Process loss before this method returns
    /// can leave an unpublished, unstamped link, which recovery reports as
    /// structural repair rather than treating it as owned PDP state.
    pub async fn create_recoverable_device(
        &self,
        request: CreateGtpDeviceRequest,
        incarnation: PdpDeviceIncarnation,
    ) -> Result<GtpDevice, GtpuError> {
        self.run_blocking("create_recoverable_device", move |backend| {
            backend.create_device_with_incarnation_sync(request, Some(incarnation))
        })
        .await
    }

    #[cfg(test)]
    fn with_transport<T>(transport: T) -> Self
    where
        T: LinuxGtpuTransport + 'static,
    {
        Self {
            inner: Arc::new(LinuxGtpuDataplaneBackendInner {
                transport: Arc::new(transport),
                next_sequence: AtomicU32::new(1),
                pdp_operation_lock: Mutex::new(()),
                device_sockets: Mutex::new(HashMap::new()),
                config: LinuxGtpuDataplaneBackendConfig {
                    receive_attempts: 1,
                    receive_buffer_len: 4096,
                    retry_delay: Duration::ZERO,
                },
                pdp_recovery_root: OnceLock::new(),
            }),
        }
    }

    fn next_sequence(&self) -> u32 {
        let sequence = self.inner.next_sequence.fetch_add(1, Ordering::Relaxed);
        if sequence == 0 {
            1
        } else {
            sequence
        }
    }

    fn pdp_operation_guard(&self) -> Result<std::sync::MutexGuard<'_, ()>, GtpuError> {
        self.inner
            .pdp_operation_lock
            .lock()
            .map_err(|_| GtpuError::io("pdp_context_reconciliation", poisoned_lock()))
    }

    fn bound_pdp_recovery_root(&self) -> Option<&Path> {
        self.inner.pdp_recovery_root.get().map(PathBuf::as_path)
    }

    fn acquire_optional_pdp_topology_writer_lease(
        &self,
    ) -> Result<Option<PdpRecoveryLease>, GtpuError> {
        let Some(root) = self.bound_pdp_recovery_root() else {
            return Ok(None);
        };
        acquire_pdp_topology_lease(root)
            .map(Some)
            .map_err(map_pdp_writer_lease_error)
    }

    fn acquire_optional_pdp_device_writer_lease(
        &self,
        ifindex: u32,
    ) -> Result<Option<PdpRecoveryLease>, GtpuError> {
        let Some(root) = self.bound_pdp_recovery_root() else {
            return Ok(None);
        };
        acquire_pdp_recovery_lease(root, ifindex)
            .map(Some)
            .map_err(map_pdp_writer_lease_error)
    }

    fn route_transact(
        &self,
        operation: &'static str,
        message_type: u16,
        flags: u16,
        body: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, GtpuError> {
        self.transact(NetlinkProtocol::Route, operation, message_type, flags, body)
    }

    fn generic_transact(
        &self,
        operation: &'static str,
        message_type: u16,
        flags: u16,
        body: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, GtpuError> {
        self.transact(
            NetlinkProtocol::Generic,
            operation,
            message_type,
            flags,
            body,
        )
    }

    fn transact(
        &self,
        protocol: NetlinkProtocol,
        operation: &'static str,
        message_type: u16,
        flags: u16,
        body: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, GtpuError> {
        let sequence = self.next_sequence();
        let request = encode_netlink_message(message_type, flags, sequence, &body)?;
        self.inner
            .transport
            .transact(protocol, operation, &request, sequence, self.inner.config)
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

    fn resolve_gtp_family_id(&self) -> Result<u16, GtpuError> {
        let body = encode_generic_family_lookup()?;
        let response = self
            .generic_transact(
                "gtp_family_lookup",
                GENL_ID_CTRL,
                NLM_F_REQUEST | NLM_F_ACK,
                body,
            )?
            .ok_or_else(|| {
                GtpuError::io(
                    "gtp_family_lookup",
                    invalid_data("missing generic family response"),
                )
            })?;
        parse_generic_family_id(&response)
    }

    fn create_device_sync(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError> {
        self.create_device_with_incarnation_sync(request, None)
    }

    fn create_device_with_incarnation_sync(
        &self,
        request: CreateGtpDeviceRequest,
        incarnation: Option<PdpDeviceIncarnation>,
    ) -> Result<GtpDevice, GtpuError> {
        validate_create_device_request(&request)?;
        let _operation = self.pdp_operation_guard()?;
        if incarnation.is_some() && self.bound_pdp_recovery_root().is_none() {
            return Err(GtpuError::UnsupportedFeature {
                feature: "pdp_restart_recovery_authority",
            });
        }
        let _topology_lease = self.acquire_optional_pdp_topology_writer_lease()?;
        if incarnation.is_some() {
            // Establish absence while the shared topology authority is held.
            // That makes a link which appears after an ambiguous create ACK
            // attributable to this request within the supported cooperating-
            // writer model, so it is safe to finish stamping and verifying it.
            match self.inner.transport.ifindex_by_name(&request.name) {
                Err(GtpuError::NotFound) => {}
                Ok(_) => return Err(GtpuError::AlreadyExists),
                Err(error) => return Err(error),
            }
        }
        let socket = self.inner.transport.open_gtpu_socket(
            request.bind_address,
            request.bind_port,
            "gtpu_udp_bind",
        )?;
        let body = encode_create_device_request(&request, socket.raw_fd())?;
        let create_result = self.route_transact(
            "create_device",
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        );
        let create_was_ambiguous = match create_result {
            Ok(_) => false,
            Err(error) if incarnation.is_none() || error_proves_no_requested_mutation(&error) => {
                return Err(error);
            }
            Err(_) => true,
        };
        let ifindex = match self.ifindex_by_name_after_create(&request.name) {
            Ok(ifindex) => ifindex,
            Err(_error) if create_was_ambiguous => {
                return Err(GtpuError::StateIndeterminate {
                    operation: "recoverable_device_provision",
                });
            }
            Err(error) => return Err(error),
        };
        let device = GtpDevice {
            name: request.name,
            ifindex,
        };
        // Creation retains the stronger topology authority through identity
        // publication. Every supported device/PDP writer acquires topology
        // before a per-device lease, so no cooperating writer can observe or
        // mutate this new link until its incarnation has been verified.
        if let Some(incarnation) = incarnation {
            let stamp_result = self.stamp_and_verify_pdp_device_incarnation(&device, incarnation);
            if let Err(stamp_error) = stamp_result {
                let cleanup = self.remove_unpublished_device_sync(&device);
                return match cleanup {
                    Ok(()) => Err(stamp_error),
                    Err(_) => Err(GtpuError::StateIndeterminate {
                        operation: "recoverable_device_provision",
                    }),
                };
            }
        }
        if let Err(retain_error) = self.retain_device_socket(ifindex, socket) {
            if incarnation.is_some() && self.remove_unpublished_device_sync(&device).is_err() {
                return Err(GtpuError::StateIndeterminate {
                    operation: "recoverable_device_provision",
                });
            }
            return Err(retain_error);
        }
        Ok(device)
    }

    fn stamp_and_verify_pdp_device_incarnation(
        &self,
        device: &GtpDevice,
        incarnation: PdpDeviceIncarnation,
    ) -> Result<(), GtpuError> {
        let body = encode_set_device_alias_request(device, incarnation)?;
        let stamp_error = match self.route_transact(
            "pdp_device_identity_stamp",
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        ) {
            Ok(_) => None,
            Err(error) if error_proves_no_requested_mutation(&error) => return Err(error),
            Err(error) => Some(error),
        };
        let expected = encode_pdp_device_alias(incarnation);
        match self.inner.transport.device_alias(device, self.inner.config) {
            Ok(Some(alias)) if alias == expected.as_bytes() => Ok(()),
            Ok(_) => Err(stamp_error.unwrap_or(GtpuError::StateIndeterminate {
                operation: "recoverable_device_identity_stamp",
            })),
            Err(error) => Err(error),
        }
    }

    fn remove_unpublished_device_sync(&self, device: &GtpDevice) -> Result<(), GtpuError> {
        let body = encode_remove_device_request(device)?;
        match self.route_transact(
            "recoverable_device_provision_rollback",
            RTM_DELLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        ) {
            Ok(_) | Err(GtpuError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn resolve_device_sync(&self, name: String) -> Result<GtpDevice, GtpuError> {
        validate_interface_name(&name, "device.name")?;
        let ifindex = self.ifindex_by_name_after_create(&name)?;
        validate_ifindex(ifindex, "device.ifindex")?;
        Ok(GtpDevice { name, ifindex })
    }

    fn remove_device_sync(&self, device: GtpDevice) -> Result<(), GtpuError> {
        validate_device(&device)?;
        let _operation = self.pdp_operation_guard()?;
        let _topology_lease = self.acquire_optional_pdp_topology_writer_lease()?;
        let _device_lease = self.acquire_optional_pdp_device_writer_lease(device.ifindex)?;
        match self.inner.transport.ifindex_by_name(&device.name) {
            Ok(ifindex) if ifindex == device.ifindex => {}
            Ok(_) | Err(GtpuError::NotFound) => {
                return Err(GtpuError::StateIndeterminate {
                    operation: "remove_device_identity_changed",
                });
            }
            Err(error) => return Err(error),
        }
        let body = encode_remove_device_request(&device)?;
        let _ = self.route_transact(
            "remove_device",
            RTM_DELLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )?;
        self.release_device_socket(device.ifindex)?;
        Ok(())
    }

    fn ifindex_by_name_after_create(&self, name: &str) -> Result<u32, GtpuError> {
        let attempts = self.inner.config.receive_attempts.max(1);
        for attempt in 0..attempts {
            match self.inner.transport.ifindex_by_name(name) {
                Ok(ifindex) => return Ok(ifindex),
                Err(GtpuError::NotFound) if attempt + 1 < attempts => {
                    if !self.inner.config.retry_delay.is_zero() {
                        std::thread::sleep(self.inner.config.retry_delay);
                    }
                }
                Err(GtpuError::NotFound) => {
                    return Err(GtpuError::io("ifindex_lookup", not_found("gtp device")));
                }
                Err(error) => return Err(error),
            }
        }

        Err(GtpuError::io("ifindex_lookup", not_found("gtp device")))
    }

    fn retain_device_socket(
        &self,
        ifindex: u32,
        socket: GtpuSocketHandle,
    ) -> Result<(), GtpuError> {
        self.inner
            .device_sockets
            .lock()
            .map_err(|_| GtpuError::io("device_socket_retain", poisoned_lock()))?
            .insert(ifindex, socket);
        Ok(())
    }

    fn release_device_socket(&self, ifindex: u32) -> Result<(), GtpuError> {
        self.inner
            .device_sockets
            .lock()
            .map_err(|_| GtpuError::io("device_socket_release", poisoned_lock()))?
            .remove(&ifindex);
        Ok(())
    }

    fn install_pdp_context_sync(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
        let _operation = self.pdp_operation_guard()?;
        validate_pdp_context(&request)?;
        let _topology_lease = self.acquire_optional_pdp_topology_writer_lease()?;
        let _device_lease = self.acquire_optional_pdp_device_writer_lease(request.link_ifindex)?;
        let family_id = self
            .resolve_gtp_family_id()
            .map_err(map_family_lookup_error)?;
        self.install_pdp_context_with_family_locked(family_id, request)
    }

    fn install_pdp_context_with_family_locked(
        &self,
        family_id: u16,
        request: GtpPdpContext,
    ) -> Result<(), GtpuError> {
        let body = encode_install_pdp_context(&request)?;
        let _ = self.generic_transact(
            "install_pdp_context",
            family_id,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL,
            body,
        )?;
        Ok(())
    }

    fn remove_pdp_context_sync(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        let _operation = self.pdp_operation_guard()?;
        validate_remove_pdp_context_request(&request)?;
        let _topology_lease = self.acquire_optional_pdp_topology_writer_lease()?;
        let _device_lease = self.acquire_optional_pdp_device_writer_lease(request.link_ifindex)?;
        let family_id = self
            .resolve_gtp_family_id()
            .map_err(map_family_lookup_error)?;
        let body = encode_remove_pdp_context(&request)?;
        let _ = self.generic_transact(
            "remove_pdp_context",
            family_id,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )?;
        Ok(())
    }

    fn get_pdp_context_once_locked(
        &self,
        family_id: u16,
        selector: &PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        validate_pdp_context_selector(selector)?;
        let body = encode_get_pdp_context(selector)?;
        let response =
            match self.generic_transact("read_pdp_context", family_id, NLM_F_REQUEST, body) {
                Ok(Some(response)) => response,
                Ok(None) => {
                    return Err(GtpuError::StateIndeterminate {
                        operation: "linux_pdp_context_readback",
                    });
                }
                Err(GtpuError::NotFound) => return Ok(PdpContextReadback::Absent),
                Err(error) => return Err(error),
            };
        parse_pdp_context_response(&response, selector, family_id).map(PdpContextReadback::Present)
    }

    fn get_pdp_context_stable_locked(
        &self,
        family_id: u16,
        selector: &PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        let first = self.get_pdp_context_once_locked(family_id, selector)?;
        let second = self.get_pdp_context_once_locked(family_id, selector)?;
        if first == second {
            Ok(first)
        } else {
            Err(GtpuError::StateIndeterminate {
                operation: "linux_pdp_context_state_changed",
            })
        }
    }

    fn read_pdp_context_sync(
        &self,
        selector: PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        validate_pdp_context_selector(&selector)?;
        let _operation = self.pdp_operation_guard()?;
        let family_id = self
            .resolve_gtp_family_id()
            .map_err(map_family_lookup_error)?;
        self.get_pdp_context_stable_locked(family_id, &selector)
    }

    fn inspect_desired_axes_stable_locked(
        &self,
        family_id: u16,
        desired: &GtpPdpContext,
    ) -> Result<(PdpContextReadback, PdpContextReadback), GtpuError> {
        let local = PdpContextSelector::LocalTeid(
            PdpContextLocalTeidSelector::from_context(desired).ok_or_else(|| {
                GtpuError::invalid_config("pdp.link_ifindex", "ifindex must be nonzero")
            })?,
        );
        let uplink = PdpContextSelector::Uplink(
            PdpContextUplinkSelector::from_context(desired).ok_or_else(|| {
                GtpuError::invalid_config("pdp.ms_address", "MS address must not be unspecified")
            })?,
        );
        let first_local = self.get_pdp_context_once_locked(family_id, &local)?;
        let first_uplink = self.get_pdp_context_once_locked(family_id, &uplink)?;
        let second_local = self.get_pdp_context_once_locked(family_id, &local)?;
        let second_uplink = self.get_pdp_context_once_locked(family_id, &uplink)?;
        if first_local == second_local && first_uplink == second_uplink {
            Ok((first_local, first_uplink))
        } else {
            Err(GtpuError::StateIndeterminate {
                operation: "linux_pdp_context_state_changed",
            })
        }
    }

    fn install_pdp_context_classified_sync(
        &self,
        request: GtpPdpContext,
    ) -> Result<PdpContextInstallOutcome, GtpuError> {
        validate_pdp_context(&request)?;
        let _operation = self.pdp_operation_guard()?;
        let acquire_writer_authority = || {
            let topology = self.acquire_optional_pdp_topology_writer_lease()?;
            let device = self.acquire_optional_pdp_device_writer_lease(request.link_ifindex)?;
            Ok::<_, GtpuError>((topology, device))
        };
        let (_topology_lease, _device_lease) = match acquire_writer_authority() {
            Ok(authority) => authority,
            Err(GtpuError::RetryRequired { .. }) => {
                return Ok(PdpContextInstallOutcome::Indeterminate(
                    PdpContextIndeterminateReason::AuthorityUnavailable,
                ));
            }
            Err(error) => return Err(error),
        };
        let family_id = self
            .resolve_gtp_family_id()
            .map_err(map_family_lookup_error)?;
        let (local, uplink) = match self.inspect_desired_axes_stable_locked(family_id, &request) {
            Ok(observed) => observed,
            Err(GtpuError::StateIndeterminate { .. }) => {
                return Ok(PdpContextInstallOutcome::Indeterminate(
                    PdpContextIndeterminateReason::StateChanged,
                ));
            }
            Err(error) => return Err(error),
        };
        match classify_dual_selector_state(&local, &uplink, &request) {
            DualSelectorState::Exact => Ok(PdpContextInstallOutcome::ExactAlreadyPresent),
            DualSelectorState::Conflict(conflict) => {
                Ok(PdpContextInstallOutcome::Conflict(conflict))
            }
            DualSelectorState::Indeterminate => Ok(PdpContextInstallOutcome::Indeterminate(
                PdpContextIndeterminateReason::IncompleteState,
            )),
            DualSelectorState::BothAbsent => {
                let install =
                    self.install_pdp_context_with_family_locked(family_id, request.clone());
                match install {
                    Ok(()) => {}
                    Err(error) if error_proves_no_requested_mutation(&error) => return Err(error),
                    Err(_error) => {
                        // A non-definitive netlink failure can mean ACK loss
                        // after a committed mutation. Re-read both axes before
                        // classifying it; never treat the error itself as
                        // proof that the context is absent.
                        return match self.inspect_desired_axes_stable_locked(family_id, &request) {
                            Ok((local, uplink)) => {
                                match classify_dual_selector_state(&local, &uplink, &request) {
                                    DualSelectorState::Exact => {
                                        Ok(PdpContextInstallOutcome::ExactAlreadyPresent)
                                    }
                                    DualSelectorState::Conflict(conflict) => {
                                        Ok(PdpContextInstallOutcome::Conflict(conflict))
                                    }
                                    _ => Ok(PdpContextInstallOutcome::Indeterminate(
                                        PdpContextIndeterminateReason::MutationUnconfirmed,
                                    )),
                                }
                            }
                            Err(_) => Ok(PdpContextInstallOutcome::Indeterminate(
                                PdpContextIndeterminateReason::MutationUnconfirmed,
                            )),
                        };
                    }
                }
                match self.inspect_desired_axes_stable_locked(family_id, &request) {
                    Ok((local, uplink)) => {
                        match classify_dual_selector_state(&local, &uplink, &request) {
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
                    Err(_) => Ok(PdpContextInstallOutcome::Indeterminate(
                        PdpContextIndeterminateReason::MutationUnconfirmed,
                    )),
                }
            }
        }
    }
}

impl LinuxGtpuDataplaneBackend {
    /// The trait request lacks durable device-incarnation identity and cannot
    /// safely authorize Linux restart cleanup.
    fn remove_pdp_context_exact_recovery_sync(
        &self,
        _expected: GtpPdpContext,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        Err(GtpuError::UnsupportedFeature {
            feature: "pdp_context_exact_removal",
        })
    }

    /// Acquire exact restart-recovery authority over one durable PDP context
    /// and remove it if it exactly matches the expected identity.
    ///
    /// This is the durable-reconciliation entry point an ePDG-style consumer
    /// uses after process loss: the kernel-GTP PDP context and its GTP device
    /// survive the writer, and the consumer must prove either exact removal or
    /// exact absence of the descriptor before protocol egress. Before any
    /// mutation it acquires the shared topology then per-device authorities
    /// and proves the expected device name, ifindex, and kernel-bound
    /// incarnation. A concurrent cooperating writer cannot overlap the
    /// transaction, and a completed device replacement fails closed without
    /// touching resident state.
    ///
    /// Like [`GtpuDataplaneBackend::remove_pdp_context_exact`], the blocking
    /// worker runs to completion even if the returned future is dropped.
    pub async fn recover_pdp_context_exact(
        &self,
        request: PdpRestartRecoveryRequest,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        self.run_blocking("recover_pdp_context_exact", move |backend| {
            backend.recover_pdp_context_exact_sync(request)
        })
        .await
    }

    fn recover_pdp_context_exact_sync(
        &self,
        request: PdpRestartRecoveryRequest,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        let device = request.device().clone();
        let expected = request.expected().clone();
        validate_device(&device)?;
        validate_pdp_context(&expected)?;
        if expected.link_ifindex != device.ifindex {
            return Err(GtpuError::invalid_config(
                "recovery.device_ifindex",
                "device ifindex must match the expected context link",
            ));
        }
        let _operation = self.pdp_operation_guard()?;
        let root = self.pdp_recovery_root_or_unsupported()?;
        let _topology_lease = match acquire_pdp_topology_lease(&root) {
            Ok(lease) => lease,
            Err(GtpuError::AlreadyExists) => {
                return Ok(PdpContextRemovalOutcome::Indeterminate(
                    PdpContextIndeterminateReason::AuthorityUnavailable,
                ));
            }
            Err(error) => return Err(error),
        };
        let _device_lease = match acquire_pdp_recovery_lease(&root, device.ifindex) {
            Ok(lease) => lease,
            Err(GtpuError::AlreadyExists) => {
                return Ok(PdpContextRemovalOutcome::Indeterminate(
                    PdpContextIndeterminateReason::AuthorityUnavailable,
                ));
            }
            Err(error) => return Err(error),
        };
        // Prove the complete device incarnation only after both authorities
        // are held. Name and ifindex alone are reusable after link deletion.
        match self.inner.transport.ifindex_by_name(&device.name) {
            Ok(ifindex) if ifindex == device.ifindex => {}
            Ok(_) | Err(GtpuError::NotFound) => {
                return Ok(PdpContextRemovalOutcome::RepairRequired(
                    PdpContextRepairReason::DeviceIdentityChanged,
                ));
            }
            Err(error) => return Err(error),
        }
        let expected_alias = encode_pdp_device_alias(request.incarnation());
        match self
            .inner
            .transport
            .device_alias(&device, self.inner.config)
        {
            Ok(Some(alias)) if alias == expected_alias.as_bytes() => {}
            Ok(_) | Err(GtpuError::NotFound) => {
                return Ok(PdpContextRemovalOutcome::RepairRequired(
                    PdpContextRepairReason::DeviceIdentityChanged,
                ));
            }
            Err(error) => return Err(error),
        }
        let family_id = self
            .resolve_gtp_family_id()
            .map_err(map_family_lookup_error)?;
        self.remove_pdp_context_exact_locked(family_id, &expected)
    }

    /// Acquire the identity of one retained Linux kernel-GTP device without
    /// reading, installing, or deleting any PDP context and without mutating
    /// any device.
    ///
    /// This is the identity-bearing, mutation-free restart-recovery primitive
    /// an ePDG-style consumer uses after process loss when its durable roster
    /// records a shared recoverable device that may have survived without an
    /// effect-possible PDP descriptor. [`Self::create_recoverable_device`]
    /// refuses a retained device, [`GtpuDataplaneBackend::resolve_device`]
    /// proves only name and ifindex, and
    /// [`Self::recover_pdp_context_exact`] verifies the incarnation only as
    /// part of a PDP-context recovery request that may remove an exact
    /// resident context. This primitive closes that gap: it classifies the
    /// retained device identity so the consumer can choose exact retained
    /// reuse or authoritative absence followed by one
    /// [`Self::create_recoverable_device`] call.
    ///
    /// The request carries the exact durable [`GtpDevice`], the non-reusable
    /// [`PdpDeviceIncarnation`], and the prior-writer stop attestation. The
    /// recovery root must already be bound. The acquisition acquires the
    /// shared topology authority and then the per-device writer authority for
    /// the expected ifindex, proves the live name still resolves to that
    /// ifindex, and proves the kernel `IFLA_IFALIAS` incarnation with one
    /// read-only `RTM_GETLINK` probe. Outcomes:
    ///
    /// - [`RetainedDeviceIdentityOutcome::Retained`] — name, ifindex, and
    ///   incarnation all match; the retained device may be reused.
    /// - [`RetainedDeviceIdentityOutcome::Absent`] — the name is
    ///   authoritatively absent under the topology authority; one fresh
    ///   [`Self::create_recoverable_device`] call with a newly minted
    ///   incarnation is the supported next step.
    /// - [`RetainedDeviceIdentityOutcome::Conflict`] — the name is occupied by
    ///   a different ifindex, or the name and ifindex are occupied with a
    ///   different (including foreign or malformed) kernel-bound identity;
    ///   the live state is left untouched.
    /// - [`RetainedDeviceIdentityOutcome::Indeterminate`] — a concurrent
    ///   cooperating writer holds the writer authority; retry the identical
    ///   request.
    /// - [`RetainedDeviceIdentityOutcome::RepairRequired`] — a link matching
    ///   the expected name and ifindex is unstamped; retrying cannot succeed
    ///   without repair.
    ///
    /// Renamed and removed devices present as authoritative name absence;
    /// structurally unreadable link evidence fails closed as an error. Every
    /// classification is structurally distinct from transient authority
    /// unavailability. The operation never reads, installs, or deletes a PDP
    /// context and never mutates the device, so an idempotent retry returns
    /// the same classified identity state while live state is unchanged.
    ///
    /// Like [`Self::recover_pdp_context_exact`], the blocking worker runs to
    /// completion even if the returned future is dropped: it retains both
    /// writer authorities until the classification finishes, so a retry cannot
    /// overlap an admitted acquisition. This call does not extend the writer
    /// authorities past its return; subsequent device and PDP mutations are
    /// fenced independently by the existing lease hierarchy.
    pub async fn acquire_retained_device_identity(
        &self,
        request: RetainedDeviceIdentityRequest,
    ) -> Result<RetainedDeviceIdentityOutcome, GtpuError> {
        self.run_blocking("acquire_retained_device_identity", move |backend| {
            backend.acquire_retained_device_identity_sync(request)
        })
        .await
    }

    fn acquire_retained_device_identity_sync(
        &self,
        request: RetainedDeviceIdentityRequest,
    ) -> Result<RetainedDeviceIdentityOutcome, GtpuError> {
        let device = request.device().clone();
        validate_device(&device)?;
        let _operation = self.pdp_operation_guard()?;
        let root = self.pdp_recovery_root_or_unsupported()?;
        let _topology_lease = match acquire_pdp_topology_lease(&root) {
            Ok(lease) => lease,
            Err(GtpuError::AlreadyExists) => {
                return Ok(RetainedDeviceIdentityOutcome::Indeterminate(
                    RetainedDeviceIndeterminateReason::AuthorityUnavailable,
                ));
            }
            Err(error) => return Err(error),
        };
        let _device_lease = match acquire_pdp_recovery_lease(&root, device.ifindex) {
            Ok(lease) => lease,
            Err(GtpuError::AlreadyExists) => {
                return Ok(RetainedDeviceIdentityOutcome::Indeterminate(
                    RetainedDeviceIndeterminateReason::AuthorityUnavailable,
                ));
            }
            Err(error) => return Err(error),
        };
        // Prove the complete device identity only after both authorities are
        // held, and never touch PDP state. Name and ifindex alone are
        // reusable after link deletion.
        match self.inner.transport.ifindex_by_name(&device.name) {
            Err(GtpuError::NotFound) => return Ok(RetainedDeviceIdentityOutcome::Absent),
            Ok(ifindex) if ifindex != device.ifindex => {
                return Ok(RetainedDeviceIdentityOutcome::Conflict(
                    RetainedDeviceConflictReason::ReplacementIdentity,
                ));
            }
            Ok(_) => {}
            Err(error) => return Err(error),
        }
        match self
            .inner
            .transport
            .link_identity(device.ifindex, self.inner.config)
        {
            Ok(Some(probe)) => {
                if probe.name != device.name.as_bytes() {
                    // The name resolved to this ifindex but the authoritative
                    // link readback disagrees. No cooperating writer can
                    // rename a link while both authorities are held, so fail
                    // closed rather than classify contested state.
                    return Err(GtpuError::StateIndeterminate {
                        operation: "retained_device_identity",
                    });
                }
                let expected_alias = encode_pdp_device_alias(request.incarnation());
                match probe.alias {
                    Some(alias) if alias == expected_alias.as_bytes() => {
                        Ok(RetainedDeviceIdentityOutcome::Retained)
                    }
                    Some(_) => Ok(RetainedDeviceIdentityOutcome::Conflict(
                        RetainedDeviceConflictReason::ReplacementIdentity,
                    )),
                    None => Ok(RetainedDeviceIdentityOutcome::RepairRequired(
                        RetainedDeviceRepairReason::Unstamped,
                    )),
                }
            }
            // The name just resolved to this ifindex, so a live link must own
            // it. Absent link evidence at this point is unrepresentable
            // state; fail closed without classifying it as owned, absent, or
            // retryable authority unavailability.
            Ok(None) => Err(GtpuError::StateIndeterminate {
                operation: "retained_device_identity",
            }),
            Err(error) => Err(error),
        }
    }

    fn pdp_recovery_root_or_unsupported(&self) -> Result<PathBuf, GtpuError> {
        self.inner
            .pdp_recovery_root
            .get()
            .cloned()
            .ok_or(GtpuError::UnsupportedFeature {
                feature: "pdp_restart_recovery_authority",
            })
    }

    /// Core exact-removal transaction under an already-held lease.
    ///
    /// Stably reads both selector axes, classifies, and only deletes when the
    /// resident context exactly matches `expected`. After an admitted delete
    /// it re-reads both axes and reports the authoritative post-mutation
    /// state, never the delete call's own success or error.
    fn remove_pdp_context_exact_locked(
        &self,
        family_id: u16,
        expected: &GtpPdpContext,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        let (local, uplink) = match self.inspect_desired_axes_stable_locked(family_id, expected) {
            Ok(observed) => observed,
            Err(GtpuError::StateIndeterminate { .. }) => {
                return Ok(PdpContextRemovalOutcome::Indeterminate(
                    PdpContextIndeterminateReason::StateChanged,
                ));
            }
            Err(error) => return Err(error),
        };
        match classify_dual_selector_state(&local, &uplink, expected) {
            DualSelectorState::BothAbsent => Ok(PdpContextRemovalOutcome::AlreadyAbsent),
            DualSelectorState::Conflict(conflict) => {
                Ok(PdpContextRemovalOutcome::Conflict(conflict))
            }
            DualSelectorState::Indeterminate => Ok(PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::IncompleteState,
            )),
            DualSelectorState::Exact => {
                let request = RemovePdpContextRequest::from_context(expected);
                let body = encode_remove_pdp_context(&request)?;
                match self.generic_transact(
                    "remove_pdp_context_exact",
                    family_id,
                    NLM_F_REQUEST | NLM_F_ACK,
                    body,
                ) {
                    Ok(_) => {}
                    Err(error) if error_proves_no_requested_mutation(&error) => {
                        return Err(error);
                    }
                    Err(_) => {
                        // A non-definitive netlink failure can mean ACK loss
                        // after a committed delete. Never treat the error as
                        // proof of absence; confirm from readback below.
                    }
                }
                match self.inspect_desired_axes_stable_locked(family_id, expected) {
                    Ok((local, uplink)) => {
                        match classify_dual_selector_state(&local, &uplink, expected) {
                            DualSelectorState::BothAbsent => Ok(PdpContextRemovalOutcome::Removed),
                            _ => Ok(PdpContextRemovalOutcome::Indeterminate(
                                PdpContextIndeterminateReason::MutationUnconfirmed,
                            )),
                        }
                    }
                    Err(_) => Ok(PdpContextRemovalOutcome::Indeterminate(
                        PdpContextIndeterminateReason::MutationUnconfirmed,
                    )),
                }
            }
        }
    }
}

/// Cross-process lease guarding one GTP device's PDP restart recovery.
///
/// On Linux the lease is an exclusive `flock` on a per-device file beneath the
/// bound recovery root. It is host-global, released by the kernel on process
/// exit, and held for exactly one exact-removal transaction, so a dying writer
/// and a restarting reconciler cannot overlap on the same device. Dropping the
/// lease (or process loss) releases it. Off Linux there is no kernel GTP
/// device to serialize against, so the lease is vacuously held (`_lock` is
/// `None`); every actual mutation is still fenced by the Linux-only netlink
/// transport, which fails closed on other platforms.
struct PdpRecoveryLease {
    _lock: Option<std::fs::File>,
}

impl Drop for PdpRecoveryLease {
    fn drop(&mut self) {
        // Release the lock explicitly rather than relying solely on
        // close-on-drop: under concurrent load, an immediate re-acquisition of
        // the same lease could otherwise observe the still-held lock
        // intermittently before the descriptor teardown completed. Unlocking
        // first makes the release deterministic; the subsequent close then has
        // no lock left to release.
        #[cfg(target_os = "linux")]
        if let Some(file) = self._lock.as_ref() {
            let _ = rustix::fs::flock(file, rustix::fs::FlockOperation::Unlock);
        }
    }
}

#[cfg(target_os = "linux")]
fn acquire_pdp_recovery_lease(root: &Path, ifindex: u32) -> Result<PdpRecoveryLease, GtpuError> {
    acquire_pdp_recovery_named_lease(root, &format!("pdp-recovery-{ifindex}.lock"))
}

#[cfg(target_os = "linux")]
fn acquire_pdp_topology_lease(root: &Path) -> Result<PdpRecoveryLease, GtpuError> {
    acquire_pdp_recovery_named_lease(root, PDP_TOPOLOGY_LEASE_NAME)
}

#[cfg(target_os = "linux")]
fn acquire_pdp_recovery_named_lease(
    root: &Path,
    lease_name: &str,
) -> Result<PdpRecoveryLease, GtpuError> {
    use std::os::unix::fs::MetadataExt;
    std::fs::create_dir_all(root)
        .map_err(|error| GtpuError::io("pdp_recovery_root_create", error))?;
    let lock_path = root.join(lease_name);
    let file = rustix::fs::open(
        &lock_path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map(std::fs::File::from)
    .map_err(|error| GtpuError::io("pdp_recovery_lease_open", error.into()))?;
    let opened = file
        .metadata()
        .map_err(|error| GtpuError::io("pdp_recovery_lease_stat", error))?;
    let named = std::fs::symlink_metadata(&lock_path)
        .map_err(|error| GtpuError::io("pdp_recovery_lease_stat", error))?;
    if !named.file_type().is_file() || opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(GtpuError::StateIndeterminate {
            operation: "pdp_restart_recovery_lease",
        });
    }
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::AGAIN) => return Err(GtpuError::AlreadyExists),
        Err(error) => {
            return Err(GtpuError::io("pdp_recovery_lease_lock", error.into()));
        }
    }
    let locked = std::fs::symlink_metadata(&lock_path)
        .map_err(|error| GtpuError::io("pdp_recovery_lease_recheck", error))?;
    if !locked.file_type().is_file() || opened.dev() != locked.dev() || opened.ino() != locked.ino()
    {
        return Err(GtpuError::StateIndeterminate {
            operation: "pdp_restart_recovery_lease",
        });
    }
    Ok(PdpRecoveryLease { _lock: Some(file) })
}

#[cfg(not(target_os = "linux"))]
fn acquire_pdp_recovery_lease(_root: &Path, _ifindex: u32) -> Result<PdpRecoveryLease, GtpuError> {
    // Off Linux there is no kernel GTP device for the lease to serialize
    // against, so the lease is vacuously held. Actual mutation still requires
    // the Linux-only netlink transport, which fails closed on this platform,
    // so a vacuous lease admits no real removal here.
    Ok(PdpRecoveryLease { _lock: None })
}

#[cfg(not(target_os = "linux"))]
fn acquire_pdp_topology_lease(_root: &Path) -> Result<PdpRecoveryLease, GtpuError> {
    Ok(PdpRecoveryLease { _lock: None })
}

#[async_trait]
impl GtpuDataplaneBackend for LinuxGtpuDataplaneBackend {
    async fn create_device(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError> {
        self.run_blocking("create_device", move |backend| {
            backend.create_device_sync(request)
        })
        .await
    }

    async fn resolve_device(&self, name: &str) -> Result<GtpDevice, GtpuError> {
        let name = name.to_string();
        self.run_blocking("resolve_device", move |backend| {
            backend.resolve_device_sync(name)
        })
        .await
    }

    async fn remove_device(&self, device: &GtpDevice) -> Result<(), GtpuError> {
        let device = device.clone();
        self.run_blocking("remove_device", move |backend| {
            backend.remove_device_sync(device)
        })
        .await
    }

    async fn install_pdp_context(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
        self.run_blocking("install_pdp_context", move |backend| {
            backend.install_pdp_context_sync(request)
        })
        .await
    }

    async fn remove_pdp_context(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        self.run_blocking("remove_pdp_context", move |backend| {
            backend.remove_pdp_context_sync(request)
        })
        .await
    }

    async fn read_pdp_context(
        &self,
        selector: PdpContextSelector,
    ) -> Result<PdpContextReadback, GtpuError> {
        self.run_blocking("read_pdp_context", move |backend| {
            backend.read_pdp_context_sync(selector)
        })
        .await
    }

    async fn install_pdp_context_classified(
        &self,
        request: GtpPdpContext,
    ) -> Result<PdpContextInstallOutcome, GtpuError> {
        self.run_blocking("install_pdp_context_classified", move |backend| {
            backend.install_pdp_context_classified_sync(request)
        })
        .await
    }

    async fn remove_pdp_context_exact(
        &self,
        expected: GtpPdpContext,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        self.run_blocking("remove_pdp_context_exact", move |backend| {
            backend.remove_pdp_context_exact_recovery_sync(expected)
        })
        .await
    }

    async fn recover_pdp_context_exact(
        &self,
        request: PdpRestartRecoveryRequest,
    ) -> Result<PdpContextRemovalOutcome, GtpuError> {
        LinuxGtpuDataplaneBackend::recover_pdp_context_exact(self, request).await
    }

    fn pdp_context_reconciliation_capabilities(&self) -> PdpContextReconciliationCapabilities {
        let probe = self.inner.transport.probe(self.inner.config);
        let readback = if !probe.platform_supported || !probe.gtp_module_present {
            GtpuCapability::Missing
        } else if !probe.net_admin_capable {
            GtpuCapability::PermissionDenied
        } else if probe.kernel_reachable {
            GtpuCapability::Available
        } else {
            GtpuCapability::Unknown
        };
        PdpContextReconciliationCapabilities {
            readback,
            classified_install: if probe.mutation_ready {
                GtpuCapability::Available
            } else if matches!(readback, GtpuCapability::PermissionDenied) {
                GtpuCapability::PermissionDenied
            } else {
                GtpuCapability::Missing
            },
            // The trait request carries only a context. Linux exact restart
            // removal additionally requires a durable device incarnation, so
            // callers must use `recover_pdp_context_exact` instead.
            exact_removal: GtpuCapability::Missing,
        }
    }

    fn pdp_restart_recovery_capability(&self) -> GtpuCapability {
        if self.bound_pdp_recovery_root().is_none() {
            return GtpuCapability::Missing;
        }
        match self.pdp_context_reconciliation_capabilities().readback {
            GtpuCapability::Available => GtpuCapability::Available,
            GtpuCapability::PermissionDenied => GtpuCapability::PermissionDenied,
            GtpuCapability::Unknown => GtpuCapability::Unknown,
            GtpuCapability::Missing => GtpuCapability::Missing,
        }
    }

    async fn probe(&self) -> Result<GtpuProbe, GtpuError> {
        Ok(self.inner.transport.probe(self.inner.config))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetlinkProtocol {
    Route,
    Generic,
}

#[derive(Debug)]
struct GtpuSocketHandle {
    raw_fd: i32,
    _socket: Option<GtpuUdpSocket>,
}

impl GtpuSocketHandle {
    fn real(socket: GtpuUdpSocket) -> Self {
        Self {
            raw_fd: socket.raw_fd(),
            _socket: Some(socket),
        }
    }

    #[cfg(test)]
    fn fake(raw_fd: i32) -> Self {
        Self {
            raw_fd,
            _socket: None,
        }
    }

    fn raw_fd(&self) -> i32 {
        self.raw_fd
    }
}

trait LinuxGtpuTransport: Send + Sync + fmt::Debug {
    fn transact(
        &self,
        protocol: NetlinkProtocol,
        operation: &'static str,
        request: &[u8],
        expected_sequence: u32,
        config: LinuxGtpuDataplaneBackendConfig,
    ) -> Result<Option<Vec<u8>>, GtpuError>;

    fn open_gtpu_socket(
        &self,
        bind_address: IpAddr,
        bind_port: u16,
        operation: &'static str,
    ) -> Result<GtpuSocketHandle, GtpuError>;

    fn ifindex_by_name(&self, name: &str) -> Result<u32, GtpuError>;

    /// Return the unwrapped `IFLA_IFALIAS` bytes for the exact live link.
    fn device_alias(
        &self,
        device: &GtpDevice,
        config: LinuxGtpuDataplaneBackendConfig,
    ) -> Result<Option<Vec<u8>>, GtpuError>;

    /// Read the live identity of one exact link by ifindex.
    ///
    /// Returns the link's current name and optional `IFLA_IFALIAS` bytes
    /// without asserting the name, or `None` when no link owns `ifindex`.
    /// This is a read-only `RTM_GETLINK` probe; it never mutates link or PDP
    /// state.
    fn link_identity(
        &self,
        ifindex: u32,
        config: LinuxGtpuDataplaneBackendConfig,
    ) -> Result<Option<LinkIdentityProbe>, GtpuError>;

    fn probe(&self, config: LinuxGtpuDataplaneBackendConfig) -> GtpuProbe;
}

#[derive(Debug)]
struct NetlinkGtpuTransport;

impl LinuxGtpuTransport for NetlinkGtpuTransport {
    fn transact(
        &self,
        protocol: NetlinkProtocol,
        operation: &'static str,
        request: &[u8],
        expected_sequence: u32,
        config: LinuxGtpuDataplaneBackendConfig,
    ) -> Result<Option<Vec<u8>>, GtpuError> {
        let socket = match protocol {
            NetlinkProtocol::Route => open_route_netlink_socket(),
            NetlinkProtocol::Generic => open_generic_netlink_socket(),
        }
        .map_err(|error| map_open_error(operation, error))?;

        let sent =
            send_message(&socket, request).map_err(|error| GtpuError::io("netlink_send", error))?;
        if sent != request.len() {
            return Err(GtpuError::io(
                "netlink_send",
                io::Error::new(io::ErrorKind::WriteZero, "short netlink send"),
            ));
        }

        let mut buffer = vec![0_u8; config.receive_buffer_len];
        for _ in 0..config.receive_attempts {
            match receive_kernel_message(&socket, &mut buffer) {
                Ok(0) => {}
                Ok(len) => {
                    let request_type = read_u16_ne(request, 4)?;
                    // RTM_GETLINK replies carry RTM_NEWLINK payloads. Other
                    // route and generic-netlink transactions in this backend
                    // reply with their request family/type.
                    let expected_payload_type = if request_type == RTM_GETLINK {
                        RTM_NEWLINK
                    } else {
                        request_type
                    };
                    return parse_netlink_response(
                        &buffer[..len],
                        expected_sequence,
                        expected_payload_type,
                    );
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(GtpuError::io("netlink_receive", error)),
            }
            if !config.retry_delay.is_zero() {
                std::thread::sleep(config.retry_delay);
            }
        }

        Err(GtpuError::io(
            operation,
            io::Error::new(io::ErrorKind::TimedOut, "netlink ack timeout"),
        ))
    }

    fn open_gtpu_socket(
        &self,
        bind_address: IpAddr,
        bind_port: u16,
        operation: &'static str,
    ) -> Result<GtpuSocketHandle, GtpuError> {
        let bind = GtpuUdpBind {
            address: sys_ip_address(bind_address),
            port: bind_port,
        };
        let socket = open_gtpu_udp_socket(bind).map_err(|error| GtpuError::io(operation, error))?;
        Ok(GtpuSocketHandle::real(socket))
    }

    fn ifindex_by_name(&self, name: &str) -> Result<u32, GtpuError> {
        linux_ifindex_by_name(name).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => GtpuError::NotFound,
            _ => GtpuError::io("ifindex_lookup", error),
        })
    }

    fn device_alias(
        &self,
        device: &GtpDevice,
        config: LinuxGtpuDataplaneBackendConfig,
    ) -> Result<Option<Vec<u8>>, GtpuError> {
        const IDENTITY_QUERY_SEQUENCE: u32 = 1;
        let body = encode_get_device_request(device.ifindex)?;
        let request =
            encode_netlink_message(RTM_GETLINK, NLM_F_REQUEST, IDENTITY_QUERY_SEQUENCE, &body)?;
        let response = self
            .transact(
                NetlinkProtocol::Route,
                "pdp_device_identity_read",
                &request,
                IDENTITY_QUERY_SEQUENCE,
                config,
            )?
            .ok_or_else(|| {
                GtpuError::io(
                    "pdp_device_identity_read",
                    invalid_data("missing link identity response"),
                )
            })?;
        parse_device_alias_response(&response, device)
    }

    fn link_identity(
        &self,
        ifindex: u32,
        config: LinuxGtpuDataplaneBackendConfig,
    ) -> Result<Option<LinkIdentityProbe>, GtpuError> {
        const IDENTITY_QUERY_SEQUENCE: u32 = 1;
        let body = encode_get_device_request(ifindex)?;
        let request =
            encode_netlink_message(RTM_GETLINK, NLM_F_REQUEST, IDENTITY_QUERY_SEQUENCE, &body)?;
        let response = match self.transact(
            NetlinkProtocol::Route,
            "retained_device_identity_read",
            &request,
            IDENTITY_QUERY_SEQUENCE,
            config,
        ) {
            Ok(Some(response)) => response,
            Ok(None) => {
                return Err(GtpuError::io(
                    "retained_device_identity_read",
                    invalid_data("missing link identity response"),
                ));
            }
            // The kernel answers an RTM_GETLINK for a vanished ifindex with
            // -ENODEV. `parse_netlink_error` maps ENOENT/ESRCH (and any errno
            // whose I/O kind is NotFound) to `NotFound`; map the ENODEV
            // remainder explicitly so absence is authoritative on every
            // kernel/libc combination.
            Err(GtpuError::NotFound) => return Ok(None),
            Err(GtpuError::Io {
                raw_os_error: Some(ENODEV),
                ..
            }) => return Ok(None),
            Err(error) => return Err(error),
        };
        parse_link_identity_response(&response, ifindex, "retained_device_identity_read").map(Some)
    }

    fn probe(&self, config: LinuxGtpuDataplaneBackendConfig) -> GtpuProbe {
        let route_open = open_route_netlink_socket();
        let generic_open = open_generic_netlink_socket();
        let platform_supported = !matches!(
            route_open.as_ref().err().map(io::Error::kind),
            Some(io::ErrorKind::Unsupported)
        ) && !matches!(
            generic_open.as_ref().err().map(io::Error::kind),
            Some(io::ErrorKind::Unsupported)
        );
        let kernel_reachable = route_open.is_ok() && generic_open.is_ok();
        drop(route_open);
        drop(generic_open);

        let gtp_module_present = if kernel_reachable {
            probe_gtp_family(self, config)
        } else {
            false
        };
        let net_admin_capable = effective_cap_net_admin().unwrap_or(false);
        let socket_bindable = self
            .open_gtpu_socket(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                GTPU_PORT,
                "gtpu_udp_probe_bind",
            )
            .is_ok();
        let mutation_ready = platform_supported
            && kernel_reachable
            && gtp_module_present
            && net_admin_capable
            && socket_bindable;
        let details = if !platform_supported {
            Some("linux GTP-U netlink unsupported on this platform")
        } else if !kernel_reachable {
            Some("linux route or generic netlink socket unavailable")
        } else if !gtp_module_present {
            Some("linux gtp generic-netlink family not present")
        } else if !net_admin_capable {
            Some("CAP_NET_ADMIN is not effective")
        } else if !socket_bindable {
            Some("GTP-U UDP socket bind failed")
        } else {
            Some("linux GTP-U dataplane mutation ready")
        };

        GtpuProbe {
            kind: GtpuBackendKind::LinuxKernel,
            platform_supported,
            kernel_reachable,
            gtp_module_present,
            net_admin_capable,
            bpf_capable: false,
            btf_present: false,
            mutation_ready,
            egress_dscp_marking: GtpuCapability::Missing,
            per_bearer_marking: GtpuCapability::Missing,
            downlink_endpoint_binding: GtpuCapability::Missing,
            uplink_source_port_selection: GtpuCapability::Missing,
            uplink_pmtu_enforcement: GtpuCapability::Missing,
            // The generic-netlink family probe proves only that the Linux GTP
            // driver is present. It does not prove fragmented outer packets
            // re-enter that driver's UDP consumer exactly once, so this
            // backend must not advertise the stronger handoff contract.
            downlink_outer_fragment_handling: GtpuDownlinkFragmentContract::Unsupported,
            details,
        }
    }
}

fn probe_gtp_family<T>(transport: &T, config: LinuxGtpuDataplaneBackendConfig) -> bool
where
    T: LinuxGtpuTransport + ?Sized,
{
    let body = match encode_generic_family_lookup() {
        Ok(body) => body,
        Err(_) => return false,
    };
    let message = match encode_netlink_message(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, 1, &body) {
        Ok(message) => message,
        Err(_) => return false,
    };
    match transport.transact(
        NetlinkProtocol::Generic,
        "gtp_family_lookup",
        &message,
        1,
        config,
    ) {
        Ok(Some(response)) => parse_generic_family_id(&response).is_ok(),
        _ => false,
    }
}

fn map_open_error(operation: &'static str, error: io::Error) -> GtpuError {
    if error.kind() == io::ErrorKind::Unsupported {
        GtpuError::UnsupportedPlatform
    } else {
        GtpuError::io(operation, error)
    }
}

fn map_family_lookup_error(error: GtpuError) -> GtpuError {
    match error {
        GtpuError::NotFound => GtpuError::UnsupportedPlatform,
        other => other,
    }
}

fn map_pdp_writer_lease_error(error: GtpuError) -> GtpuError {
    if matches!(error, GtpuError::AlreadyExists) {
        GtpuError::RetryRequired {
            operation: "pdp_writer_authority",
        }
    } else {
        error
    }
}

fn validate_pdp_recovery_root(root: &Path) -> Result<(), GtpuError> {
    if !root.is_absolute() {
        return Err(GtpuError::invalid_config(
            "pdp_recovery.root",
            "recovery root must be an absolute path",
        ));
    }
    if root
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(GtpuError::invalid_config(
            "pdp_recovery.root",
            "recovery root must not contain parent-directory components",
        ));
    }
    if root.parent().is_none() {
        return Err(GtpuError::invalid_config(
            "pdp_recovery.root",
            "recovery root must not be the filesystem root",
        ));
    }
    Ok(())
}

fn validate_create_device_request(request: &CreateGtpDeviceRequest) -> Result<(), GtpuError> {
    validate_interface_name(&request.name, "device.name")?;
    if request.bind_port == 0 {
        return Err(GtpuError::invalid_config(
            "device.bind_port",
            "bind port must be nonzero",
        ));
    }
    if matches!(request.pdp_hashsize, Some(0)) {
        return Err(GtpuError::invalid_config(
            "device.pdp_hashsize",
            "hash size must be nonzero",
        ));
    }
    if request.uplink_mtu_policy.is_some() {
        // The netlink gtp driver leaves outer fragmentation and MTU handling
        // to the kernel routing layer; the typed SDK policy is not
        // implemented by this backend and must fail closed rather than be
        // silently ignored.
        return Err(GtpuError::UnsupportedFeature {
            feature: "uplink_pmtu_enforcement",
        });
    }
    Ok(())
}

fn validate_device(device: &GtpDevice) -> Result<(), GtpuError> {
    validate_interface_name(&device.name, "device.name")?;
    validate_ifindex(device.ifindex, "device.ifindex")?;
    Ok(())
}

fn validate_pdp_context(context: &GtpPdpContext) -> Result<(), GtpuError> {
    if context.bearer_mark.is_some() {
        return Err(GtpuError::UnsupportedFeature {
            feature: "per_bearer_marking",
        });
    }
    if context.egress_dscp.is_some() {
        return Err(GtpuError::UnsupportedFeature {
            feature: "fixed_outer_dscp",
        });
    }
    if context.downlink_source_port_policy != crate::GtpuSourcePortPolicy::Any {
        return Err(GtpuError::UnsupportedFeature {
            feature: "downlink_source_port_policy",
        });
    }
    if context.uplink_source_port_policy != crate::GtpuUplinkSourcePortPolicy::LegacyServicePort {
        return Err(GtpuError::UnsupportedFeature {
            feature: "uplink_source_port_selection",
        });
    }
    validate_ifindex(context.link_ifindex, "pdp.link_ifindex")?;
    validate_gtp_version(context.gtp_version)?;
    if is_unspecified(context.ms_address) {
        return Err(GtpuError::invalid_config(
            "pdp.ms_address",
            "MS address must not be unspecified",
        ));
    }
    if is_unspecified(context.peer_address) {
        return Err(GtpuError::invalid_config(
            "pdp.peer_address",
            "peer address must not be unspecified",
        ));
    }
    Ok(())
}

fn validate_remove_pdp_context_request(request: &RemovePdpContextRequest) -> Result<(), GtpuError> {
    validate_ifindex(request.link_ifindex, "pdp.link_ifindex")?;
    validate_gtp_version(request.gtp_version)?;
    Ok(())
}

fn validate_pdp_context_selector(selector: &PdpContextSelector) -> Result<(), GtpuError> {
    match selector {
        PdpContextSelector::LocalTeid(selector) => {
            validate_ifindex(selector.link_ifindex(), "pdp.selector.link_ifindex")?;
            validate_gtp_version(selector.gtp_version())?;
        }
        PdpContextSelector::Uplink(selector) => {
            validate_ifindex(selector.link_ifindex(), "pdp.selector.link_ifindex")?;
            validate_gtp_version(selector.gtp_version())?;
            if selector.identity().bearer_mark().is_some() {
                return Err(GtpuError::UnsupportedFeature {
                    feature: "per_bearer_marking",
                });
            }
            if is_unspecified(selector.identity().ms_address()) {
                return Err(GtpuError::invalid_config(
                    "pdp.selector.ms_address",
                    "MS address must not be unspecified",
                ));
            }
        }
    }
    Ok(())
}

fn validate_interface_name(name: &str, field: &'static str) -> Result<(), GtpuError> {
    if name.is_empty() {
        return Err(GtpuError::invalid_config(field, "name must be nonempty"));
    }
    if name.len() >= IFNAMSIZ {
        return Err(GtpuError::invalid_config(
            field,
            "name must fit Linux IFNAMSIZ",
        ));
    }
    if name.as_bytes().contains(&0) {
        return Err(GtpuError::invalid_config(
            field,
            "name must not contain NUL",
        ));
    }
    if name.contains('/') {
        return Err(GtpuError::invalid_config(
            field,
            "name must not contain path separators",
        ));
    }
    Ok(())
}

fn validate_ifindex(ifindex: u32, field: &'static str) -> Result<(), GtpuError> {
    if ifindex == 0 {
        return Err(GtpuError::invalid_config(field, "ifindex must be nonzero"));
    }
    let _ = ifindex_i32(ifindex, field)?;
    Ok(())
}

fn validate_gtp_version(version: GtpVersion) -> Result<(), GtpuError> {
    match version {
        GtpVersion::V1 => Ok(()),
    }
}

fn ifindex_i32(ifindex: u32, field: &'static str) -> Result<i32, GtpuError> {
    i32::try_from(ifindex)
        .map_err(|_| GtpuError::invalid_config(field, "ifindex exceeds i32 range"))
}

fn is_unspecified(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_unspecified(),
        IpAddr::V6(address) => address.is_unspecified(),
    }
}

fn sys_ip_address(address: IpAddr) -> GtpuIpAddress {
    match address {
        IpAddr::V4(address) => GtpuIpAddress::Ipv4(address.octets()),
        IpAddr::V6(address) => GtpuIpAddress::Ipv6(address.octets()),
    }
}

fn encode_netlink_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    body: &[u8],
) -> Result<Vec<u8>, GtpuError> {
    let length = NETLINK_HEADER_LEN
        .checked_add(body.len())
        .ok_or_else(|| GtpuError::invalid_config("netlink.length", "message length overflow"))?;
    let length_u32 = u32::try_from(length)
        .map_err(|_| GtpuError::invalid_config("netlink.length", "message length overflow"))?;

    let mut out = Vec::with_capacity(length);
    push_u32_ne(&mut out, length_u32);
    push_u16_ne(&mut out, message_type);
    push_u16_ne(&mut out, flags);
    push_u32_ne(&mut out, sequence);
    push_u32_ne(&mut out, 0);
    out.extend_from_slice(body);
    Ok(out)
}

fn encode_create_device_request(
    request: &CreateGtpDeviceRequest,
    fd: i32,
) -> Result<Vec<u8>, GtpuError> {
    let fd = u32::try_from(fd)
        .map_err(|_| GtpuError::invalid_config("device.fd1", "fd must be nonnegative"))?;
    let mut out = Vec::with_capacity(IF_INFO_MESSAGE_LEN + 128);
    push_u8(&mut out, AF_INET);
    push_u8(&mut out, 0);
    push_u16_ne(&mut out, 0);
    push_i32_ne(&mut out, 0);
    push_u32_ne(&mut out, IFF_UP);
    push_u32_ne(&mut out, IFF_UP);
    debug_assert_eq!(out.len(), IF_INFO_MESSAGE_LEN);

    append_attr_string(&mut out, IFLA_IFNAME, &request.name)?;
    let linkinfo = start_attr(&mut out, IFLA_LINKINFO);
    append_attr_string(&mut out, IFLA_INFO_KIND, "gtp")?;
    let info_data = start_attr(&mut out, IFLA_INFO_DATA);
    append_attr_u32_ne(&mut out, IFLA_GTP_FD1, fd)?;
    if let Some(hashsize) = request.pdp_hashsize {
        append_attr_u32_ne(&mut out, IFLA_GTP_PDP_HASHSIZE, hashsize)?;
    }
    append_attr_u32_ne(&mut out, IFLA_GTP_ROLE, encode_role(request.role))?;
    append_local_address_attr(&mut out, request.bind_address)?;
    finish_attr(&mut out, info_data)?;
    finish_attr(&mut out, linkinfo)?;
    Ok(out)
}

fn encode_set_device_alias_request(
    device: &GtpDevice,
    incarnation: PdpDeviceIncarnation,
) -> Result<Vec<u8>, GtpuError> {
    let mut out = encode_get_device_request(device.ifindex)?;
    append_attr_string(
        &mut out,
        IFLA_IFALIAS,
        &encode_pdp_device_alias(incarnation),
    )?;
    Ok(out)
}

fn encode_get_device_request(ifindex: u32) -> Result<Vec<u8>, GtpuError> {
    let mut out = Vec::with_capacity(IF_INFO_MESSAGE_LEN);
    push_u8(&mut out, AF_UNSPEC);
    push_u8(&mut out, 0);
    push_u16_ne(&mut out, 0);
    push_i32_ne(
        &mut out,
        ifindex_i32(ifindex, "pdp_recovery.device_ifindex")?,
    );
    push_u32_ne(&mut out, 0);
    push_u32_ne(&mut out, 0);
    debug_assert_eq!(out.len(), IF_INFO_MESSAGE_LEN);
    Ok(out)
}

fn encode_remove_device_request(device: &GtpDevice) -> Result<Vec<u8>, GtpuError> {
    let mut out = Vec::with_capacity(IF_INFO_MESSAGE_LEN);
    push_u8(&mut out, AF_INET);
    push_u8(&mut out, 0);
    push_u16_ne(&mut out, 0);
    push_i32_ne(&mut out, ifindex_i32(device.ifindex, "device.ifindex")?);
    push_u32_ne(&mut out, 0);
    push_u32_ne(&mut out, IFF_UP);
    debug_assert_eq!(out.len(), IF_INFO_MESSAGE_LEN);
    Ok(out)
}

fn encode_generic_family_lookup() -> Result<Vec<u8>, GtpuError> {
    let mut out = Vec::with_capacity(GENERIC_NETLINK_HEADER_LEN + 32);
    push_u8(&mut out, CTRL_CMD_GETFAMILY);
    push_u8(&mut out, CTRL_VERSION);
    push_u16_ne(&mut out, 0);
    append_attr_u16_ne(&mut out, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL)?;
    append_attr_string(&mut out, CTRL_ATTR_FAMILY_NAME, GTP_GENL_NAME)?;
    Ok(out)
}

fn encode_install_pdp_context(context: &GtpPdpContext) -> Result<Vec<u8>, GtpuError> {
    let mut out = encode_gtp_genl_header(GTP_CMD_NEWPDP);
    append_attr_u32_ne(&mut out, GTPA_LINK, context.link_ifindex)?;
    append_attr_u32_ne(&mut out, GTPA_VERSION, encode_version(context.gtp_version))?;
    append_attr_u8(&mut out, GTPA_FAMILY, encode_ip_family(context.ms_address))?;
    append_ip_attr(&mut out, context.ms_address, GTPA_MS_ADDRESS, GTPA_MS_ADDR6)?;
    append_ip_attr(
        &mut out,
        context.peer_address,
        GTPA_PEER_ADDRESS,
        GTPA_PEER_ADDR6,
    )?;
    append_attr_u32_ne(&mut out, GTPA_I_TEI, context.local_teid.get())?;
    append_attr_u32_ne(&mut out, GTPA_O_TEI, context.peer_teid.get())?;
    Ok(out)
}

fn encode_remove_pdp_context(request: &RemovePdpContextRequest) -> Result<Vec<u8>, GtpuError> {
    let mut out = encode_gtp_genl_header(GTP_CMD_DELPDP);
    append_attr_u32_ne(&mut out, GTPA_LINK, request.link_ifindex)?;
    append_attr_u32_ne(&mut out, GTPA_VERSION, encode_version(request.gtp_version))?;
    append_attr_u8(
        &mut out,
        GTPA_FAMILY,
        encode_address_family(request.address_family),
    )?;
    append_attr_u32_ne(&mut out, GTPA_I_TEI, request.local_teid.get())?;
    Ok(out)
}

fn encode_get_pdp_context(selector: &PdpContextSelector) -> Result<Vec<u8>, GtpuError> {
    validate_pdp_context_selector(selector)?;
    let mut out = encode_gtp_genl_header(GTP_CMD_GETPDP);
    match selector {
        PdpContextSelector::LocalTeid(selector) => {
            append_attr_u32_ne(&mut out, GTPA_LINK, selector.link_ifindex())?;
            append_attr_u32_ne(
                &mut out,
                GTPA_VERSION,
                encode_version(selector.gtp_version()),
            )?;
            append_attr_u8(
                &mut out,
                GTPA_FAMILY,
                encode_address_family(selector.address_family()),
            )?;
            append_attr_u32_ne(&mut out, GTPA_I_TEI, selector.local_teid().get())?;
        }
        PdpContextSelector::Uplink(selector) => {
            append_attr_u32_ne(&mut out, GTPA_LINK, selector.link_ifindex())?;
            append_attr_u32_ne(
                &mut out,
                GTPA_VERSION,
                encode_version(selector.gtp_version()),
            )?;
            append_attr_u8(
                &mut out,
                GTPA_FAMILY,
                encode_ip_family(selector.identity().ms_address()),
            )?;
            append_ip_attr(
                &mut out,
                selector.identity().ms_address(),
                GTPA_MS_ADDRESS,
                GTPA_MS_ADDR6,
            )?;
        }
    }
    Ok(out)
}

fn encode_gtp_genl_header(command: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(GENERIC_NETLINK_HEADER_LEN + 64);
    push_u8(&mut out, command);
    push_u8(&mut out, GTP_GENL_VERSION);
    push_u16_ne(&mut out, 0);
    out
}

#[derive(Default)]
struct PdpResponseAttributes<'a> {
    link: Option<&'a [u8]>,
    version: Option<&'a [u8]>,
    family: Option<&'a [u8]>,
    ms_ipv4: Option<&'a [u8]>,
    ms_ipv6: Option<&'a [u8]>,
    peer_ipv4: Option<&'a [u8]>,
    peer_ipv6: Option<&'a [u8]>,
    local_teid: Option<&'a [u8]>,
    peer_teid: Option<&'a [u8]>,
}

fn parse_pdp_context_response(
    body: &[u8],
    selector: &PdpContextSelector,
    expected_family_id: u16,
) -> Result<GtpPdpContext, GtpuError> {
    let invalid = |reason| GtpuError::io("linux_pdp_context_decode", invalid_data(reason));
    if body.len() < GENERIC_NETLINK_HEADER_LEN {
        return Err(invalid("short generic netlink header"));
    }
    // Linux v6.8 through current master passes the outer generic-family ID as
    // the response command for GETPDP. Accept that correlated low byte as well
    // as GETPDP so a future kernel fix remains compatible; reject every other
    // command. The outer nlmsg type is independently bound by
    // `parse_netlink_response`.
    if !matches!(body[0], GTP_CMD_GETPDP) && body[0] != expected_family_id as u8
        || body[1] != GTP_GENL_VERSION
        || body[2..GENERIC_NETLINK_HEADER_LEN] != [0, 0]
    {
        return Err(invalid("invalid generic netlink header"));
    }
    let mut attributes = PdpResponseAttributes::default();
    let mut offset = GENERIC_NETLINK_HEADER_LEN;
    while offset < body.len() {
        if body.len() - offset < ROUTE_ATTRIBUTE_HEADER_LEN {
            return Err(invalid("trailing generic netlink bytes"));
        }
        let length = usize::from(read_u16_ne(body, offset)?);
        let raw_attribute_type = read_u16_ne(body, offset + 2)?;
        if raw_attribute_type & !0x3fff != 0 {
            return Err(invalid("flagged PDP attribute"));
        }
        let attribute_type = raw_attribute_type;
        if length < ROUTE_ATTRIBUTE_HEADER_LEN {
            return Err(invalid("invalid PDP attribute length"));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("PDP attribute length overflow"))?;
        let aligned =
            align_to_netlink(length).ok_or_else(|| invalid("PDP attribute alignment overflow"))?;
        let aligned_end = offset
            .checked_add(aligned)
            .ok_or_else(|| invalid("PDP attribute alignment overflow"))?;
        if end > body.len() || aligned_end > body.len() {
            return Err(invalid("truncated PDP attribute"));
        }
        if body[end..aligned_end].iter().any(|byte| *byte != 0) {
            return Err(invalid("nonzero PDP attribute padding"));
        }
        let payload = &body[offset + ROUTE_ATTRIBUTE_HEADER_LEN..end];
        let slot = match attribute_type {
            GTPA_LINK => Some(&mut attributes.link),
            GTPA_VERSION => Some(&mut attributes.version),
            GTPA_FAMILY => Some(&mut attributes.family),
            GTPA_MS_ADDRESS => Some(&mut attributes.ms_ipv4),
            GTPA_MS_ADDR6 => Some(&mut attributes.ms_ipv6),
            GTPA_PEER_ADDRESS => Some(&mut attributes.peer_ipv4),
            GTPA_PEER_ADDR6 => Some(&mut attributes.peer_ipv6),
            GTPA_I_TEI => Some(&mut attributes.local_teid),
            GTPA_O_TEI => Some(&mut attributes.peer_teid),
            _ => return Err(invalid("unknown PDP attribute")),
        };
        if let Some(slot) = slot {
            if slot.replace(payload).is_some() {
                return Err(invalid("duplicate PDP attribute"));
            }
        }
        offset = aligned_end;
    }

    let link_ifindex = decode_pdp_u32(attributes.link, "missing or invalid link attribute")?;
    validate_ifindex(link_ifindex, "pdp.readback.link_ifindex")?;
    let version = decode_pdp_u32(attributes.version, "missing or invalid version attribute")?;
    if version != GTP_V1 {
        return Err(invalid("unsupported PDP GTP version"));
    }
    let local_teid = Teid::new(decode_pdp_u32(
        attributes.local_teid,
        "missing or invalid local TEID attribute",
    )?)
    .ok_or_else(|| invalid("zero local TEID attribute"))?;
    let peer_teid = Teid::new(decode_pdp_u32(
        attributes.peer_teid,
        "missing or invalid peer TEID attribute",
    )?)
    .ok_or_else(|| invalid("zero peer TEID attribute"))?;

    // GTPA_FAMILY selects the MS/PAA lookup table. The outer peer address is
    // independently selected by the GTP device's UDP socket family, so valid
    // contexts may combine an IPv4 PAA with an IPv6 peer or vice versa.
    let ms_address = decode_pdp_address(
        attributes.ms_ipv4,
        attributes.ms_ipv6,
        "missing or ambiguous MS address attributes",
        "invalid IPv4 MS address attribute",
        "invalid IPv6 MS address attribute",
    )?;
    let peer_address = decode_pdp_address(
        attributes.peer_ipv4,
        attributes.peer_ipv6,
        "missing or ambiguous peer address attributes",
        "invalid IPv4 peer address attribute",
        "invalid IPv6 peer address attribute",
    )?;
    let ms_family = GtpAddressFamily::from_ip(ms_address);
    if is_unspecified(ms_address) || is_unspecified(peer_address) {
        return Err(invalid("unspecified PDP address attribute"));
    }
    if let Some(family) = attributes.family {
        if family.len() != 1 || family[0] != encode_address_family(ms_family) {
            return Err(invalid("PDP family/MS-address mismatch"));
        }
    }

    let context = GtpPdpContext {
        local_teid,
        peer_teid,
        ms_address,
        peer_address,
        link_ifindex,
        downlink_source_port_policy: crate::GtpuSourcePortPolicy::Any,
        gtp_version: GtpVersion::V1,
        bearer_mark: None,
        egress_dscp: None,
        uplink_source_port_policy: crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
    };
    let selector_matches = match selector {
        PdpContextSelector::LocalTeid(selector) => {
            selector.link_ifindex() == context.link_ifindex
                && selector.gtp_version() == context.gtp_version
                && selector.address_family() == ms_family
                && selector.local_teid() == context.local_teid
        }
        PdpContextSelector::Uplink(selector) => {
            selector.link_ifindex() == context.link_ifindex
                && selector.gtp_version() == context.gtp_version
                && selector.identity().bearer_mark().is_none()
                && selector.identity().ms_address() == context.ms_address
        }
    };
    if !selector_matches {
        return Err(invalid("PDP response selector mismatch"));
    }
    Ok(context)
}

fn decode_pdp_address(
    ipv4: Option<&[u8]>,
    ipv6: Option<&[u8]>,
    missing_or_ambiguous: &'static str,
    invalid_ipv4: &'static str,
    invalid_ipv6: &'static str,
) -> Result<IpAddr, GtpuError> {
    let invalid = |reason| GtpuError::io("linux_pdp_context_decode", invalid_data(reason));
    match (ipv4, ipv6) {
        (Some(address), None) => {
            let address: [u8; 4] = address.try_into().map_err(|_| invalid(invalid_ipv4))?;
            Ok(IpAddr::V4(address.into()))
        }
        (None, Some(address)) => {
            let address: [u8; 16] = address.try_into().map_err(|_| invalid(invalid_ipv6))?;
            Ok(IpAddr::V6(address.into()))
        }
        (None, None) | (Some(_), Some(_)) => Err(invalid(missing_or_ambiguous)),
    }
}

fn decode_pdp_u32(payload: Option<&[u8]>, reason: &'static str) -> Result<u32, GtpuError> {
    let payload =
        payload.ok_or_else(|| GtpuError::io("linux_pdp_context_decode", invalid_data(reason)))?;
    if payload.len() != 4 {
        return Err(GtpuError::io(
            "linux_pdp_context_decode",
            invalid_data(reason),
        ));
    }
    Ok(u32::from_ne_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

fn append_local_address_attr(out: &mut Vec<u8>, address: IpAddr) -> Result<(), GtpuError> {
    if is_unspecified(address) {
        return Ok(());
    }
    match address {
        IpAddr::V4(address) => {
            append_attr_u32_ne(out, IFLA_GTP_LOCAL, u32::from_ne_bytes(address.octets()))
        }
        IpAddr::V6(address) => append_attr(out, IFLA_GTP_LOCAL6, &address.octets()),
    }
}

fn append_ip_attr(
    out: &mut Vec<u8>,
    address: IpAddr,
    ipv4_attr: u16,
    ipv6_attr: u16,
) -> Result<(), GtpuError> {
    match address {
        IpAddr::V4(address) => {
            append_attr_u32_ne(out, ipv4_attr, u32::from_ne_bytes(address.octets()))
        }
        IpAddr::V6(address) => append_attr(out, ipv6_attr, &address.octets()),
    }
}

fn append_attr(out: &mut Vec<u8>, attr_type: u16, payload: &[u8]) -> Result<(), GtpuError> {
    let length = ROUTE_ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(|| GtpuError::invalid_config("netlink.attr", "attribute length overflow"))?;
    let aligned = align_to_netlink(length)
        .ok_or_else(|| GtpuError::invalid_config("netlink.attr", "attribute length overflow"))?;
    let length_u16 = u16::try_from(length)
        .map_err(|_| GtpuError::invalid_config("netlink.attr", "attribute length overflow"))?;
    push_u16_ne(out, length_u16);
    push_u16_ne(out, attr_type);
    out.extend_from_slice(payload);
    out.resize(out.len() + aligned - length, 0);
    Ok(())
}

fn append_attr_string(out: &mut Vec<u8>, attr_type: u16, value: &str) -> Result<(), GtpuError> {
    if value.as_bytes().contains(&0) {
        return Err(GtpuError::invalid_config(
            "netlink.attr_string",
            "string attribute must not contain NUL",
        ));
    }
    let mut payload = Vec::with_capacity(value.len() + 1);
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
    append_attr(out, attr_type, &payload)
}

fn append_attr_u8(out: &mut Vec<u8>, attr_type: u16, value: u8) -> Result<(), GtpuError> {
    append_attr(out, attr_type, &[value])
}

fn append_attr_u16_ne(out: &mut Vec<u8>, attr_type: u16, value: u16) -> Result<(), GtpuError> {
    append_attr(out, attr_type, &value.to_ne_bytes())
}

fn append_attr_u32_ne(out: &mut Vec<u8>, attr_type: u16, value: u32) -> Result<(), GtpuError> {
    append_attr(out, attr_type, &value.to_ne_bytes())
}

fn start_attr(out: &mut Vec<u8>, attr_type: u16) -> usize {
    let start = out.len();
    push_u16_ne(out, 0);
    push_u16_ne(out, attr_type);
    start
}

fn finish_attr(out: &mut Vec<u8>, start: usize) -> Result<(), GtpuError> {
    let length = out
        .len()
        .checked_sub(start)
        .ok_or_else(|| GtpuError::invalid_config("netlink.attr", "attribute start overflow"))?;
    let aligned = align_to_netlink(length)
        .ok_or_else(|| GtpuError::invalid_config("netlink.attr", "attribute length overflow"))?;
    let length_u16 = u16::try_from(length)
        .map_err(|_| GtpuError::invalid_config("netlink.attr", "attribute length overflow"))?;
    let length_bytes = length_u16.to_ne_bytes();
    let header = out
        .get_mut(start..start + 2)
        .ok_or_else(|| GtpuError::invalid_config("netlink.attr", "attribute header overflow"))?;
    header.copy_from_slice(&length_bytes);
    out.resize(out.len() + aligned - length, 0);
    Ok(())
}

fn parse_netlink_response(
    response: &[u8],
    expected_sequence: u32,
    expected_payload_type: u16,
) -> Result<Option<Vec<u8>>, GtpuError> {
    let mut offset = 0;
    let mut payload = None;
    while offset < response.len() {
        if response.len() - offset < NETLINK_HEADER_LEN {
            return Err(GtpuError::io(
                "netlink_receive",
                invalid_data("short netlink header"),
            ));
        }
        let length = read_u32_ne(response, offset)? as usize;
        if length < NETLINK_HEADER_LEN || offset + length > response.len() {
            return Err(GtpuError::io(
                "netlink_receive",
                invalid_data("invalid netlink length"),
            ));
        }
        let message_type = read_u16_ne(response, offset + 4)?;
        let sequence = read_u32_ne(response, offset + 8)?;
        if sequence != expected_sequence {
            return Err(GtpuError::io(
                "netlink_receive",
                invalid_data("unexpected netlink sequence"),
            ));
        }

        let body = &response[offset + NETLINK_HEADER_LEN..offset + length];
        match message_type {
            NLMSG_ERROR => {
                parse_netlink_error(body)?;
                if payload.is_some() {
                    return Ok(payload);
                }
            }
            NLMSG_DONE => return Ok(payload),
            NLMSG_NOOP => {}
            _ => {
                if message_type != expected_payload_type {
                    return Err(GtpuError::io(
                        "netlink_receive",
                        invalid_data("unexpected netlink payload family"),
                    ));
                }
                if payload.is_none() {
                    payload = Some(body.to_vec());
                }
            }
        }

        let aligned = align_to_netlink(length).ok_or_else(|| {
            GtpuError::io(
                "netlink_receive",
                invalid_data("netlink alignment overflow"),
            )
        })?;
        if aligned == 0 {
            return Err(GtpuError::io(
                "netlink_receive",
                invalid_data("zero netlink alignment"),
            ));
        }
        offset += aligned;
    }
    Ok(payload)
}

fn parse_netlink_error(body: &[u8]) -> Result<(), GtpuError> {
    if body.len() < 4 {
        return Err(GtpuError::io(
            "netlink_receive",
            invalid_data("short netlink error"),
        ));
    }
    let error = i32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
    if error == 0 {
        return Ok(());
    }
    if error > 0 {
        return Err(GtpuError::io(
            "netlink_receive",
            invalid_data("positive netlink error"),
        ));
    }
    let errno = error.saturating_abs();
    if matches!(errno, ENOENT | ESRCH) {
        return Err(GtpuError::NotFound);
    }
    let io_error = io::Error::from_raw_os_error(errno);
    match io_error.kind() {
        io::ErrorKind::AlreadyExists => Err(GtpuError::AlreadyExists),
        io::ErrorKind::NotFound => Err(GtpuError::NotFound),
        _ => Err(GtpuError::io("netlink_ack", io_error)),
    }
}

fn parse_generic_family_id(body: &[u8]) -> Result<u16, GtpuError> {
    if body.len() < GENERIC_NETLINK_HEADER_LEN {
        return Err(GtpuError::io(
            "gtp_family_lookup",
            invalid_data("short generic netlink header"),
        ));
    }
    let mut offset = GENERIC_NETLINK_HEADER_LEN;
    while offset + ROUTE_ATTRIBUTE_HEADER_LEN <= body.len() {
        let length = usize::from(read_u16_ne(body, offset)?);
        let attr_type = read_u16_ne(body, offset + 2)?;
        if length < ROUTE_ATTRIBUTE_HEADER_LEN || offset + length > body.len() {
            return Err(GtpuError::io(
                "gtp_family_lookup",
                invalid_data("invalid generic netlink attr"),
            ));
        }
        if attr_type == CTRL_ATTR_FAMILY_ID {
            let payload_offset = offset + ROUTE_ATTRIBUTE_HEADER_LEN;
            if length < ROUTE_ATTRIBUTE_HEADER_LEN + 2 {
                return Err(GtpuError::io(
                    "gtp_family_lookup",
                    invalid_data("short family id attr"),
                ));
            }
            return read_u16_ne(body, payload_offset);
        }
        offset += align_to_netlink(length).ok_or_else(|| {
            GtpuError::io(
                "gtp_family_lookup",
                invalid_data("attribute alignment overflow"),
            )
        })?;
    }
    Err(GtpuError::NotFound)
}

/// Live identity of one exact link: its current name and optional
/// `IFLA_IFALIAS` bytes.
///
/// This probe is deliberately name-tolerant: callers that already know the
/// expected name compare it themselves so a renamed or replaced link can be
/// classified instead of surfacing as a decode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinkIdentityProbe {
    name: Vec<u8>,
    alias: Option<Vec<u8>>,
}

fn parse_link_identity_response(
    body: &[u8],
    expected_ifindex: u32,
    operation: &'static str,
) -> Result<LinkIdentityProbe, GtpuError> {
    let invalid = |reason| GtpuError::io(operation, invalid_data(reason));
    if body.len() < IF_INFO_MESSAGE_LEN {
        return Err(invalid("short link identity response"));
    }
    let index = i32::from_ne_bytes(
        body[4..8]
            .try_into()
            .map_err(|_| invalid("short link ifindex"))?,
    );
    if index != ifindex_i32(expected_ifindex, "pdp_recovery.device_ifindex")? {
        return Err(invalid("link identity ifindex mismatch"));
    }

    let mut offset = IF_INFO_MESSAGE_LEN;
    let mut name = None;
    let mut alias = None;
    while offset < body.len() {
        if body.len() - offset < ROUTE_ATTRIBUTE_HEADER_LEN {
            return Err(invalid("trailing link identity bytes"));
        }
        let length = usize::from(read_u16_ne(body, offset)?);
        let raw_attribute_type = read_u16_ne(body, offset + 2)?;
        if length < ROUTE_ATTRIBUTE_HEADER_LEN || offset + length > body.len() {
            return Err(invalid("invalid link identity attribute"));
        }
        let attribute_type = raw_attribute_type & 0x3fff;
        let aligned_end = offset
            .checked_add(
                align_to_netlink(length)
                    .ok_or_else(|| invalid("link identity attribute alignment overflow"))?,
            )
            .ok_or_else(|| invalid("link identity attribute alignment overflow"))?;
        if aligned_end > body.len() {
            return Err(invalid("truncated aligned link identity attribute"));
        }
        let payload = &body[offset + ROUTE_ATTRIBUTE_HEADER_LEN..offset + length];
        let slot = match attribute_type {
            IFLA_IFNAME => Some(&mut name),
            IFLA_IFALIAS => Some(&mut alias),
            _ => None,
        };
        if let Some(slot) = slot {
            if raw_attribute_type != attribute_type {
                return Err(invalid("flagged link identity attribute"));
            }
            let value = parse_nul_terminated_link_attribute(payload, operation)?;
            if slot.replace(value.to_vec()).is_some() {
                return Err(invalid("duplicate link identity attribute"));
            }
        }
        offset = aligned_end;
    }

    let name = name.ok_or_else(|| invalid("missing link name attribute"))?;
    Ok(LinkIdentityProbe { name, alias })
}

fn parse_device_alias_response(
    body: &[u8],
    expected: &GtpDevice,
) -> Result<Option<Vec<u8>>, GtpuError> {
    let invalid = |reason| GtpuError::io("pdp_device_identity_read", invalid_data(reason));
    let probe = parse_link_identity_response(body, expected.ifindex, "pdp_device_identity_read")?;
    if probe.name != expected.name.as_bytes() {
        return Err(invalid("link identity name mismatch"));
    }
    Ok(probe.alias)
}

fn parse_nul_terminated_link_attribute<'a>(
    payload: &'a [u8],
    operation: &'static str,
) -> Result<&'a [u8], GtpuError> {
    let Some(value) = payload.strip_suffix(&[0]) else {
        return Err(GtpuError::io(
            operation,
            invalid_data("unterminated link string attribute"),
        ));
    };
    if value.contains(&0) {
        return Err(GtpuError::io(
            operation,
            invalid_data("embedded NUL in link string attribute"),
        ));
    }
    Ok(value)
}

fn effective_cap_net_admin() -> Result<bool, GtpuError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| GtpuError::io("capability_probe", error))?;
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            let caps = u64::from_str_radix(hex.trim(), 16)
                .map_err(|_| GtpuError::io("capability_probe", invalid_data("invalid CapEff")))?;
            let mask = 1_u64.checked_shl(CAP_NET_ADMIN).ok_or_else(|| {
                GtpuError::io("capability_probe", invalid_data("invalid capability index"))
            })?;
            return Ok((caps & mask) != 0);
        }
    }
    Ok(false)
}

fn encode_role(role: GtpRole) -> u32 {
    match role {
        GtpRole::Ggsn => GTP_ROLE_GGSN,
        GtpRole::Sgsn => GTP_ROLE_SGSN,
    }
}

fn encode_pdp_device_alias(incarnation: PdpDeviceIncarnation) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = incarnation.to_bytes();
    let mut alias = String::with_capacity(PDP_DEVICE_ALIAS_PREFIX.len() + bytes.len() * 2);
    alias.push_str(PDP_DEVICE_ALIAS_PREFIX);
    for byte in bytes {
        alias.push(char::from(HEX[usize::from(byte >> 4)]));
        alias.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    alias
}

fn encode_version(version: GtpVersion) -> u32 {
    match version {
        GtpVersion::V1 => GTP_V1,
    }
}

fn encode_ip_family(address: IpAddr) -> u8 {
    encode_address_family(GtpAddressFamily::from_ip(address))
}

fn encode_address_family(family: GtpAddressFamily) -> u8 {
    match family {
        GtpAddressFamily::Ipv4 => AF_INET,
        GtpAddressFamily::Ipv6 => AF_INET6,
    }
}

fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn push_u16_ne(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn push_i32_ne(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn push_u32_ne(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn read_u16_ne(bytes: &[u8], offset: usize) -> Result<u16, GtpuError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| GtpuError::io("netlink_receive", invalid_data("offset overflow")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| GtpuError::io("netlink_receive", invalid_data("short netlink field")))?;
    Ok(u16::from_ne_bytes([slice[0], slice[1]]))
}

fn read_u32_ne(bytes: &[u8], offset: usize) -> Result<u32, GtpuError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| GtpuError::io("netlink_receive", invalid_data("offset overflow")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| GtpuError::io("netlink_receive", invalid_data("short netlink field")))?;
    Ok(u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn not_found(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, message)
}

fn poisoned_lock() -> io::Error {
    io::Error::other("gtpu backend mutex poisoned")
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, Ipv6Addr};
    #[cfg(target_os = "linux")]
    use std::sync::Condvar;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::model::{Teid, DEFAULT_PDP_HASHSIZE};
    use crate::{
        PdpContextMismatchField, PdpContextSelectorOccupancy, PdpRestartRecoveryProof,
        RetainedDeviceConflictReason, RetainedDeviceIdentityOutcome, RetainedDeviceIdentityRequest,
        RetainedDeviceIndeterminateReason, RetainedDeviceRepairReason,
    };

    type TransportResponse = Result<Option<Vec<u8>>, GtpuError>;

    /// A queued transport response. `Latched` blocks the (blocking-pool)
    /// caller inside `transact` until the latch is released, letting a test
    /// hold the worker at a precise netlink boundary — e.g. drop a recovery
    /// future exactly at the admitted-mutation point.
    enum QueuedResponse {
        Immediate(TransportResponse),
        #[cfg(target_os = "linux")]
        Latched {
            latch: Arc<ResponseLatch>,
            response: TransportResponse,
        },
    }

    type ResponseQueue = Arc<Mutex<VecDeque<QueuedResponse>>>;

    /// A queued link-identity probe response. `Latched` blocks the
    /// (blocking-pool) caller inside `link_identity` until the latch is
    /// released, letting a test hold the worker at the admitted identity-read
    /// boundary — e.g. drop an acquisition future exactly there.
    enum QueuedLinkIdentity {
        Immediate(Result<Option<LinkIdentityProbe>, GtpuError>),
        #[cfg(target_os = "linux")]
        Latched {
            latch: Arc<ResponseLatch>,
            response: Result<Option<LinkIdentityProbe>, GtpuError>,
        },
    }

    type LinkIdentityQueue = Arc<Mutex<VecDeque<QueuedLinkIdentity>>>;

    /// A queued name-lookup response. `Latched` blocks the (blocking-pool)
    /// caller inside `ifindex_by_name` until the latch is released, letting a
    /// test hold the worker at the admitted name-lookup boundary.
    enum QueuedIfindex {
        Immediate(IfindexResponse),
        #[cfg(target_os = "linux")]
        Latched {
            latch: Arc<ResponseLatch>,
            response: IfindexResponse,
        },
    }

    type IfindexQueue = Arc<Mutex<VecDeque<QueuedIfindex>>>;

    /// One-shot gate used to hold a transport response until released.
    #[cfg(target_os = "linux")]
    struct ResponseLatch {
        released: Mutex<bool>,
        condvar: Condvar,
    }

    #[cfg(target_os = "linux")]
    impl ResponseLatch {
        fn new() -> Self {
            Self {
                released: Mutex::new(false),
                condvar: Condvar::new(),
            }
        }

        fn release(&self) {
            let mut released = self
                .released
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *released = true;
            self.condvar.notify_all();
        }

        fn wait(&self) {
            let mut released = self
                .released
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            while !*released {
                released = self
                    .condvar
                    .wait(released)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
    }

    #[cfg(target_os = "linux")]
    struct ResponseLatchReleaseGuard(Option<Arc<ResponseLatch>>);

    #[cfg(target_os = "linux")]
    impl ResponseLatchReleaseGuard {
        fn new(latch: Arc<ResponseLatch>) -> Self {
            Self(Some(latch))
        }

        fn release_now(&mut self) {
            if let Some(latch) = self.0.take() {
                latch.release();
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ResponseLatchReleaseGuard {
        fn drop(&mut self) {
            self.release_now();
        }
    }

    #[cfg(target_os = "linux")]
    struct ChildProcessGuard(Option<std::process::Child>);

    #[cfg(target_os = "linux")]
    impl ChildProcessGuard {
        fn new(child: std::process::Child) -> Self {
            Self(Some(child))
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ChildProcessGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl fmt::Debug for ResponseLatch {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ResponseLatch").finish_non_exhaustive()
        }
    }

    impl fmt::Debug for QueuedResponse {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                QueuedResponse::Immediate(_) => {
                    f.write_str("QueuedResponse::Immediate(<netlink-response>)")
                }
                #[cfg(target_os = "linux")]
                QueuedResponse::Latched { .. } => {
                    f.write_str("QueuedResponse::Latched(<latched-netlink-response>)")
                }
            }
        }
    }

    impl fmt::Debug for QueuedLinkIdentity {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                QueuedLinkIdentity::Immediate(_) => {
                    f.write_str("QueuedLinkIdentity::Immediate(<link-identity>)")
                }
                #[cfg(target_os = "linux")]
                QueuedLinkIdentity::Latched { .. } => {
                    f.write_str("QueuedLinkIdentity::Latched(<latched-link-identity>)")
                }
            }
        }
    }

    impl fmt::Debug for QueuedIfindex {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                QueuedIfindex::Immediate(_) => {
                    f.write_str("QueuedIfindex::Immediate(<name-lookup>)")
                }
                #[cfg(target_os = "linux")]
                QueuedIfindex::Latched { .. } => {
                    f.write_str("QueuedIfindex::Latched(<latched-name-lookup>)")
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    struct CapturingTransport {
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        responses: ResponseQueue,
        ifindex_responses: IfindexQueue,
        link_identity_responses: LinkIdentityQueue,
        /// Counts admitted name lookups. A latched lookup blocks the caller
        /// after this increments, so a test can observe the exact
        /// admitted-name-lookup boundary.
        ifindex_admissions: Arc<AtomicU32>,
        /// Counts admitted link-identity probes. A latched probe blocks the
        /// caller after this increments, so a test can observe the exact
        /// admitted-identity-read boundary.
        link_identity_admissions: Arc<AtomicU32>,
        probe: GtpuProbe,
        socket_fd: i32,
        ifindex: u32,
        device_alias: Option<Vec<u8>>,
        link_identity: Option<LinkIdentityProbe>,
    }

    fn test_link_identity() -> LinkIdentityProbe {
        LinkIdentityProbe {
            name: b"gtp0".to_vec(),
            alias: Some(encode_pdp_device_alias(test_device_incarnation()).into_bytes()),
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum IfindexResponse {
        Found(u32),
        NotFound,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CapturedRequest {
        protocol: NetlinkProtocol,
        operation: &'static str,
        request: Vec<u8>,
        expected_sequence: u32,
    }

    impl CapturingTransport {
        fn new() -> Self {
            Self {
                requests: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(VecDeque::new())),
                ifindex_responses: Arc::new(Mutex::new(VecDeque::new())),
                link_identity_responses: Arc::new(Mutex::new(VecDeque::new())),
                ifindex_admissions: Arc::new(AtomicU32::new(0)),
                link_identity_admissions: Arc::new(AtomicU32::new(0)),
                probe: GtpuProbe {
                    kind: GtpuBackendKind::LinuxKernel,
                    platform_supported: true,
                    kernel_reachable: true,
                    gtp_module_present: true,
                    net_admin_capable: true,
                    bpf_capable: false,
                    btf_present: false,
                    mutation_ready: true,
                    egress_dscp_marking: GtpuCapability::Missing,
                    per_bearer_marking: GtpuCapability::Missing,
                    downlink_endpoint_binding: GtpuCapability::Missing,
                    uplink_source_port_selection: GtpuCapability::Missing,
                    uplink_pmtu_enforcement: GtpuCapability::Missing,
                    downlink_outer_fragment_handling: GtpuDownlinkFragmentContract::Unsupported,
                    details: Some("test transport"),
                },
                socket_fd: 9,
                ifindex: 42,
                device_alias: Some(encode_pdp_device_alias(test_device_incarnation()).into_bytes()),
                link_identity: Some(test_link_identity()),
            }
        }

        fn with_response(response: Result<Option<Vec<u8>>, GtpuError>) -> Self {
            let transport = Self::new();
            transport.push_response(response);
            transport
        }

        fn push_response(&self, response: Result<Option<Vec<u8>>, GtpuError>) {
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(QueuedResponse::Immediate(response));
        }

        #[cfg(target_os = "linux")]
        fn push_latched_response(
            &self,
            latch: Arc<ResponseLatch>,
            response: Result<Option<Vec<u8>>, GtpuError>,
        ) {
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(QueuedResponse::Latched { latch, response });
        }

        fn push_ifindex_response(&self, response: IfindexResponse) {
            self.ifindex_responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(QueuedIfindex::Immediate(response));
        }

        #[cfg(target_os = "linux")]
        fn push_latched_ifindex_response(
            &self,
            latch: Arc<ResponseLatch>,
            response: IfindexResponse,
        ) {
            self.ifindex_responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(QueuedIfindex::Latched { latch, response });
        }

        fn push_link_identity_response(
            &self,
            response: Result<Option<LinkIdentityProbe>, GtpuError>,
        ) {
            self.link_identity_responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(QueuedLinkIdentity::Immediate(response));
        }

        #[cfg(target_os = "linux")]
        fn push_latched_link_identity_response(
            &self,
            latch: Arc<ResponseLatch>,
            response: Result<Option<LinkIdentityProbe>, GtpuError>,
        ) {
            self.link_identity_responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(QueuedLinkIdentity::Latched { latch, response });
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[test]
    fn netlink_probe_does_not_claim_unproven_fragment_handoff() {
        let probe = LinuxGtpuTransport::probe(
            &NetlinkGtpuTransport,
            LinuxGtpuDataplaneBackendConfig {
                receive_attempts: 1,
                receive_buffer_len: 4096,
                retry_delay: Duration::ZERO,
            },
        );

        assert_eq!(
            probe.downlink_outer_fragment_handling,
            GtpuDownlinkFragmentContract::Unsupported
        );
    }

    impl LinuxGtpuTransport for CapturingTransport {
        fn transact(
            &self,
            protocol: NetlinkProtocol,
            operation: &'static str,
            request: &[u8],
            expected_sequence: u32,
            _config: LinuxGtpuDataplaneBackendConfig,
        ) -> Result<Option<Vec<u8>>, GtpuError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(CapturedRequest {
                    protocol,
                    operation,
                    request: request.to_vec(),
                    expected_sequence,
                });
            let queued = self
                .responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front();
            match queued {
                Some(QueuedResponse::Immediate(response)) => response,
                #[cfg(target_os = "linux")]
                Some(QueuedResponse::Latched { latch, response }) => {
                    // Hold the (blocking-pool) caller here until the test
                    // releases the latch; the requests log already records the
                    // admitted operation.
                    latch.wait();
                    response
                }
                None => Ok(None),
            }
        }

        fn open_gtpu_socket(
            &self,
            _bind_address: IpAddr,
            _bind_port: u16,
            _operation: &'static str,
        ) -> Result<GtpuSocketHandle, GtpuError> {
            Ok(GtpuSocketHandle::fake(self.socket_fd))
        }

        fn ifindex_by_name(&self, _name: &str) -> Result<u32, GtpuError> {
            self.ifindex_admissions.fetch_add(1, Ordering::SeqCst);
            let queued = self
                .ifindex_responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front();
            let response = match queued {
                Some(QueuedIfindex::Immediate(response)) => response,
                #[cfg(target_os = "linux")]
                Some(QueuedIfindex::Latched { latch, response }) => {
                    // Hold the (blocking-pool) caller here until the test
                    // releases the latch; the admission counter already
                    // records the admitted name lookup.
                    latch.wait();
                    response
                }
                None => return Ok(self.ifindex),
            };
            match response {
                IfindexResponse::Found(ifindex) => Ok(ifindex),
                IfindexResponse::NotFound => Err(GtpuError::NotFound),
            }
        }

        fn device_alias(
            &self,
            _device: &GtpDevice,
            _config: LinuxGtpuDataplaneBackendConfig,
        ) -> Result<Option<Vec<u8>>, GtpuError> {
            Ok(self.device_alias.clone())
        }

        fn link_identity(
            &self,
            _ifindex: u32,
            _config: LinuxGtpuDataplaneBackendConfig,
        ) -> Result<Option<LinkIdentityProbe>, GtpuError> {
            self.link_identity_admissions.fetch_add(1, Ordering::SeqCst);
            let queued = self
                .link_identity_responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front();
            match queued {
                Some(QueuedLinkIdentity::Immediate(response)) => response,
                #[cfg(target_os = "linux")]
                Some(QueuedLinkIdentity::Latched { latch, response }) => {
                    // Hold the (blocking-pool) caller here until the test
                    // releases the latch; the admission counter already
                    // records the admitted identity read.
                    latch.wait();
                    response
                }
                None => Ok(self.link_identity.clone()),
            }
        }

        fn probe(&self, _config: LinuxGtpuDataplaneBackendConfig) -> GtpuProbe {
            self.probe
        }
    }

    impl CapturingTransport {
        fn ifindex_admissions(&self) -> u32 {
            self.ifindex_admissions.load(Ordering::SeqCst)
        }

        fn link_identity_admissions(&self) -> u32 {
            self.link_identity_admissions.load(Ordering::SeqCst)
        }
    }

    fn teid(value: u32) -> Teid {
        Teid::new(value).unwrap()
    }

    fn test_device_incarnation() -> PdpDeviceIncarnation {
        PdpDeviceIncarnation::from_bytes([0xa5; 16]).unwrap()
    }

    fn pdp_context() -> GtpPdpContext {
        GtpPdpContext {
            local_teid: teid(0x1122_3344),
            peer_teid: teid(0x5566_7788),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 42,
            downlink_source_port_policy: crate::GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
        }
    }

    fn mixed_family_pdp_contexts() -> [GtpPdpContext; 2] {
        let mut ipv6_ms_ipv4_peer = pdp_context();
        // Linux currently represents an IPv6 MS/PAA as the canonical /64
        // prefix (the lower 64 bits must be zero in ipv6_pdp_fill).
        ipv6_ms_ipv4_peer.ms_address = "2001:db8:23:1::".parse().unwrap();

        let mut ipv4_ms_ipv6_peer = pdp_context();
        ipv4_ms_ipv6_peer.peer_address = "2001:db8:ffff::10".parse().unwrap();

        [ipv6_ms_ipv4_peer, ipv4_ms_ipv6_peer]
    }

    fn ack(sequence: u32) -> Vec<u8> {
        let mut body = Vec::new();
        push_i32_ne(&mut body, 0);
        encode_netlink_message(NLMSG_ERROR, 0, sequence, &body).unwrap()
    }

    fn netlink_error(sequence: u32, errno: i32) -> Vec<u8> {
        let mut body = Vec::new();
        push_i32_ne(&mut body, -errno);
        encode_netlink_message(NLMSG_ERROR, 0, sequence, &body).unwrap()
    }

    fn family_response(sequence: u32, family_id: u16) -> Vec<u8> {
        let mut body = encode_gtp_genl_header(CTRL_CMD_GETFAMILY);
        append_attr_u16_ne(&mut body, CTRL_ATTR_FAMILY_ID, family_id).unwrap();
        encode_netlink_message(GENL_ID_CTRL, 0, sequence, &body).unwrap()
    }

    fn pdp_response(context: &GtpPdpContext, include_family: bool) -> Vec<u8> {
        let mut body = encode_gtp_genl_header(GTP_CMD_GETPDP);
        append_attr_u32_ne(&mut body, GTPA_LINK, context.link_ifindex).unwrap();
        append_attr_u32_ne(&mut body, GTPA_VERSION, encode_version(context.gtp_version)).unwrap();
        if include_family {
            append_attr_u8(&mut body, GTPA_FAMILY, encode_ip_family(context.ms_address)).unwrap();
        }
        append_ip_attr(
            &mut body,
            context.ms_address,
            GTPA_MS_ADDRESS,
            GTPA_MS_ADDR6,
        )
        .unwrap();
        append_ip_attr(
            &mut body,
            context.peer_address,
            GTPA_PEER_ADDRESS,
            GTPA_PEER_ADDR6,
        )
        .unwrap();
        append_attr_u32_ne(&mut body, GTPA_I_TEI, context.local_teid.get()).unwrap();
        append_attr_u32_ne(&mut body, GTPA_O_TEI, context.peer_teid.get()).unwrap();
        body
    }

    fn push_family_lookup(transport: &CapturingTransport) {
        transport.push_response(Ok(Some(netlink_body(&family_response(1, 31)).to_vec())));
    }

    fn push_present(transport: &CapturingTransport, context: &GtpPdpContext) {
        transport.push_response(Ok(Some(pdp_response(context, false))));
    }

    fn push_present_with_family(
        transport: &CapturingTransport,
        context: &GtpPdpContext,
        include_family: bool,
    ) {
        transport.push_response(Ok(Some(pdp_response(context, include_family))));
    }

    fn push_absent(transport: &CapturingTransport) {
        transport.push_response(Err(GtpuError::NotFound));
    }

    fn netlink_body(message: &[u8]) -> &[u8] {
        let len = u32::from_ne_bytes([message[0], message[1], message[2], message[3]]) as usize;
        &message[NETLINK_HEADER_LEN..len]
    }

    fn attr_payload(body: &[u8], attr_type: u16) -> Option<&[u8]> {
        attr_payload_from(body, 0, attr_type)
    }

    fn attr_payload_from(body: &[u8], mut offset: usize, attr_type: u16) -> Option<&[u8]> {
        while offset + ROUTE_ATTRIBUTE_HEADER_LEN <= body.len() {
            let len = usize::from(u16::from_ne_bytes([body[offset], body[offset + 1]]));
            let found_type = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]);
            if len < ROUTE_ATTRIBUTE_HEADER_LEN || offset + len > body.len() {
                return None;
            }
            let payload = &body[offset + ROUTE_ATTRIBUTE_HEADER_LEN..offset + len];
            if found_type == attr_type {
                return Some(payload);
            }
            offset += align_to_netlink(len)?;
        }
        None
    }

    fn replace_attr_payload(body: &mut [u8], attr_type: u16, replacement: &[u8]) -> bool {
        let mut offset = GENERIC_NETLINK_HEADER_LEN;
        while offset + ROUTE_ATTRIBUTE_HEADER_LEN <= body.len() {
            let len = usize::from(u16::from_ne_bytes([body[offset], body[offset + 1]]));
            let found_type = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]) & 0x3fff;
            if len < ROUTE_ATTRIBUTE_HEADER_LEN || offset + len > body.len() {
                return false;
            }
            if found_type == attr_type && replacement.len() == len - ROUTE_ATTRIBUTE_HEADER_LEN {
                body[offset + ROUTE_ATTRIBUTE_HEADER_LEN..offset + len]
                    .copy_from_slice(replacement);
                return true;
            }
            let Some(aligned) = align_to_netlink(len) else {
                return false;
            };
            offset += aligned;
        }
        false
    }

    fn attr_u32(body: &[u8], attr_type: u16) -> u32 {
        let payload = attr_payload(body, attr_type).unwrap();
        u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]])
    }

    fn attr_u8(body: &[u8], attr_type: u16) -> u8 {
        attr_payload(body, attr_type).unwrap()[0]
    }

    fn retained_socket_count(backend: &LinuxGtpuDataplaneBackend) -> usize {
        backend
            .inner
            .device_sockets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    #[test]
    fn encodes_create_device_with_fd1_role_and_hashsize() {
        let request = CreateGtpDeviceRequest::new("gtp0");
        let body = encode_create_device_request(&request, 9).unwrap();

        assert_eq!(body[0], AF_INET);
        assert_eq!(i32::from_ne_bytes([body[4], body[5], body[6], body[7]]), 0);
        assert_eq!(
            u32::from_ne_bytes([body[8], body[9], body[10], body[11]]),
            IFF_UP
        );
        assert_eq!(
            attr_payload_from(&body, IF_INFO_MESSAGE_LEN, IFLA_IFNAME),
            Some(&b"gtp0\0"[..])
        );

        let linkinfo = attr_payload_from(&body, IF_INFO_MESSAGE_LEN, IFLA_LINKINFO).unwrap();
        assert_eq!(attr_payload(linkinfo, IFLA_INFO_KIND), Some(&b"gtp\0"[..]));
        let info_data = attr_payload(linkinfo, IFLA_INFO_DATA).unwrap();
        assert_eq!(attr_u32(info_data, IFLA_GTP_FD1), 9);
        assert_eq!(
            attr_u32(info_data, IFLA_GTP_PDP_HASHSIZE),
            DEFAULT_PDP_HASHSIZE
        );
        assert_eq!(attr_u32(info_data, IFLA_GTP_ROLE), GTP_ROLE_GGSN);
        assert!(attr_payload(info_data, IFLA_GTP_LOCAL).is_none());
        assert!(attr_payload_from(&body, IF_INFO_MESSAGE_LEN, IFLA_IFALIAS).is_none());
    }

    #[test]
    fn encodes_recoverable_device_incarnation_stamp_in_kernel_alias() {
        let device = GtpDevice {
            name: "gtp0".to_string(),
            ifindex: 42,
        };
        let incarnation = test_device_incarnation();
        let body = encode_set_device_alias_request(&device, incarnation).unwrap();
        let mut expected = encode_pdp_device_alias(incarnation).into_bytes();
        expected.push(0);

        assert_eq!(
            attr_payload_from(&body, IF_INFO_MESSAGE_LEN, IFLA_IFALIAS),
            Some(expected.as_slice())
        );
        assert_eq!(
            i32::from_ne_bytes(body[4..8].try_into().unwrap()),
            device.ifindex as i32
        );
    }

    #[test]
    fn encodes_create_device_with_sgsn_role_and_ipv6_local() {
        let mut request = CreateGtpDeviceRequest::new("gtp6");
        request.role = GtpRole::Sgsn;
        request.bind_address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        request.pdp_hashsize = None;
        let body = encode_create_device_request(&request, 10).unwrap();
        let linkinfo = attr_payload_from(&body, IF_INFO_MESSAGE_LEN, IFLA_LINKINFO).unwrap();
        let info_data = attr_payload(linkinfo, IFLA_INFO_DATA).unwrap();
        assert_eq!(attr_u32(info_data, IFLA_GTP_ROLE), GTP_ROLE_SGSN);
        assert_eq!(
            attr_payload(info_data, IFLA_GTP_LOCAL6),
            Some(&Ipv6Addr::LOCALHOST.octets()[..])
        );
        assert!(attr_payload(info_data, IFLA_GTP_PDP_HASHSIZE).is_none());
    }

    #[test]
    fn encodes_install_pdp_context_attrs() {
        let body = encode_install_pdp_context(&pdp_context()).unwrap();
        assert_eq!(body[0], GTP_CMD_NEWPDP);
        assert_eq!(body[1], GTP_GENL_VERSION);
        assert_eq!(attr_u32(&body[GENERIC_NETLINK_HEADER_LEN..], GTPA_LINK), 42);
        assert_eq!(
            attr_u32(&body[GENERIC_NETLINK_HEADER_LEN..], GTPA_VERSION),
            GTP_V1
        );
        assert_eq!(
            attr_u8(&body[GENERIC_NETLINK_HEADER_LEN..], GTPA_FAMILY),
            AF_INET
        );
        assert_eq!(
            attr_payload(&body[GENERIC_NETLINK_HEADER_LEN..], GTPA_MS_ADDRESS)
                .unwrap()
                .to_vec(),
            Ipv4Addr::new(10, 23, 0, 2).octets()
        );
        assert_eq!(
            attr_payload(&body[GENERIC_NETLINK_HEADER_LEN..], GTPA_PEER_ADDRESS)
                .unwrap()
                .to_vec(),
            Ipv4Addr::new(192, 0, 2, 10).octets()
        );
        assert_eq!(
            attr_u32(&body[GENERIC_NETLINK_HEADER_LEN..], GTPA_I_TEI),
            0x1122_3344
        );
        assert_eq!(
            attr_u32(&body[GENERIC_NETLINK_HEADER_LEN..], GTPA_O_TEI),
            0x5566_7788
        );
    }

    #[test]
    fn kernel_backend_rejects_fixed_outer_dscp_without_sending_it() {
        let baseline = pdp_context();
        let baseline_bytes = encode_install_pdp_context(&baseline).unwrap();
        assert!(validate_pdp_context(&baseline).is_ok());

        let mut marked = baseline.clone();
        marked.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        assert!(matches!(
            validate_pdp_context(&marked).unwrap_err(),
            GtpuError::UnsupportedFeature {
                feature: "fixed_outer_dscp"
            }
        ));
        // The encoder has no hidden DSCP attribute: the supported None path
        // remains exactly the established netlink payload.
        assert_eq!(
            encode_install_pdp_context(&baseline).unwrap(),
            baseline_bytes
        );
    }

    #[test]
    fn kernel_backend_rejects_bounded_source_port_policy_without_sending_it() {
        for policy in [
            crate::GtpuSourcePortPolicy::Exact(21_152),
            crate::GtpuSourcePortPolicy::inclusive_range(20_000, 21_000).unwrap(),
        ] {
            let baseline = pdp_context();
            let baseline_bytes = encode_install_pdp_context(&baseline).unwrap();
            let mut bounded = baseline.clone();
            bounded.downlink_source_port_policy = policy;

            assert!(matches!(
                validate_pdp_context(&bounded).unwrap_err(),
                GtpuError::UnsupportedFeature {
                    feature: "downlink_source_port_policy"
                }
            ));
            assert_eq!(
                encode_install_pdp_context(&baseline).unwrap(),
                baseline_bytes
            );
        }
    }

    #[test]
    fn kernel_backend_rejects_selected_uplink_source_port_without_sending_it() {
        let baseline = pdp_context();
        let baseline_bytes = encode_install_pdp_context(&baseline).unwrap();
        let mut selected = baseline.clone();
        selected.uplink_source_port_policy =
            crate::GtpuUplinkSourcePortPolicy::selected(40_000).unwrap();

        assert!(matches!(
            validate_pdp_context(&selected).unwrap_err(),
            GtpuError::UnsupportedFeature {
                feature: "uplink_source_port_selection"
            }
        ));
        // The explicit legacy policy remains the exact established payload.
        assert_eq!(
            encode_install_pdp_context(&baseline).unwrap(),
            baseline_bytes
        );
    }

    #[test]
    fn encodes_ipv6_pdp_context_attrs() {
        let mut context = pdp_context();
        let ms_address: Ipv6Addr = "2001:db8:23:1::".parse().unwrap();
        context.ms_address = IpAddr::V6(ms_address);
        context.peer_address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let body = encode_install_pdp_context(&context).unwrap();
        let attrs = &body[GENERIC_NETLINK_HEADER_LEN..];
        assert_eq!(attr_u8(attrs, GTPA_FAMILY), AF_INET6);
        assert_eq!(
            attr_payload(attrs, GTPA_MS_ADDR6),
            Some(&ms_address.octets()[..])
        );
        assert_eq!(
            attr_payload(attrs, GTPA_PEER_ADDR6),
            Some(&Ipv6Addr::LOCALHOST.octets()[..])
        );
    }

    #[test]
    fn encodes_remove_pdp_context_attrs() {
        let request = RemovePdpContextRequest::from_context(&pdp_context());
        let body = encode_remove_pdp_context(&request).unwrap();
        let attrs = &body[GENERIC_NETLINK_HEADER_LEN..];
        assert_eq!(body[0], GTP_CMD_DELPDP);
        assert_eq!(attr_u32(attrs, GTPA_LINK), 42);
        assert_eq!(attr_u32(attrs, GTPA_VERSION), GTP_V1);
        assert_eq!(attr_u8(attrs, GTPA_FAMILY), AF_INET);
        assert_eq!(attr_u32(attrs, GTPA_I_TEI), 0x1122_3344);
        assert!(attr_payload(attrs, GTPA_O_TEI).is_none());
        // Axis purity: DELPDP selects only the downlink I_TEI axis. The kernel
        // checks GTPA_MS_ADDRESS before GTPA_I_TEI, so sending an MS attribute
        // would silently flip the lookup axis; it must never be present.
        assert!(attr_payload(attrs, GTPA_MS_ADDRESS).is_none());
        assert!(attr_payload(attrs, GTPA_MS_ADDR6).is_none());
    }

    #[test]
    fn encodes_remove_device_by_ifindex() {
        let body = encode_remove_device_request(&GtpDevice {
            name: "gtp0".to_string(),
            ifindex: 42,
        })
        .unwrap();

        assert_eq!(body[0], AF_INET);
        assert_eq!(i32::from_ne_bytes([body[4], body[5], body[6], body[7]]), 42);
        assert_eq!(
            u32::from_ne_bytes([body[12], body[13], body[14], body[15]]),
            IFF_UP
        );
    }

    #[test]
    fn parses_ack_and_errno_mapping() {
        assert_eq!(parse_netlink_response(&ack(7), 7, 31).unwrap(), None);

        let err = parse_netlink_response(&netlink_error(8, 17), 8, 31).unwrap_err();
        assert!(matches!(err, GtpuError::AlreadyExists));

        let err = parse_netlink_response(&netlink_error(9, 95), 9, 31).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(95));

        let err = parse_netlink_response(&netlink_error(10, ENOENT), 10, 31).unwrap_err();
        assert!(matches!(err, GtpuError::NotFound));
    }

    #[test]
    fn rejects_malformed_netlink_responses() {
        let err = parse_netlink_response(&[0_u8; NETLINK_HEADER_LEN - 1], 1, 31).unwrap_err();
        assert_eq!(err.io_kind(), Some(io::ErrorKind::InvalidData));

        let mut invalid_len = ack(1);
        invalid_len[0..4].copy_from_slice(&(NETLINK_HEADER_LEN as u32 - 1).to_ne_bytes());
        let err = parse_netlink_response(&invalid_len, 1, 31).unwrap_err();
        assert_eq!(err.io_kind(), Some(io::ErrorKind::InvalidData));

        let err = parse_netlink_response(&ack(2), 1, 31).unwrap_err();
        assert_eq!(err.io_kind(), Some(io::ErrorKind::InvalidData));

        let wrong_family =
            encode_netlink_message(30, 0, 1, &encode_gtp_genl_header(GTP_CMD_GETPDP)).unwrap();
        let err = parse_netlink_response(&wrong_family, 1, 31).unwrap_err();
        assert_eq!(err.io_kind(), Some(io::ErrorKind::InvalidData));
    }

    #[test]
    fn parses_multipart_payload_before_ack() {
        let mut payload_body = encode_gtp_genl_header(CTRL_CMD_GETFAMILY);
        append_attr_u16_ne(&mut payload_body, CTRL_ATTR_FAMILY_ID, 31).unwrap();
        let mut response = encode_netlink_message(GENL_ID_CTRL, 0, 9, &payload_body).unwrap();
        response.extend_from_slice(&ack(9));

        let payload = parse_netlink_response(&response, 9, GENL_ID_CTRL)
            .unwrap()
            .unwrap();
        assert_eq!(parse_generic_family_id(&payload).unwrap(), 31);
    }

    #[test]
    fn parses_generic_family_response() {
        let response = parse_netlink_response(&family_response(3, 29), 3, GENL_ID_CTRL)
            .unwrap()
            .unwrap();
        assert_eq!(parse_generic_family_id(&response).unwrap(), 29);
    }

    #[test]
    fn parses_strict_pdp_readback_with_kernel_family_omission() {
        let ipv4 = pdp_context();
        let local = PdpContextSelector::LocalTeid(
            PdpContextLocalTeidSelector::from_context(&ipv4).unwrap(),
        );
        assert_eq!(
            parse_pdp_context_response(&pdp_response(&ipv4, false), &local, 31).unwrap(),
            ipv4
        );

        let mut ipv6 = pdp_context();
        ipv6.ms_address = "2001:db8:23:1::".parse().unwrap();
        ipv6.peer_address = "2001:db8::2".parse().unwrap();
        let uplink =
            PdpContextSelector::Uplink(PdpContextUplinkSelector::from_context(&ipv6).unwrap());
        assert_eq!(
            parse_pdp_context_response(&pdp_response(&ipv6, false), &uplink, 31).unwrap(),
            ipv6
        );
    }

    #[test]
    fn parses_mixed_inner_outer_families_by_both_selectors_with_optional_family() {
        for context in mixed_family_pdp_contexts() {
            let selectors = [
                PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context).unwrap(),
                ),
                PdpContextSelector::Uplink(
                    PdpContextUplinkSelector::from_context(&context).unwrap(),
                ),
            ];
            for include_family in [false, true] {
                for selector in &selectors {
                    assert_eq!(
                        parse_pdp_context_response(
                            &pdp_response(&context, include_family),
                            selector,
                            31,
                        )
                        .unwrap(),
                        context
                    );
                }
            }
        }
    }

    #[test]
    fn pdp_readback_decoder_rejects_ambiguous_or_malformed_identity() {
        let context = pdp_context();
        let selector = PdpContextSelector::LocalTeid(
            PdpContextLocalTeidSelector::from_context(&context).unwrap(),
        );

        let mut duplicate = pdp_response(&context, true);
        append_attr_u32_ne(&mut duplicate, GTPA_LINK, context.link_ifindex).unwrap();
        assert!(parse_pdp_context_response(&duplicate, &selector, 31).is_err());

        let mut mixed = pdp_response(&context, true);
        append_attr(&mut mixed, GTPA_MS_ADDR6, &Ipv6Addr::LOCALHOST.octets()).unwrap();
        append_attr(&mut mixed, GTPA_PEER_ADDR6, &Ipv6Addr::LOCALHOST.octets()).unwrap();
        assert!(parse_pdp_context_response(&mixed, &selector, 31).is_err());

        let mut zero_teid = pdp_response(&context, true);
        assert!(replace_attr_payload(
            &mut zero_teid,
            GTPA_I_TEI,
            &0_u32.to_ne_bytes()
        ));
        assert!(parse_pdp_context_response(&zero_teid, &selector, 31).is_err());

        let mut wrong_family = pdp_response(&context, true);
        assert!(replace_attr_payload(
            &mut wrong_family,
            GTPA_FAMILY,
            &[AF_INET6]
        ));
        assert!(parse_pdp_context_response(&wrong_family, &selector, 31).is_err());

        let mut nonzero_padding = pdp_response(&context, true);
        append_attr(&mut nonzero_padding, 0x3ffe, &[1]).unwrap();
        let last = nonzero_padding.len() - 1;
        nonzero_padding[last] = 1;
        assert!(parse_pdp_context_response(&nonzero_padding, &selector, 31).is_err());

        let mut truncated = pdp_response(&context, true);
        truncated.pop();
        assert!(parse_pdp_context_response(&truncated, &selector, 31).is_err());

        let mut selector_mismatch = context.clone();
        selector_mismatch.local_teid = teid(9);
        assert!(parse_pdp_context_response(
            &pdp_response(&context, true),
            &PdpContextSelector::LocalTeid(
                PdpContextLocalTeidSelector::from_context(&selector_mismatch).unwrap(),
            ),
            31,
        )
        .is_err());
    }

    #[test]
    fn pdp_readback_decoder_rejects_unmodeled_attributes_and_allows_kernel_command_quirk() {
        let context = pdp_context();
        let selector =
            PdpContextSelector::Uplink(PdpContextUplinkSelector::from_context(&context).unwrap());
        let mut body = pdp_response(&context, false);
        body[0] = 31;
        assert_eq!(
            parse_pdp_context_response(&body, &selector, 31).unwrap(),
            context
        );

        let mut unknown = body.clone();
        append_attr(&mut unknown, 0x3ffe, &[1, 2, 3]).unwrap();
        assert!(parse_pdp_context_response(&unknown, &selector, 31).is_err());

        let mut flagged = body.clone();
        let flagged_link = (GTPA_LINK | 0x8000).to_ne_bytes();
        flagged[GENERIC_NETLINK_HEADER_LEN + 2..GENERIC_NETLINK_HEADER_LEN + 4]
            .copy_from_slice(&flagged_link);
        assert!(parse_pdp_context_response(&flagged, &selector, 31).is_err());

        body[0] = GTP_CMD_NEWPDP;
        assert!(parse_pdp_context_response(&body, &selector, 31).is_err());
    }

    #[test]
    fn rejects_malformed_generic_family_responses() {
        assert!(matches!(
            parse_generic_family_id(&[]),
            Err(GtpuError::Io { .. })
        ));

        let body = encode_gtp_genl_header(CTRL_CMD_GETFAMILY);
        assert!(matches!(
            parse_generic_family_id(&body),
            Err(GtpuError::NotFound)
        ));

        let mut malformed_attr = encode_gtp_genl_header(CTRL_CMD_GETFAMILY);
        push_u16_ne(&mut malformed_attr, 3);
        push_u16_ne(&mut malformed_attr, CTRL_ATTR_FAMILY_ID);
        malformed_attr.push(0);
        let err = parse_generic_family_id(&malformed_attr).unwrap_err();
        assert_eq!(err.io_kind(), Some(io::ErrorKind::InvalidData));
    }

    #[test]
    fn parses_exact_link_identity_alias_and_rejects_identity_drift() {
        let device = GtpDevice {
            name: "gtp0".to_string(),
            ifindex: 42,
        };
        let alias = encode_pdp_device_alias(test_device_incarnation());
        let mut body = encode_get_device_request(device.ifindex).unwrap();
        append_attr_string(&mut body, IFLA_IFNAME, &device.name).unwrap();
        append_attr_string(&mut body, IFLA_IFALIAS, &alias).unwrap();

        assert_eq!(
            parse_device_alias_response(&body, &device).unwrap(),
            Some(alias.as_bytes().to_vec())
        );

        let replaced = GtpDevice {
            name: device.name.clone(),
            ifindex: device.ifindex + 1,
        };
        assert!(parse_device_alias_response(&body, &replaced).is_err());

        let mut flagged = body;
        let alias_offset = IF_INFO_MESSAGE_LEN
            + align_to_netlink(ROUTE_ATTRIBUTE_HEADER_LEN + device.name.len() + 1).unwrap();
        let flagged_type = (IFLA_IFALIAS | 0x8000).to_ne_bytes();
        flagged[alias_offset + 2..alias_offset + 4].copy_from_slice(&flagged_type);
        assert!(parse_device_alias_response(&flagged, &device).is_err());
    }

    #[tokio::test]
    async fn linux_backend_create_device_uses_route_netlink_and_returns_ifindex() {
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone());
        let device = backend
            .create_device(CreateGtpDeviceRequest::new("gtp0"))
            .await
            .unwrap();
        assert_eq!(device.ifindex, 42);
        assert_eq!(retained_socket_count(&backend), 1);

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].protocol, NetlinkProtocol::Route);
        assert_eq!(requests[0].operation, "create_device");
        assert_eq!(requests[0].expected_sequence, 1);
        let body = netlink_body(&requests[0].request);
        let linkinfo = attr_payload_from(body, IF_INFO_MESSAGE_LEN, IFLA_LINKINFO).unwrap();
        let info_data = attr_payload(linkinfo, IFLA_INFO_DATA).unwrap();
        assert_eq!(attr_u32(info_data, IFLA_GTP_FD1), 9);
    }

    #[tokio::test]
    async fn linux_recoverable_device_reconciles_alias_ack_loss_before_publication() {
        let root = unique_recovery_root("create-recoverable-ack-loss");
        let transport = CapturingTransport::new();
        transport.push_ifindex_response(IfindexResponse::NotFound);
        transport.push_response(Ok(None));
        transport.push_response(Err(GtpuError::io(
            "netlink_ack",
            io::Error::new(io::ErrorKind::TimedOut, "redacted"),
        )));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let device = backend
            .create_recoverable_device(
                CreateGtpDeviceRequest::new("gtp0"),
                test_device_incarnation(),
            )
            .await
            .unwrap();

        assert_eq!(device.ifindex, 42);
        assert_eq!(retained_socket_count(&backend), 1);
        assert_eq!(
            transport
                .requests()
                .iter()
                .map(|request| request.operation)
                .collect::<Vec<_>>(),
            vec!["create_device", "pdp_device_identity_stamp"]
        );
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_recoverable_device_reconciles_create_ack_loss_before_publication() {
        let root = unique_recovery_root("create-recoverable-create-ack-loss");
        let transport = CapturingTransport::new();
        transport.push_ifindex_response(IfindexResponse::NotFound);
        transport.push_ifindex_response(IfindexResponse::Found(42));
        transport.push_response(Err(GtpuError::io(
            "netlink_ack",
            io::Error::new(io::ErrorKind::TimedOut, "redacted"),
        )));
        transport.push_response(Ok(None));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let device = backend
            .create_recoverable_device(
                CreateGtpDeviceRequest::new("gtp0"),
                test_device_incarnation(),
            )
            .await
            .unwrap();

        assert_eq!(device.ifindex, 42);
        assert_eq!(retained_socket_count(&backend), 1);
        assert_eq!(
            transport
                .requests()
                .iter()
                .map(|request| request.operation)
                .collect::<Vec<_>>(),
            vec!["create_device", "pdp_device_identity_stamp"]
        );
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_recoverable_device_refuses_preexisting_name_before_effect() {
        let root = unique_recovery_root("create-recoverable-preexisting");
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        assert!(matches!(
            backend
                .create_recoverable_device(
                    CreateGtpDeviceRequest::new("gtp0"),
                    test_device_incarnation(),
                )
                .await
                .unwrap_err(),
            GtpuError::AlreadyExists
        ));
        assert_eq!(retained_socket_count(&backend), 0);
        assert!(transport.requests().is_empty());
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_recoverable_device_rolls_back_unverified_alias() {
        let root = unique_recovery_root("create-recoverable-alias-mismatch");
        let mut transport = CapturingTransport::new();
        transport.device_alias = None;
        transport.push_ifindex_response(IfindexResponse::NotFound);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        assert!(matches!(
            backend
                .create_recoverable_device(
                    CreateGtpDeviceRequest::new("gtp0"),
                    test_device_incarnation(),
                )
                .await
                .unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "recoverable_device_identity_stamp"
            }
        ));
        assert_eq!(retained_socket_count(&backend), 0);
        assert_eq!(
            transport
                .requests()
                .iter()
                .map(|request| request.operation)
                .collect::<Vec<_>>(),
            vec![
                "create_device",
                "pdp_device_identity_stamp",
                "recoverable_device_provision_rollback"
            ]
        );
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_recoverable_device_requires_authority_before_effect() {
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone());

        assert!(matches!(
            backend
                .create_recoverable_device(
                    CreateGtpDeviceRequest::new("gtp0"),
                    test_device_incarnation(),
                )
                .await
                .unwrap_err(),
            GtpuError::UnsupportedFeature {
                feature: "pdp_restart_recovery_authority"
            }
        ));
        assert!(transport.requests().is_empty());
    }

    #[tokio::test]
    async fn linux_backend_resolves_device_by_name_without_create_mutation() {
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone());

        let device = backend.resolve_device("gtp0").await.unwrap();

        assert_eq!(
            device,
            GtpDevice {
                name: "gtp0".to_string(),
                ifindex: 42,
            }
        );
        assert!(transport.requests().is_empty());
        assert_eq!(retained_socket_count(&backend), 0);
    }

    #[tokio::test]
    async fn linux_backend_releases_retained_socket_after_successful_remove() {
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport);
        let device = backend
            .create_device(CreateGtpDeviceRequest::new("gtp0"))
            .await
            .unwrap();
        assert_eq!(retained_socket_count(&backend), 1);

        backend.remove_device(&device).await.unwrap();

        assert_eq!(retained_socket_count(&backend), 0);
    }

    #[tokio::test]
    async fn linux_backend_keeps_retained_socket_when_remove_fails() {
        let transport = CapturingTransport::new();
        transport.push_response(Ok(None));
        transport.push_response(Err(GtpuError::NotFound));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport);
        let device = backend
            .create_device(CreateGtpDeviceRequest::new("gtp0"))
            .await
            .unwrap();

        let error = backend.remove_device(&device).await.unwrap_err();

        assert!(matches!(error, GtpuError::NotFound));
        assert_eq!(retained_socket_count(&backend), 1);
    }

    #[tokio::test]
    async fn linux_backend_install_pdp_resolves_family_then_sends_newpdp() {
        let transport = CapturingTransport::with_response(Ok(Some(
            netlink_body(&family_response(1, 31)).to_vec(),
        )));
        transport.push_response(Ok(None));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone());
        backend.install_pdp_context(pdp_context()).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].protocol, NetlinkProtocol::Generic);
        assert_eq!(requests[0].operation, "gtp_family_lookup");
        assert_eq!(requests[1].protocol, NetlinkProtocol::Generic);
        assert_eq!(requests[1].operation, "install_pdp_context");
        let body = netlink_body(&requests[1].request);
        assert_eq!(body[0], GTP_CMD_NEWPDP);
    }

    #[tokio::test]
    async fn linux_backend_reads_exact_state_by_both_selectors() {
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        push_present(&transport, &context);
        push_present(&transport, &context);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone());

        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(context.clone())
        );

        let requests = transport.requests();
        assert_eq!(requests.len(), 3);
        for request in &requests[1..] {
            assert_eq!(request.operation, "read_pdp_context");
            assert_eq!(read_u16_ne(&request.request, 6).unwrap(), NLM_F_REQUEST);
            assert_eq!(netlink_body(&request.request)[0], GTP_CMD_GETPDP);
        }

        let second_transport = CapturingTransport::new();
        push_family_lookup(&second_transport);
        push_present(&second_transport, &context);
        push_present(&second_transport, &context);
        let second = LinuxGtpuDataplaneBackend::with_transport(second_transport);
        assert_eq!(
            second
                .read_pdp_context(PdpContextSelector::Uplink(
                    PdpContextUplinkSelector::from_context(&context).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Present(context)
        );
    }

    #[tokio::test]
    async fn linux_backend_reconciles_mixed_inner_outer_families() {
        for context in mixed_family_pdp_contexts() {
            for include_family in [false, true] {
                let selectors = [
                    PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(&context).unwrap(),
                    ),
                    PdpContextSelector::Uplink(
                        PdpContextUplinkSelector::from_context(&context).unwrap(),
                    ),
                ];
                for selector in selectors {
                    let transport = CapturingTransport::new();
                    push_family_lookup(&transport);
                    push_present_with_family(&transport, &context, include_family);
                    push_present_with_family(&transport, &context, include_family);
                    let backend = LinuxGtpuDataplaneBackend::with_transport(transport);
                    assert_eq!(
                        backend.read_pdp_context(selector).await.unwrap(),
                        PdpContextReadback::Present(context.clone())
                    );
                }

                let transport = CapturingTransport::new();
                push_family_lookup(&transport);
                for _ in 0..4 {
                    push_present_with_family(&transport, &context, include_family);
                }
                let backend = LinuxGtpuDataplaneBackend::with_transport(transport);
                assert_eq!(
                    backend
                        .install_pdp_context_classified(context.clone())
                        .await
                        .unwrap(),
                    PdpContextInstallOutcome::ExactAlreadyPresent
                );
            }
        }
    }

    #[tokio::test]
    async fn linux_readback_distinguishes_absence_from_missing_or_changing_evidence() {
        let context = pdp_context();

        let absent_transport = CapturingTransport::new();
        push_family_lookup(&absent_transport);
        push_absent(&absent_transport);
        push_absent(&absent_transport);
        let absent_backend = LinuxGtpuDataplaneBackend::with_transport(absent_transport);
        assert_eq!(
            absent_backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context).unwrap(),
                ))
                .await
                .unwrap(),
            PdpContextReadback::Absent
        );

        let no_response_transport = CapturingTransport::new();
        push_family_lookup(&no_response_transport);
        no_response_transport.push_response(Ok(None));
        let no_response = LinuxGtpuDataplaneBackend::with_transport(no_response_transport);
        assert!(matches!(
            no_response
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context).unwrap(),
                ))
                .await
                .unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "linux_pdp_context_readback"
            }
        ));

        let changed_transport = CapturingTransport::new();
        let mut changed = context.clone();
        changed.peer_teid = teid(9);
        push_family_lookup(&changed_transport);
        push_present(&changed_transport, &context);
        push_present(&changed_transport, &changed);
        let changed_backend = LinuxGtpuDataplaneBackend::with_transport(changed_transport);
        assert!(matches!(
            changed_backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context).unwrap(),
                ))
                .await
                .unwrap_err(),
            GtpuError::StateIndeterminate {
                operation: "linux_pdp_context_state_changed"
            }
        ));
    }

    #[tokio::test]
    async fn linux_classified_install_proves_exact_and_both_collision_shapes() {
        let exact_transport = CapturingTransport::new();
        let installed = pdp_context();
        push_family_lookup(&exact_transport);
        for _ in 0..4 {
            push_present(&exact_transport, &installed);
        }
        let exact_backend = LinuxGtpuDataplaneBackend::with_transport(exact_transport.clone());
        assert_eq!(
            exact_backend
                .install_pdp_context_classified(installed.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::ExactAlreadyPresent
        );
        assert!(exact_transport
            .requests()
            .iter()
            .all(|request| request.operation != "install_pdp_context"));

        let uplink_conflict_transport = CapturingTransport::new();
        let mut same_uplink = installed.clone();
        same_uplink.local_teid = teid(9);
        same_uplink.peer_teid = teid(10);
        push_family_lookup(&uplink_conflict_transport);
        push_absent(&uplink_conflict_transport);
        push_present(&uplink_conflict_transport, &installed);
        push_absent(&uplink_conflict_transport);
        push_present(&uplink_conflict_transport, &installed);
        let uplink_backend =
            LinuxGtpuDataplaneBackend::with_transport(uplink_conflict_transport.clone());
        assert!(matches!(
            uplink_backend
                .install_pdp_context_classified(same_uplink)
                .await
                .unwrap(),
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == crate::PdpContextSelectorOccupancy::Uplink
        ));
        assert!(uplink_conflict_transport
            .requests()
            .iter()
            .all(|request| request.operation != "install_pdp_context"));

        let local_conflict_transport = CapturingTransport::new();
        let mut same_local = installed.clone();
        same_local.ms_address = IpAddr::V4(Ipv4Addr::new(10, 23, 0, 3));
        push_family_lookup(&local_conflict_transport);
        push_present(&local_conflict_transport, &installed);
        push_absent(&local_conflict_transport);
        push_present(&local_conflict_transport, &installed);
        push_absent(&local_conflict_transport);
        let local_backend =
            LinuxGtpuDataplaneBackend::with_transport(local_conflict_transport.clone());
        assert!(matches!(
            local_backend
                .install_pdp_context_classified(same_local)
                .await
                .unwrap(),
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == crate::PdpContextSelectorOccupancy::LocalTeid
        ));
        assert!(local_conflict_transport
            .requests()
            .iter()
            .all(|request| request.operation != "install_pdp_context"));
    }

    #[tokio::test]
    async fn linux_classified_install_requires_exact_postread_and_reconciles_eexist() {
        let installed = pdp_context();
        let fresh_transport = CapturingTransport::new();
        push_family_lookup(&fresh_transport);
        for _ in 0..4 {
            push_absent(&fresh_transport);
        }
        fresh_transport.push_response(Ok(None));
        for _ in 0..4 {
            push_present(&fresh_transport, &installed);
        }
        let fresh = LinuxGtpuDataplaneBackend::with_transport(fresh_transport);
        assert_eq!(
            fresh
                .install_pdp_context_classified(installed.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Installed
        );

        let raced_transport = CapturingTransport::new();
        push_family_lookup(&raced_transport);
        for _ in 0..4 {
            push_absent(&raced_transport);
        }
        raced_transport.push_response(Err(GtpuError::AlreadyExists));
        for _ in 0..4 {
            push_present(&raced_transport, &installed);
        }
        let raced = LinuxGtpuDataplaneBackend::with_transport(raced_transport);
        assert_eq!(
            raced
                .install_pdp_context_classified(installed.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::ExactAlreadyPresent
        );

        let post_conflict_transport = CapturingTransport::new();
        push_family_lookup(&post_conflict_transport);
        for _ in 0..4 {
            push_absent(&post_conflict_transport);
        }
        post_conflict_transport.push_response(Ok(None));
        let mut conflicting = installed.clone();
        conflicting.peer_teid = teid(9);
        conflicting.peer_address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        for _ in 0..4 {
            push_present(&post_conflict_transport, &conflicting);
        }
        let post_conflict = LinuxGtpuDataplaneBackend::with_transport(post_conflict_transport);
        assert!(matches!(
            post_conflict
                .install_pdp_context_classified(installed)
                .await
                .unwrap(),
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == crate::PdpContextSelectorOccupancy::Both
        ));
    }

    #[tokio::test]
    async fn linux_classified_install_preserves_definitive_errors_and_reconciles_ack_loss() {
        let desired = pdp_context();
        let denied_transport = CapturingTransport::new();
        push_family_lookup(&denied_transport);
        for _ in 0..4 {
            push_absent(&denied_transport);
        }
        denied_transport.push_response(Err(GtpuError::io(
            "netlink_ack",
            io::Error::new(io::ErrorKind::PermissionDenied, "redacted"),
        )));
        let denied = LinuxGtpuDataplaneBackend::with_transport(denied_transport);
        assert!(matches!(
            denied
                .install_pdp_context_classified(desired.clone())
                .await
                .unwrap_err(),
            GtpuError::Io {
                kind: io::ErrorKind::PermissionDenied,
                ..
            }
        ));

        let timeout_transport = CapturingTransport::new();
        push_family_lookup(&timeout_transport);
        for _ in 0..4 {
            push_absent(&timeout_transport);
        }
        timeout_transport.push_response(Err(GtpuError::io(
            "netlink_ack",
            io::Error::new(io::ErrorKind::TimedOut, "redacted"),
        )));
        for _ in 0..4 {
            push_present(&timeout_transport, &desired);
        }
        let timed_out = LinuxGtpuDataplaneBackend::with_transport(timeout_transport);
        assert_eq!(
            timed_out
                .install_pdp_context_classified(desired)
                .await
                .unwrap(),
            PdpContextInstallOutcome::ExactAlreadyPresent
        );
    }

    #[tokio::test]
    async fn linux_exact_removal_is_unavailable_without_a_bound_recovery_root() {
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone());
        assert!(matches!(
            backend
                .remove_pdp_context_exact(pdp_context())
                .await
                .unwrap_err(),
            GtpuError::UnsupportedFeature {
                feature: "pdp_context_exact_removal"
            }
        ));
        assert!(transport.requests().is_empty());
        assert_eq!(
            backend.pdp_context_reconciliation_capabilities(),
            PdpContextReconciliationCapabilities {
                readback: GtpuCapability::Available,
                classified_install: GtpuCapability::Available,
                exact_removal: GtpuCapability::Missing,
            }
        );
        assert_eq!(
            backend.pdp_restart_recovery_capability(),
            GtpuCapability::Missing
        );

        let mut unavailable_transport = CapturingTransport::new();
        unavailable_transport.probe.mutation_ready = false;
        let unavailable = LinuxGtpuDataplaneBackend::with_transport(unavailable_transport);
        assert_eq!(
            unavailable
                .pdp_context_reconciliation_capabilities()
                .classified_install,
            GtpuCapability::Missing
        );
        assert_eq!(
            unavailable
                .pdp_context_reconciliation_capabilities()
                .exact_removal,
            GtpuCapability::Missing
        );
    }

    static RECOVERY_ROOT_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_recovery_root(tag: &str) -> PathBuf {
        let sequence = RECOVERY_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "opc-gtpu-627-recovery-{}-{sequence}-{tag}",
            std::process::id()
        ))
    }

    fn push_exact_readback(transport: &CapturingTransport, context: &GtpPdpContext) {
        for _ in 0..4 {
            push_present(transport, context);
        }
    }

    fn push_absent_readback(transport: &CapturingTransport) {
        for _ in 0..4 {
            push_absent(transport);
        }
    }

    fn recovery_request(context: GtpPdpContext) -> PdpRestartRecoveryRequest {
        PdpRestartRecoveryRequest::new(
            GtpDevice {
                name: "gtp0".to_string(),
                ifindex: context.link_ifindex,
            },
            test_device_incarnation(),
            context,
            PdpRestartRecoveryProof::previous_writer_stopped(),
        )
    }

    fn assert_no_exact_delete(requests: &[CapturedRequest]) {
        assert!(
            requests
                .iter()
                .all(|request| request.operation != "remove_pdp_context_exact"),
            "no DELPDP mutation may be issued"
        );
    }

    #[tokio::test]
    async fn linux_exact_removal_removes_exact_context_under_recovery_authority() {
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        push_exact_readback(&transport, &context);
        transport.push_response(Ok(None));
        push_absent_readback(&transport);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("removed"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(context.clone()))
            .await
            .unwrap();

        assert_eq!(outcome, PdpContextRemovalOutcome::Removed);
        let deletes: Vec<_> = transport
            .requests()
            .into_iter()
            .filter(|request| request.operation == "remove_pdp_context_exact")
            .collect();
        assert_eq!(deletes.len(), 1);
        assert_eq!(netlink_body(&deletes[0].request)[0], GTP_CMD_DELPDP);
    }

    #[tokio::test]
    async fn linux_exact_removal_absent_returns_already_absent_without_mutation() {
        let transport = CapturingTransport::new();
        push_family_lookup(&transport);
        push_absent_readback(&transport);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("absent"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(pdp_context()))
            .await
            .unwrap();

        assert_eq!(outcome, PdpContextRemovalOutcome::AlreadyAbsent);
        assert_no_exact_delete(&transport.requests());
    }

    #[tokio::test]
    async fn linux_exact_removal_conflict_leaves_resident_state_untouched() {
        let transport = CapturingTransport::new();
        let desired = pdp_context();
        let mut foreign = desired.clone();
        foreign.peer_teid = teid(0x9999_9999);
        push_family_lookup(&transport);
        push_exact_readback(&transport, &foreign);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("conflict"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(desired))
            .await
            .unwrap();

        let conflict = match outcome {
            PdpContextRemovalOutcome::Conflict(conflict) => conflict,
            other => panic!("expected Conflict, got {other:?}"),
        };
        assert_eq!(conflict.occupied(), PdpContextSelectorOccupancy::Both);
        assert!(conflict
            .mismatches()
            .contains(&PdpContextMismatchField::PeerTeid));
        assert_no_exact_delete(&transport.requests());
    }

    #[tokio::test]
    async fn linux_exact_removal_state_changed_is_retryable_not_a_mutation() {
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        // First observation present, second observation differs -> unstable.
        push_present(&transport, &context);
        push_present(&transport, &context);
        push_absent(&transport);
        push_absent(&transport);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("changed"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(context))
            .await
            .unwrap();

        assert_eq!(
            outcome,
            PdpContextRemovalOutcome::Indeterminate(PdpContextIndeterminateReason::StateChanged)
        );
        assert_no_exact_delete(&transport.requests());
    }

    #[tokio::test]
    async fn linux_exact_removal_confirms_from_readback_not_delete_ack() {
        // DELPDP is ACKed, but the post-mutation readback still finds the
        // exact context. The outcome must come from the readback, so this is
        // MutationUnconfirmed, never Removed.
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        push_exact_readback(&transport, &context);
        transport.push_response(Ok(None));
        push_exact_readback(&transport, &context);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("confirm-present"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(context))
            .await
            .unwrap();

        assert_eq!(
            outcome,
            PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::MutationUnconfirmed
            )
        );
        let requests = transport.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.operation == "remove_pdp_context_exact")
                .count(),
            1
        );
        // family + 4 pre-reads + 1 delete + 4 confirmation reads.
        assert_eq!(requests.len(), 10);
    }

    #[tokio::test]
    async fn linux_exact_removal_ack_loss_with_absent_confirmation_is_removed() {
        // A non-definitive DELPDP failure can be ACK loss after a committed
        // delete. The authoritative absent confirmation readback proves the
        // removal, so the outcome is Removed rather than the raw error.
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        push_exact_readback(&transport, &context);
        transport.push_response(Err(GtpuError::io(
            "netlink_ack",
            io::Error::new(io::ErrorKind::TimedOut, "redacted"),
        )));
        push_absent_readback(&transport);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("ack-loss-absent"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(context))
            .await
            .unwrap();

        assert_eq!(outcome, PdpContextRemovalOutcome::Removed);
        assert_eq!(
            transport
                .requests()
                .iter()
                .filter(|request| request.operation == "remove_pdp_context_exact")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn linux_exact_removal_ack_loss_with_present_confirmation_is_unconfirmed() {
        // ACK loss followed by a confirmation readback that still finds the
        // exact context cannot prove either way; it stays retryable.
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        push_exact_readback(&transport, &context);
        transport.push_response(Err(GtpuError::io(
            "netlink_ack",
            io::Error::new(io::ErrorKind::TimedOut, "redacted"),
        )));
        push_exact_readback(&transport, &context);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("ack-loss-present"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(context))
            .await
            .unwrap();

        assert_eq!(
            outcome,
            PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::MutationUnconfirmed
            )
        );
    }

    #[tokio::test]
    async fn linux_exact_removal_definitive_delete_error_propagates() {
        // A definitive DELPDP failure proves no mutation and is propagated as
        // an error rather than classified as Removed; no confirmation readback
        // follows.
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        push_exact_readback(&transport, &context);
        transport.push_response(Err(GtpuError::io(
            "netlink_ack",
            io::Error::new(io::ErrorKind::PermissionDenied, "redacted"),
        )));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("definitive-error"))
            .unwrap();

        let error = backend
            .recover_pdp_context_exact(recovery_request(context))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            GtpuError::Io {
                kind: io::ErrorKind::PermissionDenied,
                ..
            }
        ));
        let requests = transport.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.operation == "remove_pdp_context_exact")
                .count(),
            1
        );
        // family + 4 pre-reads + 1 delete; no confirmation reads after a
        // definitive no-mutation error.
        assert_eq!(requests.len(), 6);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn linux_exact_removal_completes_without_overlap_when_future_is_dropped() {
        // Acceptance: cancellation at an admitted-mutation boundary leaves
        // durable retry authority and no overlapping delete. The latched DELPDP
        // response holds the worker exactly at the admitted-mutation point so
        // the caller's future can be dropped there; the spawn_blocking worker
        // must still run the transaction to completion, issuing exactly one
        // DELPDP and performing the confirmation readback.
        let transport = CapturingTransport::new();
        let context = pdp_context();
        let latch = Arc::new(ResponseLatch::new());
        let mut latch_guard = ResponseLatchReleaseGuard::new(latch.clone());
        let root = unique_recovery_root("drop-at-admission");
        push_family_lookup(&transport);
        push_exact_readback(&transport, &context);
        transport.push_latched_response(latch.clone(), Ok(None));
        push_absent_readback(&transport);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        // Move the owned backend into the task so the future is 'static.
        let worker_context = context.clone();
        let handle = tokio::spawn(async move {
            backend
                .recover_pdp_context_exact(recovery_request(worker_context))
                .await
        });

        // Wait until the worker admits the delete and blocks on the latch.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let admitted = transport
                .requests()
                .iter()
                .any(|request| request.operation == "remove_pdp_context_exact");
            if admitted {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the delete was never admitted"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // Cancel the caller's future at the admitted-mutation boundary, and
        // record in-test that the outer task really was cancelled. It cannot
        // have completed normally: the worker is still blocked on the
        // unreleased latch, so the JoinHandle it is awaited on cannot resolve.
        handle.abort();
        let join_error = handle
            .await
            .expect_err("the aborted recovery future must not complete");
        assert!(join_error.is_cancelled());

        // An independent backend using the same authority root cannot overlap
        // either through restart recovery or through an ordinary supported
        // mutation while the detached worker is latched after DELPDP.
        let retry_backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();
        assert_eq!(
            retry_backend
                .recover_pdp_context_exact(recovery_request(context.clone()))
                .await
                .unwrap(),
            PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable
            )
        );
        assert!(matches!(
            retry_backend
                .install_pdp_context(context.clone())
                .await
                .unwrap_err(),
            GtpuError::RetryRequired {
                operation: "pdp_writer_authority"
            }
        ));
        assert_eq!(
            transport
                .requests()
                .iter()
                .filter(|request| request.operation == "remove_pdp_context_exact")
                .count(),
            1
        );

        // Release the original worker and let its post-mutation observation
        // converge. The guard also releases on any earlier assertion panic.
        latch_guard.release_now();

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if transport.requests().len() >= 10 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the worker did not complete the transaction after drop"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // Seeing the last request in the capture log precedes function return
        // by a few instructions. Prove that the detached worker has actually
        // released topology authority before testing the durable retry.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match acquire_pdp_topology_lease(&root) {
                Ok(lease) => {
                    drop(lease);
                    break;
                }
                Err(GtpuError::AlreadyExists) => {}
                Err(error) => panic!("unexpected authority probe failure: {error}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the detached worker did not release recovery authority"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        push_family_lookup(&transport);
        push_absent_readback(&transport);
        assert_eq!(
            retry_backend
                .recover_pdp_context_exact(recovery_request(context))
                .await
                .unwrap(),
            PdpContextRemovalOutcome::AlreadyAbsent
        );

        let requests = transport.requests();
        // Exactly one admitted delete: no overlapping or duplicated DELPDP.
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.operation == "remove_pdp_context_exact")
                .count(),
            1
        );
        // Both the original pre/post readbacks and the successful idempotent
        // retry readback ran.
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.operation == "read_pdp_context")
                .count(),
            12
        );
    }

    #[tokio::test]
    async fn linux_exact_removal_ipv6_context_removes_under_recovery_authority() {
        let transport = CapturingTransport::new();
        let mut context = pdp_context();
        // Linux stores an IPv6 MS/PAA as the canonical /64 prefix.
        context.ms_address = "2001:db8:23:1::".parse().unwrap();
        push_family_lookup(&transport);
        push_exact_readback(&transport, &context);
        transport.push_response(Ok(None));
        push_absent_readback(&transport);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("ipv6"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(context))
            .await
            .unwrap();

        assert_eq!(outcome, PdpContextRemovalOutcome::Removed);
        let deletes: Vec<_> = transport
            .requests()
            .into_iter()
            .filter(|request| request.operation == "remove_pdp_context_exact")
            .collect();
        assert_eq!(deletes.len(), 1);
        // Axis purity holds for the IPv6 family too: the delete selects the
        // I_TEI axis with an AF_INET6 lookup family and carries no MS address.
        let attrs = &netlink_body(&deletes[0].request)[GENERIC_NETLINK_HEADER_LEN..];
        assert_eq!(attr_u8(attrs, GTPA_FAMILY), AF_INET6);
        assert!(attr_payload(attrs, GTPA_MS_ADDRESS).is_none());
        assert!(attr_payload(attrs, GTPA_MS_ADDR6).is_none());
    }

    #[tokio::test]
    async fn linux_recovery_maps_missing_gtp_family_to_unsupported_platform() {
        // The trait-level request can never carry the required durable device
        // incarnation, regardless of recovery-root or kernel availability.
        let transport = CapturingTransport::with_response(Err(GtpuError::NotFound));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport)
            .with_pdp_recovery_root(unique_recovery_root("unsupported-trait"))
            .unwrap();
        assert!(matches!(
            backend
                .remove_pdp_context_exact(pdp_context())
                .await
                .unwrap_err(),
            GtpuError::UnsupportedFeature {
                feature: "pdp_context_exact_removal"
            }
        ));

        // The restart primitive proves the device identity first, then maps a
        // missing GTP generic-netlink family the same way.
        let transport = CapturingTransport::with_response(Err(GtpuError::NotFound));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport)
            .with_pdp_recovery_root(unique_recovery_root("unsupported-recover"))
            .unwrap();
        assert!(matches!(
            backend
                .recover_pdp_context_exact(recovery_request(pdp_context()))
                .await
                .unwrap_err(),
            GtpuError::UnsupportedPlatform
        ));
    }

    #[tokio::test]
    async fn linux_exact_removal_malformed_readback_is_structural_error_not_indeterminate() {
        // A truncated/malformed GETPDP payload is a structural decode failure
        // (InvalidData), never a retryable Indeterminate outcome, and never a
        // mutation.
        let transport = CapturingTransport::new();
        push_family_lookup(&transport);
        transport.push_response(Ok(Some(vec![0u8; 2])));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("malformed"))
            .unwrap();

        let error = backend
            .recover_pdp_context_exact(recovery_request(pdp_context()))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            GtpuError::Io {
                kind: io::ErrorKind::InvalidData,
                ..
            }
        ));
        assert_no_exact_delete(&transport.requests());
    }

    #[tokio::test]
    async fn linux_exact_removal_rejects_unmodeled_readback_before_mutation() {
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        let mut response = pdp_response(&context, false);
        append_attr_u32_ne(&mut response, 0x3ffe, 7).unwrap();
        transport.push_response(Ok(Some(response)));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("unmodeled-readback"))
            .unwrap();

        let error = backend
            .recover_pdp_context_exact(recovery_request(context))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            GtpuError::Io {
                kind: io::ErrorKind::InvalidData,
                ..
            }
        ));
        assert_no_exact_delete(&transport.requests());
    }

    #[tokio::test]
    async fn linux_exact_removal_single_axis_occupied_is_incomplete_state() {
        // One selector axis occupied by the exact context with the other
        // authoritatively absent is unrepresentable/incomplete state: it is
        // retryable indeterminate, never a delete.
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        push_present(&transport, &context);
        push_absent(&transport);
        push_present(&transport, &context);
        push_absent(&transport);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("single-axis"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(context))
            .await
            .unwrap();

        assert_eq!(
            outcome,
            PdpContextRemovalOutcome::Indeterminate(PdpContextIndeterminateReason::IncompleteState)
        );
        assert_no_exact_delete(&transport.requests());
    }

    #[tokio::test]
    async fn linux_restart_recovery_removes_exact_context_after_device_proof() {
        let transport = CapturingTransport::new();
        let context = pdp_context();
        push_family_lookup(&transport);
        push_exact_readback(&transport, &context);
        transport.push_response(Ok(None));
        push_absent_readback(&transport);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("recover-removed"))
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(context))
            .await
            .unwrap();

        assert_eq!(outcome, PdpContextRemovalOutcome::Removed);
    }

    #[tokio::test]
    async fn linux_restart_recovery_refuses_replaced_device_identity() {
        let mut transport = CapturingTransport::new();
        // The recorded name now resolves to a different ifindex: the device
        // was replaced, so the durable descriptor is stale.
        transport.ifindex = 99;
        let request = recovery_request(pdp_context());
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("recover-replaced"))
            .unwrap();

        let outcome = backend.recover_pdp_context_exact(request).await.unwrap();

        assert_eq!(
            outcome,
            PdpContextRemovalOutcome::RepairRequired(PdpContextRepairReason::DeviceIdentityChanged)
        );
        assert!(transport.requests().is_empty());
    }

    #[tokio::test]
    async fn linux_restart_recovery_refuses_same_name_and_ifindex_with_new_incarnation() {
        let mut transport = CapturingTransport::new();
        // Linux permits explicit ifindex reuse. The name and ifindex therefore
        // still match, but the replacement's kernel-bound incarnation does
        // not, so no PDP read or mutation is authorized.
        let replacement = PdpDeviceIncarnation::from_bytes([0x5a; 16]).unwrap();
        transport.device_alias = Some(encode_pdp_device_alias(replacement).into_bytes());
        let request = recovery_request(pdp_context());
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("recover-incarnation-replaced"))
            .unwrap();

        let outcome = backend.recover_pdp_context_exact(request).await.unwrap();

        assert_eq!(
            outcome,
            PdpContextRemovalOutcome::RepairRequired(PdpContextRepairReason::DeviceIdentityChanged)
        );
        assert!(transport.requests().is_empty());
    }

    #[tokio::test]
    async fn linux_restart_recovery_rejects_mismatched_device_and_context_link() {
        let transport = CapturingTransport::new();
        let context = pdp_context();
        let request = PdpRestartRecoveryRequest::new(
            GtpDevice {
                name: "gtp0".to_string(),
                ifindex: context.link_ifindex + 1,
            },
            test_device_incarnation(),
            context,
            PdpRestartRecoveryProof::previous_writer_stopped(),
        );
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(unique_recovery_root("recover-mismatch"))
            .unwrap();

        let error = backend
            .recover_pdp_context_exact(request)
            .await
            .unwrap_err();

        assert!(matches!(error, GtpuError::InvalidConfig { .. }));
        assert!(transport.requests().is_empty());
    }

    #[tokio::test]
    async fn linux_trait_capability_does_not_advertise_generationless_exact_removal() {
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport)
            .with_pdp_recovery_root(unique_recovery_root("caps"))
            .unwrap();
        assert_eq!(
            backend
                .pdp_context_reconciliation_capabilities()
                .exact_removal,
            GtpuCapability::Missing
        );
        assert_eq!(
            backend.pdp_restart_recovery_capability(),
            GtpuCapability::Available
        );
    }

    #[tokio::test]
    async fn linux_recovery_request_and_outcomes_are_redaction_safe() {
        let request = recovery_request(pdp_context());
        let rendered = format!("{request:?}");
        for secret in ["11223344", "55667788", "10.23.0.2", "192.0.2.10", "gtp0"] {
            assert!(
                !rendered.contains(secret),
                "request debug leaked {secret}: {rendered}"
            );
        }
        let outcome =
            PdpContextRemovalOutcome::RepairRequired(PdpContextRepairReason::DeviceIdentityChanged);
        let rendered = format!("{outcome:?}");
        assert!(!rendered.contains("10.23.0.2"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_exact_removal_reports_authority_unavailable_while_lease_held() {
        let root = unique_recovery_root("busy");
        std::fs::create_dir_all(&root).unwrap();
        let lock_path = root.join(format!("pdp-recovery-{}.lock", pdp_context().link_ifindex));
        let held = std::fs::File::create(&lock_path).unwrap();
        rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();

        let transport = CapturingTransport::new();
        push_family_lookup(&transport);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root)
            .unwrap();

        let outcome = backend
            .recover_pdp_context_exact(recovery_request(pdp_context()))
            .await
            .unwrap();

        assert_eq!(
            outcome,
            PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable
            )
        );
        assert_no_exact_delete(&transport.requests());
        drop(held);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_bound_mutation_paths_share_one_writer_authority() {
        let root = unique_recovery_root("writer-domain");
        let context = pdp_context();
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let device_lease = acquire_pdp_recovery_lease(&root, context.link_ifindex).unwrap();
        assert!(matches!(
            backend
                .install_pdp_context(context.clone())
                .await
                .unwrap_err(),
            GtpuError::RetryRequired {
                operation: "pdp_writer_authority"
            }
        ));
        assert!(matches!(
            backend
                .remove_pdp_context(RemovePdpContextRequest::from_context(&context))
                .await
                .unwrap_err(),
            GtpuError::RetryRequired {
                operation: "pdp_writer_authority"
            }
        ));
        assert_eq!(
            backend
                .install_pdp_context_classified(context.clone())
                .await
                .unwrap(),
            PdpContextInstallOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable
            )
        );
        assert!(matches!(
            backend
                .remove_device(&GtpDevice {
                    name: "gtp0".to_string(),
                    ifindex: context.link_ifindex,
                })
                .await
                .unwrap_err(),
            GtpuError::RetryRequired {
                operation: "pdp_writer_authority"
            }
        ));
        assert_eq!(
            backend
                .acquire_retained_device_identity(retained_device_request())
                .await
                .unwrap(),
            RetainedDeviceIdentityOutcome::Indeterminate(
                RetainedDeviceIndeterminateReason::AuthorityUnavailable
            )
        );
        assert!(transport.requests().is_empty());
        drop(device_lease);

        let topology_lease = acquire_pdp_topology_lease(&root).unwrap();
        assert!(matches!(
            backend
                .create_device(CreateGtpDeviceRequest::new("gtp-new"))
                .await
                .unwrap_err(),
            GtpuError::RetryRequired {
                operation: "pdp_writer_authority"
            }
        ));
        assert_eq!(
            backend
                .recover_pdp_context_exact(recovery_request(context))
                .await
                .unwrap(),
            PdpContextRemovalOutcome::Indeterminate(
                PdpContextIndeterminateReason::AuthorityUnavailable
            )
        );
        assert_eq!(
            backend
                .acquire_retained_device_identity(retained_device_request())
                .await
                .unwrap(),
            RetainedDeviceIdentityOutcome::Indeterminate(
                RetainedDeviceIndeterminateReason::AuthorityUnavailable
            )
        );
        assert!(transport.requests().is_empty());
        drop(topology_lease);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    fn retained_device_request() -> RetainedDeviceIdentityRequest {
        RetainedDeviceIdentityRequest::new(
            GtpDevice {
                name: "gtp0".to_string(),
                ifindex: 42,
            },
            test_device_incarnation(),
            PdpRestartRecoveryProof::previous_writer_stopped(),
        )
    }

    fn assert_no_netlink_traffic(transport: &CapturingTransport) {
        // The acquisition is mutation-free and, in the mock, proof-only: no
        // transact call (create/stamp/delete/read of any device or PDP state)
        // may have been issued. The panic message names only static operation
        // labels, never request bytes.
        let operations: Vec<&'static str> = transport
            .requests()
            .iter()
            .map(|request| request.operation)
            .collect();
        assert!(
            operations.is_empty(),
            "acquisition issued unexpected netlink transactions: {operations:?}"
        );
    }

    #[tokio::test]
    async fn linux_retained_device_identity_returns_retained_without_mutation() {
        let root = unique_recovery_root("acquire-retained");
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let outcome = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap();

        assert_eq!(outcome, RetainedDeviceIdentityOutcome::Retained);
        assert_eq!(transport.ifindex_admissions(), 1);
        assert_eq!(transport.link_identity_admissions(), 1);
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_removed_or_renamed_name_is_absent_without_mutation() {
        // A removed device and a renamed device both present as authoritative
        // absence of the recorded name. Under the held topology authority no
        // cooperating writer can create the name concurrently, so absence
        // authorizes exactly one fresh create_recoverable_device call.
        let root = unique_recovery_root("acquire-absent");
        let transport = CapturingTransport::new();
        transport.push_ifindex_response(IfindexResponse::NotFound);
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let outcome = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap();

        assert_eq!(outcome, RetainedDeviceIdentityOutcome::Absent);
        // Absence is proven by the name lookup alone: no link probe follows.
        assert_eq!(transport.ifindex_admissions(), 1);
        assert_eq!(transport.link_identity_admissions(), 0);
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_same_name_different_ifindex_fails_closed() {
        let root = unique_recovery_root("acquire-replaced-ifindex");
        let mut transport = CapturingTransport::new();
        // The recorded name is occupied by a different link.
        transport.ifindex = 99;
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let outcome = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap();

        assert_eq!(
            outcome,
            RetainedDeviceIdentityOutcome::Conflict(
                RetainedDeviceConflictReason::ReplacementIdentity
            )
        );
        assert_eq!(transport.link_identity_admissions(), 0);
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_same_name_and_ifindex_new_incarnation_fails_closed() {
        // Linux permits explicit ifindex reuse. The name and ifindex still
        // match, but the replacement's kernel-bound incarnation does not, so
        // the identity must not be reused and nothing may be mutated.
        let root = unique_recovery_root("acquire-replaced-incarnation");
        let mut transport = CapturingTransport::new();
        let replacement = PdpDeviceIncarnation::from_bytes([0x5a; 16]).unwrap();
        transport.link_identity = Some(LinkIdentityProbe {
            name: b"gtp0".to_vec(),
            alias: Some(encode_pdp_device_alias(replacement).into_bytes()),
        });
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let outcome = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap();

        assert_eq!(
            outcome,
            RetainedDeviceIdentityOutcome::Conflict(
                RetainedDeviceConflictReason::ReplacementIdentity
            )
        );
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_unstamped_link_is_structural_repair() {
        // A link matching the expected name and ifindex without an
        // incarnation stamp was never published as recoverable; ownership
        // cannot be proven and retrying cannot succeed without repair.
        let root = unique_recovery_root("acquire-unstamped");
        let mut transport = CapturingTransport::new();
        transport.link_identity = Some(LinkIdentityProbe {
            name: b"gtp0".to_vec(),
            alias: None,
        });
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let outcome = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap();

        assert_eq!(
            outcome,
            RetainedDeviceIdentityOutcome::RepairRequired(RetainedDeviceRepairReason::Unstamped)
        );
        assert_ne!(
            outcome,
            RetainedDeviceIdentityOutcome::Indeterminate(
                RetainedDeviceIndeterminateReason::AuthorityUnavailable
            )
        );
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_malformed_alias_fails_closed_as_replacement() {
        // A foreign or malformed alias is not the kernel-bound incarnation;
        // it is a conflicting identity, never retryable authority
        // unavailability, and it is left untouched.
        let root = unique_recovery_root("acquire-malformed-alias");
        let mut transport = CapturingTransport::new();
        transport.link_identity = Some(LinkIdentityProbe {
            name: b"gtp0".to_vec(),
            alias: Some(b"operator-assigned alias".to_vec()),
        });
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let outcome = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap();

        assert_eq!(
            outcome,
            RetainedDeviceIdentityOutcome::Conflict(
                RetainedDeviceConflictReason::ReplacementIdentity
            )
        );
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_unrepresentable_link_evidence_fails_closed() {
        // The name just resolved to the expected ifindex, yet the link probe
        // reports no link: unrepresentable state fails closed as an error,
        // never as absence, retention, or retryable authority unavailability.
        let root = unique_recovery_root("acquire-unrepresentable");
        let transport = CapturingTransport::new();
        transport.push_link_identity_response(Ok(None));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let error = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            GtpuError::StateIndeterminate {
                operation: "retained_device_identity"
            }
        ));
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_contested_name_readback_fails_closed() {
        // The authoritative link readback disagrees with the name that just
        // resolved to the expected ifindex. No cooperating writer can rename
        // a link while both authorities are held, so the contested state is a
        // structural error rather than a classification.
        let root = unique_recovery_root("acquire-contested-name");
        let transport = CapturingTransport::new();
        transport.push_link_identity_response(Ok(Some(LinkIdentityProbe {
            name: b"gtp-renamed".to_vec(),
            alias: Some(encode_pdp_device_alias(test_device_incarnation()).into_bytes()),
        })));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let error = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            GtpuError::StateIndeterminate {
                operation: "retained_device_identity"
            }
        ));
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_malformed_link_response_is_structural_error() {
        // A malformed RTM_GETLINK reply is a structural decode failure
        // (InvalidData), never a retryable Indeterminate outcome.
        let root = unique_recovery_root("acquire-malformed-link");
        let transport = CapturingTransport::new();
        transport.push_link_identity_response(Err(GtpuError::io(
            "retained_device_identity_read",
            io::Error::new(io::ErrorKind::InvalidData, "redacted"),
        )));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let error = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            GtpuError::Io {
                kind: io::ErrorKind::InvalidData,
                ..
            }
        ));
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_requires_bound_recovery_root() {
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone());

        let error = backend
            .acquire_retained_device_identity(retained_device_request())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            GtpuError::UnsupportedFeature {
                feature: "pdp_restart_recovery_authority"
            }
        ));
        assert_eq!(transport.link_identity_admissions(), 0);
        assert_no_netlink_traffic(&transport);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_validates_device_identity_before_authority() {
        let root = unique_recovery_root("acquire-validate");
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let mut device = GtpDevice {
            name: "gtp0".to_string(),
            ifindex: 0,
        };
        let error = backend
            .acquire_retained_device_identity(RetainedDeviceIdentityRequest::new(
                device.clone(),
                test_device_incarnation(),
                PdpRestartRecoveryProof::previous_writer_stopped(),
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, GtpuError::InvalidConfig { .. }));

        device.name = String::new();
        device.ifindex = 42;
        let error = backend
            .acquire_retained_device_identity(RetainedDeviceIdentityRequest::new(
                device,
                test_device_incarnation(),
                PdpRestartRecoveryProof::previous_writer_stopped(),
            ))
            .await
            .unwrap_err();
        assert!(matches!(error, GtpuError::InvalidConfig { .. }));

        assert_eq!(transport.link_identity_admissions(), 0);
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_retained_device_identity_reports_authority_unavailable_while_lease_held() {
        let root = unique_recovery_root("acquire-busy");
        std::fs::create_dir_all(&root).unwrap();

        // Topology authority held by a concurrent writer.
        let topology_lease = acquire_pdp_topology_lease(&root).unwrap();
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();
        assert_eq!(
            backend
                .acquire_retained_device_identity(retained_device_request())
                .await
                .unwrap(),
            RetainedDeviceIdentityOutcome::Indeterminate(
                RetainedDeviceIndeterminateReason::AuthorityUnavailable
            )
        );
        assert_eq!(transport.link_identity_admissions(), 0);
        assert_no_netlink_traffic(&transport);
        drop(topology_lease);

        // Per-device authority held by a concurrent writer.
        let device_lease = acquire_pdp_recovery_lease(&root, 42).unwrap();
        assert_eq!(
            backend
                .acquire_retained_device_identity(retained_device_request())
                .await
                .unwrap(),
            RetainedDeviceIdentityOutcome::Indeterminate(
                RetainedDeviceIndeterminateReason::AuthorityUnavailable
            )
        );
        assert_eq!(transport.link_identity_admissions(), 0);
        assert_no_netlink_traffic(&transport);
        drop(device_lease);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_retry_is_idempotent() {
        // The acquisition never mutates, so an identical retry reclassifies
        // the same live state on both the retained and the absent paths.
        let root = unique_recovery_root("acquire-idempotent");
        let transport = CapturingTransport::new();
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        for _ in 0..2 {
            assert_eq!(
                backend
                    .acquire_retained_device_identity(retained_device_request())
                    .await
                    .unwrap(),
                RetainedDeviceIdentityOutcome::Retained
            );
        }
        transport.push_ifindex_response(IfindexResponse::NotFound);
        transport.push_ifindex_response(IfindexResponse::NotFound);
        for _ in 0..2 {
            assert_eq!(
                backend
                    .acquire_retained_device_identity(retained_device_request())
                    .await
                    .unwrap(),
                RetainedDeviceIdentityOutcome::Absent
            );
        }
        assert_eq!(transport.link_identity_admissions(), 2);
        assert_no_netlink_traffic(&transport);
        drop(backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn linux_retained_device_identity_request_and_outcomes_are_redaction_safe() {
        let request = retained_device_request();
        let rendered = format!("{request:?}");
        for secret in ["gtp0", "42", "a5a5", "[165, 165"] {
            assert!(
                !rendered.contains(secret),
                "request debug leaked {secret}: {rendered}"
            );
        }
        for outcome in [
            RetainedDeviceIdentityOutcome::Retained,
            RetainedDeviceIdentityOutcome::Absent,
            RetainedDeviceIdentityOutcome::Conflict(
                RetainedDeviceConflictReason::ReplacementIdentity,
            ),
            RetainedDeviceIdentityOutcome::Indeterminate(
                RetainedDeviceIndeterminateReason::AuthorityUnavailable,
            ),
            RetainedDeviceIdentityOutcome::RepairRequired(RetainedDeviceRepairReason::Unstamped),
        ] {
            let rendered = format!("{outcome:?}");
            for secret in ["gtp0", "a5a5", "[165, 165"] {
                assert!(
                    !rendered.contains(secret),
                    "outcome debug leaked {secret}: {rendered}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn linux_retained_device_identity_completes_without_overlap_when_future_is_dropped() {
        // Acceptance: cancellation at the admitted identity-read boundary
        // retains completion authority and prevents an overlapping
        // acquisition. The latched link-identity response holds the worker
        // exactly at that boundary so the caller's future can be dropped
        // there; the spawn_blocking worker must still run the classification
        // to completion under both held leases.
        let transport = CapturingTransport::new();
        let latch = Arc::new(ResponseLatch::new());
        let mut latch_guard = ResponseLatchReleaseGuard::new(latch.clone());
        let root = unique_recovery_root("acquire-drop-at-admission");
        transport
            .push_latched_link_identity_response(latch.clone(), Ok(Some(test_link_identity())));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        // Move the owned backend into the task so the future is 'static.
        let handle = tokio::spawn(async move {
            backend
                .acquire_retained_device_identity(retained_device_request())
                .await
        });

        // Wait until the worker admits the identity read and blocks on the
        // latch while holding both writer authorities.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if transport.link_identity_admissions() >= 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the identity read was never admitted"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // Cancel the caller's future at the admitted boundary. It cannot have
        // completed normally: the worker is still blocked on the unreleased
        // latch, so the JoinHandle it is awaited on cannot resolve.
        handle.abort();
        let join_error = handle
            .await
            .expect_err("the aborted acquisition future must not complete");
        assert!(join_error.is_cancelled());

        // An independent backend using the same authority root cannot overlap
        // the detached acquisition, and no other supported writer can admit a
        // mutation on the same device while it is latched.
        let retry_backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();
        assert_eq!(
            retry_backend
                .acquire_retained_device_identity(retained_device_request())
                .await
                .unwrap(),
            RetainedDeviceIdentityOutcome::Indeterminate(
                RetainedDeviceIndeterminateReason::AuthorityUnavailable
            )
        );
        assert!(matches!(
            retry_backend
                .install_pdp_context(pdp_context())
                .await
                .unwrap_err(),
            GtpuError::RetryRequired {
                operation: "pdp_writer_authority"
            }
        ));
        assert!(matches!(
            retry_backend
                .create_recoverable_device(
                    CreateGtpDeviceRequest::new("gtp-new"),
                    test_device_incarnation(),
                )
                .await
                .unwrap_err(),
            GtpuError::RetryRequired {
                operation: "pdp_writer_authority"
            }
        ));
        // Exactly one identity read was ever admitted.
        assert_eq!(transport.link_identity_admissions(), 1);

        // Release the original worker. The guard also releases on any earlier
        // assertion panic.
        latch_guard.release_now();

        // Prove the detached worker has actually released topology authority
        // before testing the durable retry.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match acquire_pdp_topology_lease(&root) {
                Ok(lease) => {
                    drop(lease);
                    break;
                }
                Err(GtpuError::AlreadyExists) => {}
                Err(error) => panic!("unexpected authority probe failure: {error}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the detached worker did not release recovery authority"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // The idempotent retry reclassifies the unchanged state and returns
        // the same retained identity.
        assert_eq!(
            retry_backend
                .acquire_retained_device_identity(retained_device_request())
                .await
                .unwrap(),
            RetainedDeviceIdentityOutcome::Retained
        );
        assert_eq!(transport.link_identity_admissions(), 2);
        assert_no_netlink_traffic(&transport);
        drop(retry_backend);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn linux_retained_device_identity_cancellation_at_name_lookup_boundary() {
        // The second admitted boundary: the latched name lookup holds the
        // worker before the link-identity probe, with both writer authorities
        // already held. Dropping the future there must still retain
        // completion authority and prevent an overlapping acquisition.
        let transport = CapturingTransport::new();
        let latch = Arc::new(ResponseLatch::new());
        let mut latch_guard = ResponseLatchReleaseGuard::new(latch.clone());
        let root = unique_recovery_root("acquire-drop-at-name-lookup");
        transport.push_latched_ifindex_response(latch.clone(), IfindexResponse::Found(42));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();

        let handle = tokio::spawn(async move {
            backend
                .acquire_retained_device_identity(retained_device_request())
                .await
        });

        // Wait until the worker admits the name lookup and blocks on the
        // latch while holding both writer authorities.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if transport.ifindex_admissions() >= 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the name lookup was never admitted"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        handle.abort();
        let join_error = handle
            .await
            .expect_err("the aborted acquisition future must not complete");
        assert!(join_error.is_cancelled());

        // The detached worker still fences every overlapping acquisition.
        let retry_backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
            .with_pdp_recovery_root(root.clone())
            .unwrap();
        assert_eq!(
            retry_backend
                .acquire_retained_device_identity(retained_device_request())
                .await
                .unwrap(),
            RetainedDeviceIdentityOutcome::Indeterminate(
                RetainedDeviceIndeterminateReason::AuthorityUnavailable
            )
        );
        // The original worker never reached the link probe.
        assert_eq!(transport.link_identity_admissions(), 0);

        // Release the original worker. The guard also releases on any
        // earlier assertion panic.
        latch_guard.release_now();

        // Prove the detached worker has actually released topology authority
        // before testing the durable retry.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match acquire_pdp_topology_lease(&root) {
                Ok(lease) => {
                    drop(lease);
                    break;
                }
                Err(GtpuError::AlreadyExists) => {}
                Err(error) => panic!("unexpected authority probe failure: {error}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the detached worker did not release recovery authority"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // The detached worker completed the classification and the retry
        // idempotently re-reads the unchanged state.
        assert_eq!(transport.ifindex_admissions(), 1);
        assert_eq!(transport.link_identity_admissions(), 1);
        assert_eq!(
            retry_backend
                .acquire_retained_device_identity(retained_device_request())
                .await
                .unwrap(),
            RetainedDeviceIdentityOutcome::Retained
        );
        assert_no_netlink_traffic(&transport);
        drop(retry_backend);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Child entry for the cross-process lease test: hold an exclusive flock
    /// on the lease path, signal readiness, then keep the lease until killed.
    #[cfg(target_os = "linux")]
    fn cross_process_lease_child_main() -> ! {
        let lock_path = std::env::var("OPC_GTPU_627_LEASE_PATH").expect("lease path env");
        let ready_path = std::env::var("OPC_GTPU_627_LEASE_READY").expect("ready path env");
        let file = rustix::fs::open(
            std::path::Path::new(&lock_path),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map(std::fs::File::from)
        .expect("child opens lease file");
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .expect("child takes exclusive lease");
        std::fs::write(&ready_path, b"ready").expect("child signals readiness");
        // Keep the lease held until the parent kills us.
        std::thread::sleep(Duration::from_secs(60));
        std::process::exit(0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_exact_removal_cross_process_lease_excludes() {
        // Re-exec'd child role: hold the lease instead of running the parent
        // logic. This must be checked before any other work.
        if std::env::var_os("OPC_GTPU_627_LEASE_CHILD").is_some() {
            cross_process_lease_child_main();
        }

        let root = unique_recovery_root("xproc");
        std::fs::create_dir_all(&root).unwrap();
        let ifindex = pdp_context().link_ifindex;
        let lock_path = root.join(format!("pdp-recovery-{ifindex}.lock"));
        let ready_path = root.join("child-ready");

        let exe = std::env::current_exe().expect("current test binary");
        let child = std::process::Command::new(exe)
            // Substring filter (no `--exact`): libtest's exact match would
            // require the full `linux::tests::` module path.
            .arg("linux_exact_removal_cross_process_lease_excludes")
            .env("OPC_GTPU_627_LEASE_CHILD", "1")
            .env("OPC_GTPU_627_LEASE_PATH", &lock_path)
            .env("OPC_GTPU_627_LEASE_READY", &ready_path)
            .spawn()
            .expect("spawn lease-holding child");
        let child = ChildProcessGuard::new(child);

        // Parent role: while the child holds the lease from another process,
        // exact recovery must be refused as retryable authority-unavailable.
        async {
            // Wait for the child to take the lease in a separate process.
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            while !ready_path.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "child never acquired the lease"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            let transport = CapturingTransport::new();
            push_family_lookup(&transport);
            let backend = LinuxGtpuDataplaneBackend::with_transport(transport.clone())
                .with_pdp_recovery_root(root.clone())
                .unwrap();
            let outcome = backend
                .recover_pdp_context_exact(recovery_request(pdp_context()))
                .await
                .unwrap();
            assert_eq!(
                outcome,
                PdpContextRemovalOutcome::Indeterminate(
                    PdpContextIndeterminateReason::AuthorityUnavailable
                )
            );
            assert_no_exact_delete(&transport.requests());
        }
        .await;

        drop(child);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn linux_backend_maps_missing_family_to_unsupported_platform() {
        let transport = CapturingTransport::with_response(Err(GtpuError::NotFound));
        let backend = LinuxGtpuDataplaneBackend::with_transport(transport);
        let err = backend
            .install_pdp_context(pdp_context())
            .await
            .unwrap_err();
        assert!(matches!(err, GtpuError::UnsupportedPlatform));
    }

    #[test]
    fn validates_interface_name_and_ifindex() {
        assert!(validate_interface_name("gtp0", "device.name").is_ok());
        assert!(validate_interface_name("", "device.name").is_err());
        assert!(validate_interface_name("bad/name", "device.name").is_err());
        assert!(validate_interface_name("abcdefghijklmnop", "device.name").is_err());
        assert!(validate_interface_name("bad\0name", "device.name").is_err());
        assert!(validate_ifindex(0, "device.ifindex").is_err());
    }

    #[test]
    fn recovery_root_binding_is_absolute_shared_and_non_rebindable() {
        let backend = LinuxGtpuDataplaneBackend::with_transport(CapturingTransport::new());
        let clone = backend.clone();
        assert!(clone
            .clone()
            .with_pdp_recovery_root(PathBuf::from("relative-root"))
            .is_err());
        assert!(clone
            .clone()
            .with_pdp_recovery_root(PathBuf::from("/"))
            .is_err());

        let root = unique_recovery_root("shared-root");
        let bound = clone.with_pdp_recovery_root(root.clone()).unwrap();
        assert_eq!(backend.bound_pdp_recovery_root(), Some(root.as_path()));
        assert!(backend
            .clone()
            .with_pdp_recovery_root(unique_recovery_root("other-root"))
            .is_err());
        assert!(bound.with_pdp_recovery_root(root).is_ok());
    }

    #[test]
    fn validates_device_and_pdp_requests() {
        let mut create = CreateGtpDeviceRequest::new("gtp0");
        create.bind_port = 0;
        assert!(validate_create_device_request(&create).is_err());

        let mut create = CreateGtpDeviceRequest::new("gtp0");
        create.pdp_hashsize = Some(0);
        assert!(validate_create_device_request(&create).is_err());

        let mut context = pdp_context();
        context.link_ifindex = 0;
        assert!(validate_pdp_context(&context).is_err());

        let mut context = pdp_context();
        context.ms_address = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert!(validate_pdp_context(&context).is_err());

        let mut context = pdp_context();
        context.peer_address = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        assert!(validate_pdp_context(&context).is_err());

        let mut remove = RemovePdpContextRequest::from_context(&pdp_context());
        remove.link_ifindex = 0;
        assert!(validate_remove_pdp_context_request(&remove).is_err());
    }

    #[test]
    fn parses_cap_net_admin_from_proc_status_shape() {
        let mask = 1_u64 << CAP_NET_ADMIN;
        assert_ne!(mask, 0);
    }
}
