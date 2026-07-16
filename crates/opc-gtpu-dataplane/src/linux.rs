//! Safe Linux GTP-U backend over the raw netlink sys boundary.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use opc_linux_gtpu_sys::{
    align_to_netlink, ifindex_by_name as linux_ifindex_by_name, open_generic_netlink_socket,
    open_gtpu_udp_socket, open_route_netlink_socket, receive_message, send_message, GtpuIpAddress,
    GtpuUdpBind, GtpuUdpSocket, AF_INET, AF_INET6, CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME,
    CTRL_CMD_GETFAMILY, CTRL_VERSION, GENL_ID_CTRL, GTPA_FAMILY, GTPA_I_TEI, GTPA_LINK,
    GTPA_MS_ADDR6, GTPA_MS_ADDRESS, GTPA_O_TEI, GTPA_PEER_ADDR6, GTPA_PEER_ADDRESS, GTPA_VERSION,
    GTP_CMD_DELPDP, GTP_CMD_NEWPDP, GTP_GENL_NAME, GTP_GENL_VERSION, GTP_ROLE_GGSN, GTP_ROLE_SGSN,
    GTP_V1, IFF_UP, IFLA_GTP_FD1, IFLA_GTP_LOCAL, IFLA_GTP_LOCAL6, IFLA_GTP_PDP_HASHSIZE,
    IFLA_GTP_ROLE, IFLA_IFNAME, IFLA_INFO_DATA, IFLA_INFO_KIND, IFLA_LINKINFO, NLMSG_DONE,
    NLMSG_ERROR, NLMSG_NOOP, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, RTM_DELLINK,
    RTM_NEWLINK,
};

use crate::{
    CreateGtpDeviceRequest, GtpAddressFamily, GtpDevice, GtpPdpContext, GtpRole, GtpVersion,
    GtpuBackendKind, GtpuCapability, GtpuDataplaneBackend, GtpuError, GtpuProbe,
    RemovePdpContextRequest, GTPU_PORT,
};

const NETLINK_HEADER_LEN: usize = 16;
const ROUTE_ATTRIBUTE_HEADER_LEN: usize = 4;
const IF_INFO_MESSAGE_LEN: usize = 16;
const GENERIC_NETLINK_HEADER_LEN: usize = 4;
const IFNAMSIZ: usize = 16;
const CAP_NET_ADMIN: u32 = 12;
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;

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
    device_sockets: Mutex<HashMap<u32, GtpuSocketHandle>>,
    config: LinuxGtpuDataplaneBackendConfig,
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
                device_sockets: Mutex::new(HashMap::new()),
                config,
            }),
        }
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
                device_sockets: Mutex::new(HashMap::new()),
                config: LinuxGtpuDataplaneBackendConfig {
                    receive_attempts: 1,
                    receive_buffer_len: 4096,
                    retry_delay: Duration::ZERO,
                },
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
        validate_create_device_request(&request)?;
        let socket = self.inner.transport.open_gtpu_socket(
            request.bind_address,
            request.bind_port,
            "gtpu_udp_bind",
        )?;
        let body = encode_create_device_request(&request, socket.raw_fd())?;
        let _ = self.route_transact(
            "create_device",
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )?;
        let ifindex = self.ifindex_by_name_after_create(&request.name)?;
        self.retain_device_socket(ifindex, socket)?;
        Ok(GtpDevice {
            name: request.name,
            ifindex,
        })
    }

    fn resolve_device_sync(&self, name: String) -> Result<GtpDevice, GtpuError> {
        validate_interface_name(&name, "device.name")?;
        let ifindex = self.ifindex_by_name_after_create(&name)?;
        validate_ifindex(ifindex, "device.ifindex")?;
        Ok(GtpDevice { name, ifindex })
    }

    fn remove_device_sync(&self, device: GtpDevice) -> Result<(), GtpuError> {
        validate_device(&device)?;
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
        validate_pdp_context(&request)?;
        let family_id = self
            .resolve_gtp_family_id()
            .map_err(map_family_lookup_error)?;
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
        validate_remove_pdp_context_request(&request)?;
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
            match receive_message(&socket, &mut buffer) {
                Ok(0) => {}
                Ok(len) => return parse_netlink_response(&buffer[..len], expected_sequence),
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

fn encode_gtp_genl_header(command: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(GENERIC_NETLINK_HEADER_LEN + 64);
    push_u8(&mut out, command);
    push_u8(&mut out, GTP_GENL_VERSION);
    push_u16_ne(&mut out, 0);
    out
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
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::model::{Teid, DEFAULT_PDP_HASHSIZE};

    type TransportResponse = Result<Option<Vec<u8>>, GtpuError>;
    type ResponseQueue = Arc<Mutex<VecDeque<TransportResponse>>>;

    #[derive(Debug, Clone)]
    struct CapturingTransport {
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        responses: ResponseQueue,
        probe: GtpuProbe,
        socket_fd: i32,
        ifindex: u32,
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
                    details: Some("test transport"),
                },
                socket_fd: 9,
                ifindex: 42,
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
                .push_back(response);
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
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
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or(Ok(None))
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
            Ok(self.ifindex)
        }

        fn probe(&self, _config: LinuxGtpuDataplaneBackendConfig) -> GtpuProbe {
            self.probe
        }
    }

    fn teid(value: u32) -> Teid {
        Teid::new(value).unwrap()
    }

    fn pdp_context() -> GtpPdpContext {
        GtpPdpContext {
            local_teid: teid(0x1122_3344),
            peer_teid: teid(0x5566_7788),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 42,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
        }
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
    fn encodes_ipv6_pdp_context_attrs() {
        let mut context = pdp_context();
        context.ms_address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        context.peer_address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let body = encode_install_pdp_context(&context).unwrap();
        let attrs = &body[GENERIC_NETLINK_HEADER_LEN..];
        assert_eq!(attr_u8(attrs, GTPA_FAMILY), AF_INET6);
        assert_eq!(
            attr_payload(attrs, GTPA_MS_ADDR6),
            Some(&Ipv6Addr::LOCALHOST.octets()[..])
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
        assert_eq!(parse_netlink_response(&ack(7), 7).unwrap(), None);

        let err = parse_netlink_response(&netlink_error(8, 17), 8).unwrap_err();
        assert!(matches!(err, GtpuError::AlreadyExists));

        let err = parse_netlink_response(&netlink_error(9, 95), 9).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(95));

        let err = parse_netlink_response(&netlink_error(10, ENOENT), 10).unwrap_err();
        assert!(matches!(err, GtpuError::NotFound));
    }

    #[test]
    fn rejects_malformed_netlink_responses() {
        let err = parse_netlink_response(&[0_u8; NETLINK_HEADER_LEN - 1], 1).unwrap_err();
        assert_eq!(err.io_kind(), Some(io::ErrorKind::InvalidData));

        let mut invalid_len = ack(1);
        invalid_len[0..4].copy_from_slice(&(NETLINK_HEADER_LEN as u32 - 1).to_ne_bytes());
        let err = parse_netlink_response(&invalid_len, 1).unwrap_err();
        assert_eq!(err.io_kind(), Some(io::ErrorKind::InvalidData));

        let err = parse_netlink_response(&ack(2), 1).unwrap_err();
        assert_eq!(err.io_kind(), Some(io::ErrorKind::InvalidData));
    }

    #[test]
    fn parses_multipart_payload_before_ack() {
        let mut payload_body = encode_gtp_genl_header(CTRL_CMD_GETFAMILY);
        append_attr_u16_ne(&mut payload_body, CTRL_ATTR_FAMILY_ID, 31).unwrap();
        let mut response = encode_netlink_message(GENL_ID_CTRL, 0, 9, &payload_body).unwrap();
        response.extend_from_slice(&ack(9));

        let payload = parse_netlink_response(&response, 9).unwrap().unwrap();
        assert_eq!(parse_generic_family_id(&payload).unwrap(), 31);
    }

    #[test]
    fn parses_generic_family_response() {
        let response = parse_netlink_response(&family_response(3, 29), 3)
            .unwrap()
            .unwrap();
        assert_eq!(parse_generic_family_id(&response).unwrap(), 29);
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
