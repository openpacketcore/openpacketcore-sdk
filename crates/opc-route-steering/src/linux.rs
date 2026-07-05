//! Safe Linux route-steering backend over rtnetlink.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_linux_route_sys::{
    align_to_netlink, open_route_netlink_socket, receive_message, send_message, AF_INET, AF_INET6,
    AF_UNSPEC, FRA_DST, FRA_FWMARK, FRA_FWMASK, FRA_PRIORITY, FRA_SRC, FRA_TABLE, FR_ACT_TO_TBL,
    NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
    RTA_DST, RTA_OIF, RTA_PRIORITY, RTA_TABLE, RTM_DELROUTE, RTM_DELRULE, RTM_NEWROUTE,
    RTM_NEWRULE, RTN_UNICAST, RTPROT_STATIC, RT_SCOPE_UNIVERSE, RT_TABLE_UNSPEC,
};

use crate::backend::RouteSteeringBackend;
use crate::error::RouteSteeringError;
use crate::model::{
    FirewallMark, IpPrefix, RouteRequest, RouteSteeringBackendKind, RouteSteeringProbe, RuleRequest,
};

const NETLINK_HEADER_LEN: usize = 16;
const ROUTE_ATTRIBUTE_HEADER_LEN: usize = 4;
const ROUTE_MESSAGE_LEN: usize = 12;
const FIB_RULE_HEADER_LEN: usize = 12;
const CAP_NET_ADMIN: u32 = 12;
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;

/// Runtime behavior for the Linux route-steering backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxRouteSteeringBackendConfig {
    /// Number of nonblocking receive attempts before returning timeout.
    pub receive_attempts: u16,
    /// Netlink receive buffer size in bytes.
    pub receive_buffer_len: usize,
    /// Delay between nonblocking receive attempts.
    pub retry_delay: Duration,
}

impl Default for LinuxRouteSteeringBackendConfig {
    fn default() -> Self {
        Self {
            receive_attempts: 32,
            receive_buffer_len: 8192,
            retry_delay: Duration::from_millis(1),
        }
    }
}

/// Production Linux route/rule steering backend.
#[derive(Clone)]
pub struct LinuxRouteSteeringBackend {
    inner: Arc<LinuxRouteSteeringBackendInner>,
}

struct LinuxRouteSteeringBackendInner {
    transport: Arc<dyn LinuxRouteTransport>,
    next_sequence: AtomicU32,
    config: LinuxRouteSteeringBackendConfig,
}

impl fmt::Debug for LinuxRouteSteeringBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxRouteSteeringBackend")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl Default for LinuxRouteSteeringBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxRouteSteeringBackend {
    /// Create a backend using the default netlink transport and configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(LinuxRouteSteeringBackendConfig::default())
    }

    /// Create a backend using the default netlink transport and custom config.
    #[must_use]
    pub fn with_config(config: LinuxRouteSteeringBackendConfig) -> Self {
        Self {
            inner: Arc::new(LinuxRouteSteeringBackendInner {
                transport: Arc::new(NetlinkRouteTransport),
                next_sequence: AtomicU32::new(1),
                config,
            }),
        }
    }

    #[cfg(test)]
    fn with_transport<T>(transport: T) -> Self
    where
        T: LinuxRouteTransport + 'static,
    {
        Self {
            inner: Arc::new(LinuxRouteSteeringBackendInner {
                transport: Arc::new(transport),
                next_sequence: AtomicU32::new(1),
                config: LinuxRouteSteeringBackendConfig {
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

    fn transact(
        &self,
        operation: &'static str,
        message_type: u16,
        flags: u16,
        body: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, RouteSteeringError> {
        let sequence = self.next_sequence();
        let request = encode_netlink_message(message_type, flags, sequence, &body)?;
        self.inner
            .transport
            .transact(operation, &request, sequence, self.inner.config)
    }

    async fn run_ack(
        &self,
        operation: &'static str,
        message_type: u16,
        flags: u16,
        body: Vec<u8>,
    ) -> Result<(), RouteSteeringError> {
        let backend = self.clone();
        tokio::task::spawn_blocking(move || {
            let _ = backend.transact(operation, message_type, flags, body)?;
            Ok(())
        })
        .await
        .map_err(|_| {
            RouteSteeringError::io(
                operation,
                io::Error::new(io::ErrorKind::Interrupted, "route blocking task failed"),
            )
        })?
    }
}

#[async_trait]
impl RouteSteeringBackend for LinuxRouteSteeringBackend {
    async fn install_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError> {
        let body = encode_route_request(&request)?;
        self.run_ack(
            "install_route",
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )
        .await
    }

    async fn remove_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError> {
        let body = encode_route_request(&request)?;
        self.run_ack(
            "remove_route",
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )
        .await
    }

    async fn install_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        let body = encode_rule_request(&request)?;
        self.run_ack(
            "install_rule",
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )
        .await
    }

    async fn remove_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        let body = encode_rule_request(&request)?;
        self.run_ack("remove_rule", RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, body)
            .await
    }

    async fn probe(&self) -> Result<RouteSteeringProbe, RouteSteeringError> {
        Ok(self.inner.transport.probe(self.inner.config))
    }
}

trait LinuxRouteTransport: Send + Sync + fmt::Debug {
    fn transact(
        &self,
        operation: &'static str,
        request: &[u8],
        expected_sequence: u32,
        config: LinuxRouteSteeringBackendConfig,
    ) -> Result<Option<Vec<u8>>, RouteSteeringError>;

    fn probe(&self, config: LinuxRouteSteeringBackendConfig) -> RouteSteeringProbe;
}

#[derive(Debug)]
struct NetlinkRouteTransport;

impl LinuxRouteTransport for NetlinkRouteTransport {
    fn transact(
        &self,
        operation: &'static str,
        request: &[u8],
        expected_sequence: u32,
        config: LinuxRouteSteeringBackendConfig,
    ) -> Result<Option<Vec<u8>>, RouteSteeringError> {
        let socket =
            open_route_netlink_socket().map_err(|error| map_open_error(operation, error))?;
        let sent = send_message(&socket, request)
            .map_err(|error| RouteSteeringError::io("netlink_send", error))?;
        if sent != request.len() {
            return Err(RouteSteeringError::io(
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
                Err(error) => return Err(RouteSteeringError::io("netlink_receive", error)),
            }
            if !config.retry_delay.is_zero() {
                std::thread::sleep(config.retry_delay);
            }
        }

        Err(RouteSteeringError::io(
            operation,
            io::Error::new(io::ErrorKind::TimedOut, "route netlink ack timeout"),
        ))
    }

    fn probe(&self, _config: LinuxRouteSteeringBackendConfig) -> RouteSteeringProbe {
        match open_route_netlink_socket() {
            Ok(_) => {
                let net_admin_capable = effective_cap_net_admin().unwrap_or(false);
                RouteSteeringProbe {
                    kind: RouteSteeringBackendKind::LinuxKernel,
                    platform_supported: true,
                    kernel_reachable: true,
                    net_admin_capable,
                    mutation_ready: net_admin_capable,
                    details: if net_admin_capable {
                        Some("linux route netlink mutation ready")
                    } else {
                        Some("CAP_NET_ADMIN is not effective")
                    },
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Unsupported => RouteSteeringProbe {
                kind: RouteSteeringBackendKind::LinuxKernel,
                platform_supported: false,
                kernel_reachable: false,
                net_admin_capable: false,
                mutation_ready: false,
                details: Some("linux route netlink unsupported on this platform"),
            },
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => RouteSteeringProbe {
                kind: RouteSteeringBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: false,
                net_admin_capable: false,
                mutation_ready: false,
                details: Some("linux route netlink permission denied"),
            },
            Err(_) => RouteSteeringProbe {
                kind: RouteSteeringBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: false,
                net_admin_capable: false,
                mutation_ready: false,
                details: Some("linux route netlink socket unavailable"),
            },
        }
    }
}

fn map_open_error(operation: &'static str, error: io::Error) -> RouteSteeringError {
    if error.kind() == io::ErrorKind::Unsupported {
        RouteSteeringError::UnsupportedPlatform
    } else {
        RouteSteeringError::io(operation, error)
    }
}

fn encode_route_request(request: &RouteRequest) -> Result<Vec<u8>, RouteSteeringError> {
    validate_route_request(request)?;
    let mut out = Vec::with_capacity(ROUTE_MESSAGE_LEN + 64);
    push_u8(&mut out, encode_family(request.destination.address));
    push_u8(&mut out, request.destination.prefix_len);
    push_u8(&mut out, 0);
    push_u8(&mut out, 0);
    push_u8(&mut out, table_header_value(request.table)?);
    push_u8(&mut out, RTPROT_STATIC);
    push_u8(&mut out, RT_SCOPE_UNIVERSE);
    push_u8(&mut out, RTN_UNICAST);
    push_u32_ne(&mut out, 0);
    debug_assert_eq!(out.len(), ROUTE_MESSAGE_LEN);
    append_ip_attr(&mut out, RTA_DST, request.destination.address)?;
    append_attr_u32_ne(&mut out, RTA_OIF, request.oif_ifindex)?;
    if let Some(priority) = request.priority {
        append_attr_u32_ne(&mut out, RTA_PRIORITY, priority)?;
    }
    if request.table > u32::from(u8::MAX) {
        append_attr_u32_ne(&mut out, RTA_TABLE, request.table)?;
    }
    Ok(out)
}

fn encode_rule_request(request: &RuleRequest) -> Result<Vec<u8>, RouteSteeringError> {
    validate_rule_request(request)?;
    let family = rule_family(request)?;
    let mut out = Vec::with_capacity(FIB_RULE_HEADER_LEN + 96);
    push_u8(&mut out, family);
    push_u8(
        &mut out,
        request
            .destination
            .map(|prefix| prefix.prefix_len)
            .unwrap_or(0),
    );
    push_u8(
        &mut out,
        request.source.map(|prefix| prefix.prefix_len).unwrap_or(0),
    );
    push_u8(&mut out, 0);
    push_u8(&mut out, table_header_value(request.table)?);
    push_u8(&mut out, 0);
    push_u8(&mut out, 0);
    push_u8(&mut out, FR_ACT_TO_TBL);
    push_u32_ne(&mut out, 0);
    debug_assert_eq!(out.len(), FIB_RULE_HEADER_LEN);
    if let Some(destination) = request.destination {
        append_ip_attr(&mut out, FRA_DST, destination.address)?;
    }
    if let Some(source) = request.source {
        append_ip_attr(&mut out, FRA_SRC, source.address)?;
    }
    if let Some(mark) = request.fwmark {
        append_firewall_mark_attrs(&mut out, mark)?;
    }
    append_attr_u32_ne(&mut out, FRA_PRIORITY, request.priority)?;
    if request.table > u32::from(u8::MAX) {
        append_attr_u32_ne(&mut out, FRA_TABLE, request.table)?;
    }
    Ok(out)
}

fn append_firewall_mark_attrs(
    out: &mut Vec<u8>,
    mark: FirewallMark,
) -> Result<(), RouteSteeringError> {
    append_attr_u32_ne(out, FRA_FWMARK, mark.value)?;
    append_attr_u32_ne(out, FRA_FWMASK, mark.mask)
}

fn append_ip_attr(
    out: &mut Vec<u8>,
    attr_type: u16,
    address: IpAddr,
) -> Result<(), RouteSteeringError> {
    match address {
        IpAddr::V4(address) => append_attr(out, attr_type, &address.octets()),
        IpAddr::V6(address) => append_attr(out, attr_type, &address.octets()),
    }
}

fn append_attr_u32_ne(
    out: &mut Vec<u8>,
    attr_type: u16,
    value: u32,
) -> Result<(), RouteSteeringError> {
    append_attr(out, attr_type, &value.to_ne_bytes())
}

fn append_attr(
    out: &mut Vec<u8>,
    attr_type: u16,
    payload: &[u8],
) -> Result<(), RouteSteeringError> {
    let length = ROUTE_ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(|| {
            RouteSteeringError::invalid_config("netlink.attr", "attribute length overflow")
        })?;
    let aligned = align_to_netlink(length).ok_or_else(|| {
        RouteSteeringError::invalid_config("netlink.attr", "attribute length overflow")
    })?;
    let length_u16 = u16::try_from(length).map_err(|_| {
        RouteSteeringError::invalid_config("netlink.attr", "attribute length overflow")
    })?;
    push_u16_ne(out, length_u16);
    push_u16_ne(out, attr_type);
    out.extend_from_slice(payload);
    out.resize(out.len() + aligned - length, 0);
    Ok(())
}

fn parse_netlink_response(
    response: &[u8],
    expected_sequence: u32,
) -> Result<Option<Vec<u8>>, RouteSteeringError> {
    let mut offset = 0;
    let mut payload = None;
    while offset < response.len() {
        if response.len() - offset < NETLINK_HEADER_LEN {
            return Err(RouteSteeringError::io(
                "netlink_receive",
                invalid_data("short netlink header"),
            ));
        }
        let length = read_u32_ne(response, offset)? as usize;
        if length < NETLINK_HEADER_LEN || offset + length > response.len() {
            return Err(RouteSteeringError::io(
                "netlink_receive",
                invalid_data("invalid netlink length"),
            ));
        }
        let message_type = read_u16_ne(response, offset + 4)?;
        let sequence = read_u32_ne(response, offset + 8)?;
        if sequence != expected_sequence {
            return Err(RouteSteeringError::io(
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
            RouteSteeringError::io(
                "netlink_receive",
                invalid_data("netlink alignment overflow"),
            )
        })?;
        if aligned == 0 {
            return Err(RouteSteeringError::io(
                "netlink_receive",
                invalid_data("zero netlink alignment"),
            ));
        }
        offset += aligned;
    }
    Ok(payload)
}

fn parse_netlink_error(body: &[u8]) -> Result<(), RouteSteeringError> {
    if body.len() < 4 {
        return Err(RouteSteeringError::io(
            "netlink_receive",
            invalid_data("short netlink error"),
        ));
    }
    let error = i32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
    if error == 0 {
        return Ok(());
    }
    if error > 0 {
        return Err(RouteSteeringError::io(
            "netlink_receive",
            invalid_data("positive netlink error"),
        ));
    }
    let errno = error.saturating_abs();
    if matches!(errno, ENOENT | ESRCH) {
        return Err(RouteSteeringError::NotFound);
    }
    let io_error = io::Error::from_raw_os_error(errno);
    match io_error.kind() {
        io::ErrorKind::AlreadyExists => Err(RouteSteeringError::AlreadyExists),
        io::ErrorKind::NotFound => Err(RouteSteeringError::NotFound),
        _ => Err(RouteSteeringError::io("netlink_ack", io_error)),
    }
}

fn validate_route_request(request: &RouteRequest) -> Result<(), RouteSteeringError> {
    validate_prefix(request.destination, "route.destination")?;
    validate_ifindex(request.oif_ifindex, "route.oif_ifindex")?;
    validate_table(request.table, "route.table")?;
    Ok(())
}

fn validate_rule_request(request: &RuleRequest) -> Result<(), RouteSteeringError> {
    if request.source.is_none() && request.destination.is_none() && request.fwmark.is_none() {
        return Err(RouteSteeringError::invalid_config(
            "rule.selector",
            "rule requires at least one selector",
        ));
    }
    if let Some(source) = request.source {
        validate_prefix(source, "rule.source")?;
    }
    if let Some(destination) = request.destination {
        validate_prefix(destination, "rule.destination")?;
    }
    if let (Some(source), Some(destination)) = (request.source, request.destination) {
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(RouteSteeringError::invalid_config(
                "rule.family",
                "source and destination selectors must use the same family",
            ));
        }
    }
    if matches!(request.fwmark, Some(FirewallMark { mask: 0, .. })) {
        return Err(RouteSteeringError::invalid_config(
            "rule.fwmark.mask",
            "fwmark mask must be nonzero",
        ));
    }
    validate_table(request.table, "rule.table")?;
    if request.priority == 0 {
        return Err(RouteSteeringError::invalid_config(
            "rule.priority",
            "priority must be nonzero",
        ));
    }
    Ok(())
}

fn validate_prefix(prefix: IpPrefix, field: &'static str) -> Result<(), RouteSteeringError> {
    let limit = if prefix.is_ipv4() { 32 } else { 128 };
    if prefix.prefix_len > limit {
        return Err(RouteSteeringError::invalid_config(
            field,
            "prefix length exceeds address family",
        ));
    }
    Ok(())
}

fn validate_ifindex(ifindex: u32, field: &'static str) -> Result<(), RouteSteeringError> {
    if ifindex == 0 {
        return Err(RouteSteeringError::invalid_config(
            field,
            "ifindex must be nonzero",
        ));
    }
    if i32::try_from(ifindex).is_err() {
        return Err(RouteSteeringError::invalid_config(
            field,
            "ifindex exceeds i32 range",
        ));
    }
    Ok(())
}

fn validate_table(table: u32, field: &'static str) -> Result<(), RouteSteeringError> {
    if table == 0 {
        return Err(RouteSteeringError::invalid_config(
            field,
            "table must be nonzero",
        ));
    }
    Ok(())
}

fn rule_family(request: &RuleRequest) -> Result<u8, RouteSteeringError> {
    if let Some(source) = request.source {
        return Ok(encode_family(source.address));
    }
    if let Some(destination) = request.destination {
        return Ok(encode_family(destination.address));
    }
    Ok(AF_UNSPEC)
}

fn table_header_value(table: u32) -> Result<u8, RouteSteeringError> {
    if table > u32::from(u8::MAX) {
        Ok(RT_TABLE_UNSPEC)
    } else {
        u8::try_from(table)
            .map_err(|_| RouteSteeringError::invalid_config("table", "table header value overflow"))
    }
}

fn encode_family(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}

fn encode_netlink_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    body: &[u8],
) -> Result<Vec<u8>, RouteSteeringError> {
    let length = NETLINK_HEADER_LEN.checked_add(body.len()).ok_or_else(|| {
        RouteSteeringError::invalid_config("netlink.length", "message length overflow")
    })?;
    let length_u32 = u32::try_from(length).map_err(|_| {
        RouteSteeringError::invalid_config("netlink.length", "message length overflow")
    })?;
    let mut out = Vec::with_capacity(length);
    push_u32_ne(&mut out, length_u32);
    push_u16_ne(&mut out, message_type);
    push_u16_ne(&mut out, flags);
    push_u32_ne(&mut out, sequence);
    push_u32_ne(&mut out, 0);
    out.extend_from_slice(body);
    Ok(out)
}

fn effective_cap_net_admin() -> Result<bool, RouteSteeringError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| RouteSteeringError::io("capability_probe", error))?;
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            let caps = u64::from_str_radix(hex.trim(), 16).map_err(|_| {
                RouteSteeringError::io("capability_probe", invalid_data("invalid CapEff"))
            })?;
            let mask = 1_u64.checked_shl(CAP_NET_ADMIN).ok_or_else(|| {
                RouteSteeringError::io("capability_probe", invalid_data("invalid capability index"))
            })?;
            return Ok((caps & mask) != 0);
        }
    }
    Ok(false)
}

fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn push_u16_ne(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_ne_bytes());
}

#[cfg(test)]
fn push_i32_ne(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn push_u32_ne(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn read_u16_ne(bytes: &[u8], offset: usize) -> Result<u16, RouteSteeringError> {
    let end = offset.checked_add(2).ok_or_else(|| {
        RouteSteeringError::io("netlink_receive", invalid_data("offset overflow"))
    })?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        RouteSteeringError::io("netlink_receive", invalid_data("short netlink field"))
    })?;
    Ok(u16::from_ne_bytes([slice[0], slice[1]]))
}

fn read_u32_ne(bytes: &[u8], offset: usize) -> Result<u32, RouteSteeringError> {
    let end = offset.checked_add(4).ok_or_else(|| {
        RouteSteeringError::io("netlink_receive", invalid_data("offset overflow"))
    })?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        RouteSteeringError::io("netlink_receive", invalid_data("short netlink field"))
    })?;
    Ok(u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Debug, Default, Clone)]
    struct CapturingTransport {
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        response: Option<Vec<u8>>,
        probe: RouteSteeringProbe,
    }

    impl CapturingTransport {
        fn with_response(response: Vec<u8>) -> Self {
            Self {
                response: Some(response),
                ..Self::default()
            }
        }

        fn requests(&self) -> Vec<Vec<u8>> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl LinuxRouteTransport for CapturingTransport {
        fn transact(
            &self,
            _operation: &'static str,
            request: &[u8],
            _expected_sequence: u32,
            _config: LinuxRouteSteeringBackendConfig,
        ) -> Result<Option<Vec<u8>>, RouteSteeringError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request.to_vec());
            Ok(self.response.clone())
        }

        fn probe(&self, _config: LinuxRouteSteeringBackendConfig) -> RouteSteeringProbe {
            self.probe
        }
    }

    fn prefix(octets: [u8; 4], prefix_len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(octets)), prefix_len)
    }

    fn route() -> RouteRequest {
        RouteRequest {
            destination: prefix([10, 23, 0, 0], 24),
            oif_ifindex: 42,
            table: 1000,
            priority: Some(10),
        }
    }

    fn rule() -> RuleRequest {
        RuleRequest {
            source: Some(prefix([10, 23, 0, 0], 24)),
            destination: Some(prefix([192, 0, 2, 0], 24)),
            fwmark: Some(FirewallMark {
                value: 0x40,
                mask: 0xff,
            }),
            table: 1000,
            priority: 100,
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

    fn netlink_body(message: &[u8]) -> &[u8] {
        let len = u32::from_ne_bytes([message[0], message[1], message[2], message[3]]) as usize;
        &message[NETLINK_HEADER_LEN..len]
    }

    fn attr_payload(body: &[u8], mut offset: usize, attr_type: u16) -> Option<&[u8]> {
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

    fn attr_u32(body: &[u8], offset: usize, attr_type: u16) -> u32 {
        let payload = attr_payload(body, offset, attr_type).unwrap();
        u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]])
    }

    #[test]
    fn encodes_route_with_table_oif_metric_and_destination() {
        let body = encode_route_request(&route()).unwrap();

        assert_eq!(body[0], AF_INET);
        assert_eq!(body[1], 24);
        assert_eq!(body[4], RT_TABLE_UNSPEC);
        assert_eq!(body[5], RTPROT_STATIC);
        assert_eq!(body[6], RT_SCOPE_UNIVERSE);
        assert_eq!(body[7], RTN_UNICAST);
        assert_eq!(
            attr_payload(&body, ROUTE_MESSAGE_LEN, RTA_DST),
            Some(&[10, 23, 0, 0][..])
        );
        assert_eq!(attr_u32(&body, ROUTE_MESSAGE_LEN, RTA_OIF), 42);
        assert_eq!(attr_u32(&body, ROUTE_MESSAGE_LEN, RTA_PRIORITY), 10);
        assert_eq!(attr_u32(&body, ROUTE_MESSAGE_LEN, RTA_TABLE), 1000);
    }

    #[test]
    fn encodes_rule_with_selectors_mark_priority_and_table() {
        let body = encode_rule_request(&rule()).unwrap();

        assert_eq!(body[0], AF_INET);
        assert_eq!(body[1], 24);
        assert_eq!(body[2], 24);
        assert_eq!(body[4], RT_TABLE_UNSPEC);
        assert_eq!(body[7], FR_ACT_TO_TBL);
        assert_eq!(
            attr_payload(&body, FIB_RULE_HEADER_LEN, FRA_SRC),
            Some(&[10, 23, 0, 0][..])
        );
        assert_eq!(
            attr_payload(&body, FIB_RULE_HEADER_LEN, FRA_DST),
            Some(&[192, 0, 2, 0][..])
        );
        assert_eq!(attr_u32(&body, FIB_RULE_HEADER_LEN, FRA_FWMARK), 0x40);
        assert_eq!(attr_u32(&body, FIB_RULE_HEADER_LEN, FRA_FWMASK), 0xff);
        assert_eq!(attr_u32(&body, FIB_RULE_HEADER_LEN, FRA_PRIORITY), 100);
        assert_eq!(attr_u32(&body, FIB_RULE_HEADER_LEN, FRA_TABLE), 1000);
    }

    #[test]
    fn encodes_ipv6_route_destination() {
        let body = encode_route_request(&RouteRequest {
            destination: IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
            oif_ifindex: 7,
            table: 100,
            priority: None,
        })
        .unwrap();

        assert_eq!(body[0], AF_INET6);
        assert_eq!(body[1], 128);
        assert_eq!(
            attr_payload(&body, ROUTE_MESSAGE_LEN, RTA_DST),
            Some(&Ipv6Addr::LOCALHOST.octets()[..])
        );
        assert!(attr_payload(&body, ROUTE_MESSAGE_LEN, RTA_PRIORITY).is_none());
    }

    #[test]
    fn validates_route_and_rule_requests() {
        let mut bad_route = route();
        bad_route.oif_ifindex = 0;
        assert!(matches!(
            encode_route_request(&bad_route),
            Err(RouteSteeringError::InvalidConfig {
                field: "route.oif_ifindex",
                ..
            })
        ));

        let bad_rule = RuleRequest {
            source: None,
            destination: None,
            fwmark: None,
            table: 100,
            priority: 100,
        };
        assert!(matches!(
            encode_rule_request(&bad_rule),
            Err(RouteSteeringError::InvalidConfig {
                field: "rule.selector",
                ..
            })
        ));

        let mut bad_rule = rule();
        bad_rule.destination = Some(IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128));
        assert!(matches!(
            encode_rule_request(&bad_rule),
            Err(RouteSteeringError::InvalidConfig {
                field: "rule.family",
                ..
            })
        ));

        let mut bad_rule = rule();
        bad_rule.fwmark = Some(FirewallMark { value: 1, mask: 0 });
        assert!(matches!(
            encode_rule_request(&bad_rule),
            Err(RouteSteeringError::InvalidConfig {
                field: "rule.fwmark.mask",
                ..
            })
        ));
    }

    #[test]
    fn parses_ack_and_errno_mapping() {
        assert_eq!(parse_netlink_response(&ack(7), 7).unwrap(), None);
        assert!(matches!(
            parse_netlink_response(&netlink_error(8, 17), 8).unwrap_err(),
            RouteSteeringError::AlreadyExists
        ));
        assert!(matches!(
            parse_netlink_response(&netlink_error(9, ENOENT), 9).unwrap_err(),
            RouteSteeringError::NotFound
        ));
        assert_eq!(
            parse_netlink_response(&netlink_error(10, 95), 10)
                .unwrap_err()
                .raw_os_error(),
            Some(95)
        );
    }

    #[tokio::test]
    async fn linux_backend_sends_route_and_rule_messages() {
        let transport = CapturingTransport::default();
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());

        backend.install_route(route()).await.unwrap();
        backend.install_rule(rule()).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            u16::from_ne_bytes([requests[0][4], requests[0][5]]),
            RTM_NEWROUTE
        );
        assert_eq!(
            u16::from_ne_bytes([requests[0][6], requests[0][7]]),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        assert_eq!(
            u16::from_ne_bytes([requests[1][4], requests[1][5]]),
            RTM_NEWRULE
        );
        assert_eq!(netlink_body(&requests[0])[0], AF_INET);
        assert_eq!(netlink_body(&requests[1])[7], FR_ACT_TO_TBL);
    }

    #[tokio::test]
    async fn linux_backend_sends_remove_messages() {
        let transport = CapturingTransport::with_response(ack(1));
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());

        backend.remove_route(route()).await.unwrap();
        backend.remove_rule(rule()).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            u16::from_ne_bytes([requests[0][4], requests[0][5]]),
            RTM_DELROUTE
        );
        assert_eq!(
            u16::from_ne_bytes([requests[1][4], requests[1][5]]),
            RTM_DELRULE
        );
    }
}
