//! Safe Linux XFRM backend over the raw netlink sys boundary.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_linux_xfrm_sys::{
    align_to_netlink, open_netlink_socket, receive_message, send_message, NLMSG_DONE, NLMSG_ERROR,
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST, XFRMA_ALG_AEAD,
    XFRMA_ALG_AUTH_TRUNC, XFRMA_ALG_CRYPT, XFRMA_ENCAP, XFRMA_IF_ID, XFRMA_MARK, XFRMA_TMPL,
    XFRM_MSG_ALLOCSPI, XFRM_MSG_DELPOLICY, XFRM_MSG_DELSA, XFRM_MSG_NEWPOLICY, XFRM_MSG_NEWSA,
    XFRM_MSG_UPDPOLICY, XFRM_MSG_UPDSA, XFRM_POLICY_ALLOW, XFRM_POLICY_BLOCK, XFRM_POLICY_FWD,
    XFRM_POLICY_IN, XFRM_POLICY_OUT,
};
use zeroize::Zeroizing;

use crate::{
    AllocateSpiRequest, InstallPolicyRequest, InstallSaRequest, IpAddress, LifetimeConfig,
    PolicyParameters, RekeyPolicyRequest, RekeySaRequest, RemovePolicyRequest, RemoveSaRequest,
    SaParameters, SpiAllocation, UdpEncap, XfrmAction, XfrmBackend, XfrmBackendKind,
    XfrmCapability, XfrmDirection, XfrmError, XfrmId, XfrmMark, XfrmMode, XfrmProbe, XfrmSelector,
    XfrmTemplate, XFRM_AEAD_RFC4106_GCM_AES,
};

const NETLINK_HEADER_LEN: usize = 16;
const ROUTE_ATTRIBUTE_HEADER_LEN: usize = 4;
const XFRM_ADDRESS_LEN: usize = 16;
const XFRM_SELECTOR_LEN: usize = 56;
const XFRM_LIFETIME_CONFIG_LEN: usize = 64;
const XFRM_LIFETIME_CURRENT_LEN: usize = 32;
const XFRM_STATS_LEN: usize = 12;
const XFRM_USER_SA_INFO_LEN: usize = 224;
const XFRM_USER_SA_ID_LEN: usize = 24;
const XFRM_USER_POLICY_INFO_LEN: usize = 168;
const XFRM_USER_POLICY_ID_LEN: usize = 64;
const XFRM_USER_TEMPLATE_LEN: usize = 64;
const XFRM_USER_SPI_INFO_LEN: usize = 232;
const XFRM_ALG_NAME_LEN: usize = 64;
const XFRM_ALGO_HEADER_LEN: usize = 68;
const XFRM_ALGO_AUTH_HEADER_LEN: usize = 72;
const XFRM_ALGO_AEAD_HEADER_LEN: usize = 72;
const XFRM_MARK_LEN: usize = 8;
const XFRM_ENCAP_TEMPLATE_LEN: usize = 24;
const XFRM_SPI_OFFSET_IN_SA_INFO: usize = XFRM_SELECTOR_LEN + XFRM_ADDRESS_LEN;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const XFRM_INF: u64 = u64::MAX;
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;

type SensitiveBuffer = Zeroizing<Vec<u8>>;

/// Runtime behavior for the safe Linux XFRM backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxXfrmBackendConfig {
    /// Number of nonblocking receive attempts before returning a timeout.
    pub receive_attempts: u16,
    /// Netlink receive buffer size in bytes.
    pub receive_buffer_len: usize,
    /// Delay between nonblocking receive attempts.
    pub retry_delay: Duration,
}

impl Default for LinuxXfrmBackendConfig {
    fn default() -> Self {
        Self {
            receive_attempts: 32,
            receive_buffer_len: 8192,
            retry_delay: Duration::from_millis(1),
        }
    }
}

/// Production Linux kernel XFRM backend.
///
/// This backend opens a raw `NETLINK_XFRM` socket for each operation, encodes
/// SDK request models into Linux XFRM UAPI messages, sends the request through
/// `opc-linux-xfrm-sys`, and maps ACK/error responses back into redaction-safe
/// [`XfrmError`] values.
#[derive(Clone)]
pub struct LinuxXfrmBackend {
    inner: Arc<LinuxXfrmBackendInner>,
}

struct LinuxXfrmBackendInner {
    transport: Arc<dyn LinuxXfrmTransport>,
    next_sequence: AtomicU32,
    config: LinuxXfrmBackendConfig,
}

impl fmt::Debug for LinuxXfrmBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxXfrmBackend")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl Default for LinuxXfrmBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxXfrmBackend {
    /// Create a backend using the default netlink transport and configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(LinuxXfrmBackendConfig::default())
    }

    /// Create a backend using the default netlink transport and custom config.
    #[must_use]
    pub fn with_config(config: LinuxXfrmBackendConfig) -> Self {
        Self {
            inner: Arc::new(LinuxXfrmBackendInner {
                transport: Arc::new(NetlinkXfrmTransport),
                next_sequence: AtomicU32::new(1),
                config,
            }),
        }
    }

    #[cfg(test)]
    fn with_transport<T>(transport: T) -> Self
    where
        T: LinuxXfrmTransport + 'static,
    {
        Self {
            inner: Arc::new(LinuxXfrmBackendInner {
                transport: Arc::new(transport),
                next_sequence: AtomicU32::new(1),
                config: LinuxXfrmBackendConfig {
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
        body: SensitiveBuffer,
    ) -> Result<Option<Vec<u8>>, XfrmError> {
        let sequence = self.next_sequence();
        let request = encode_netlink_message(message_type, flags, sequence, &body)?;
        self.inner
            .transport
            .transact(operation, &request, sequence, self.inner.config)
    }

    async fn transact_blocking(
        &self,
        operation: &'static str,
        message_type: u16,
        flags: u16,
        body: SensitiveBuffer,
    ) -> Result<Option<Vec<u8>>, XfrmError> {
        let backend = self.clone();
        tokio::task::spawn_blocking(move || backend.transact(operation, message_type, flags, body))
            .await
            .map_err(|_| {
                XfrmError::io(
                    operation,
                    io::Error::new(io::ErrorKind::Interrupted, "xfrm blocking task failed"),
                )
            })?
    }

    async fn run_ack(
        &self,
        operation: &'static str,
        message_type: u16,
        flags: u16,
        body: SensitiveBuffer,
    ) -> Result<(), XfrmError> {
        let _ = self
            .transact_blocking(operation, message_type, flags, body)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl XfrmBackend for LinuxXfrmBackend {
    async fn allocate_spi(&self, request: AllocateSpiRequest) -> Result<SpiAllocation, XfrmError> {
        validate_spi_range(request.min_spi, request.max_spi)?;
        let body = encode_alloc_spi_request(request)?;
        let response = self
            .transact_blocking(
                "allocspi",
                XFRM_MSG_ALLOCSPI,
                NLM_F_REQUEST | NLM_F_ACK,
                body,
            )
            .await?
            .ok_or_else(|| XfrmError::io("allocspi", invalid_data("missing allocspi response")))?;
        let spi = parse_allocated_spi(&response)?;
        Ok(SpiAllocation {
            destination: request.destination,
            protocol: request.protocol,
            spi,
        })
    }

    async fn install_sa(&self, request: InstallSaRequest) -> Result<(), XfrmError> {
        let body = encode_sa_info(&request.parameters)?;
        self.run_ack(
            "install_sa",
            XFRM_MSG_NEWSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )
        .await
    }

    async fn rekey_sa(&self, request: RekeySaRequest) -> Result<(), XfrmError> {
        let body = encode_sa_info(&request.parameters)?;
        self.run_ack(
            "rekey_sa",
            XFRM_MSG_UPDSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE,
            body,
        )
        .await
    }

    async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError> {
        let body = encode_sa_id(request.destination, request.protocol, request.spi)?;
        self.run_ack("remove_sa", XFRM_MSG_DELSA, NLM_F_REQUEST | NLM_F_ACK, body)
            .await
    }

    async fn install_policy(&self, request: InstallPolicyRequest) -> Result<(), XfrmError> {
        let body = encode_policy_info(&request.parameters)?;
        self.run_ack(
            "install_policy",
            XFRM_MSG_NEWPOLICY,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )
        .await
    }

    async fn rekey_policy(&self, request: RekeyPolicyRequest) -> Result<(), XfrmError> {
        let body = encode_policy_info(&request.parameters)?;
        self.run_ack(
            "rekey_policy",
            XFRM_MSG_UPDPOLICY,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE,
            body,
        )
        .await
    }

    async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError> {
        let body = encode_policy_id(&request.selector, request.direction)?;
        self.run_ack(
            "remove_policy",
            XFRM_MSG_DELPOLICY,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )
        .await
    }

    async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
        Ok(self.inner.transport.probe(self.inner.config))
    }
}

trait LinuxXfrmTransport: Send + Sync + fmt::Debug {
    fn transact(
        &self,
        operation: &'static str,
        request: &[u8],
        expected_sequence: u32,
        config: LinuxXfrmBackendConfig,
    ) -> Result<Option<Vec<u8>>, XfrmError>;

    fn probe(&self, config: LinuxXfrmBackendConfig) -> XfrmProbe;
}

#[derive(Debug)]
struct NetlinkXfrmTransport;

impl LinuxXfrmTransport for NetlinkXfrmTransport {
    fn transact(
        &self,
        operation: &'static str,
        request: &[u8],
        expected_sequence: u32,
        config: LinuxXfrmBackendConfig,
    ) -> Result<Option<Vec<u8>>, XfrmError> {
        let socket = open_netlink_socket().map_err(|error| map_open_error(operation, error))?;
        let sent =
            send_message(&socket, request).map_err(|error| XfrmError::io("netlink_send", error))?;
        if sent != request.len() {
            return Err(XfrmError::io(
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
                Err(error) => return Err(XfrmError::io("netlink_receive", error)),
            }
            if !config.retry_delay.is_zero() {
                std::thread::sleep(config.retry_delay);
            }
        }

        Err(XfrmError::StateIndeterminate { operation })
    }

    fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
        match open_netlink_socket() {
            Ok(_) => XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: true,
                net_admin_capable: true,
                algorithms: XfrmCapability::Available,
                details: Some("linux XFRM netlink socket reachable"),
            },
            Err(error) if error.kind() == io::ErrorKind::Unsupported => XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: false,
                kernel_reachable: false,
                net_admin_capable: false,
                algorithms: XfrmCapability::Unknown,
                details: Some("linux XFRM netlink unsupported on this platform"),
            },
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: false,
                net_admin_capable: false,
                algorithms: XfrmCapability::PermissionDenied,
                details: Some("linux XFRM netlink permission denied"),
            },
            Err(_) => XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: false,
                net_admin_capable: false,
                algorithms: XfrmCapability::Unknown,
                details: Some("linux XFRM netlink socket unavailable"),
            },
        }
    }
}

fn map_open_error(operation: &'static str, error: io::Error) -> XfrmError {
    if error.kind() == io::ErrorKind::Unsupported {
        XfrmError::UnsupportedPlatform
    } else {
        XfrmError::io(operation, error)
    }
}

fn sensitive_buffer_with_capacity(capacity: usize) -> SensitiveBuffer {
    Zeroizing::new(Vec::with_capacity(capacity))
}

fn encode_netlink_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    body: &[u8],
) -> Result<SensitiveBuffer, XfrmError> {
    let length = NETLINK_HEADER_LEN
        .checked_add(body.len())
        .ok_or_else(|| XfrmError::invalid_config("netlink.length", "message length overflow"))?;
    let length_u32 = u32::try_from(length)
        .map_err(|_| XfrmError::invalid_config("netlink.length", "message length overflow"))?;

    let mut out = sensitive_buffer_with_capacity(length);
    push_u32_ne(&mut out, length_u32);
    push_u16_ne(&mut out, message_type);
    push_u16_ne(&mut out, flags);
    push_u32_ne(&mut out, sequence);
    push_u32_ne(&mut out, 0);
    out.extend_from_slice(body);
    Ok(out)
}

fn parse_netlink_response(
    response: &[u8],
    expected_sequence: u32,
) -> Result<Option<Vec<u8>>, XfrmError> {
    if response.len() < NETLINK_HEADER_LEN {
        return Err(XfrmError::io(
            "netlink_receive",
            invalid_data("short netlink header"),
        ));
    }

    let length = read_u32_ne(response, 0)? as usize;
    if length < NETLINK_HEADER_LEN || length > response.len() {
        return Err(XfrmError::io(
            "netlink_receive",
            invalid_data("invalid netlink length"),
        ));
    }

    let message_type = read_u16_ne(response, 4)?;
    let sequence = read_u32_ne(response, 8)?;
    if sequence != expected_sequence {
        return Err(XfrmError::io(
            "netlink_receive",
            invalid_data("unexpected netlink sequence"),
        ));
    }

    let body = &response[NETLINK_HEADER_LEN..length];
    match message_type {
        NLMSG_ERROR => parse_netlink_error(body),
        NLMSG_DONE => Ok(None),
        _ => Ok(Some(body.to_vec())),
    }
}

fn parse_netlink_error(body: &[u8]) -> Result<Option<Vec<u8>>, XfrmError> {
    if body.len() < 4 {
        return Err(XfrmError::io(
            "netlink_receive",
            invalid_data("short netlink error"),
        ));
    }
    let error = i32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
    if error == 0 {
        return Ok(None);
    }
    if error > 0 {
        return Err(XfrmError::io(
            "netlink_receive",
            invalid_data("positive netlink error"),
        ));
    }
    let errno = error.saturating_abs();
    if matches!(errno, ENOENT | ESRCH) {
        return Err(XfrmError::NotFound);
    }
    let io_error = io::Error::from_raw_os_error(errno);
    match io_error.kind() {
        io::ErrorKind::AlreadyExists => Err(XfrmError::AlreadyExists),
        io::ErrorKind::NotFound => Err(XfrmError::NotFound),
        io::ErrorKind::Unsupported => Err(XfrmError::UnsupportedFeature {
            feature: "linux_xfrm_netlink",
        }),
        _ => Err(XfrmError::io("netlink_ack", io_error)),
    }
}

fn encode_alloc_spi_request(request: AllocateSpiRequest) -> Result<SensitiveBuffer, XfrmError> {
    let sa = SaParameters {
        selector: XfrmSelector::new(request.destination, request.destination, request.protocol),
        id: XfrmId {
            destination: request.destination,
            spi: 0,
            protocol: request.protocol,
        },
        source_address: request.destination,
        auth: None,
        crypt: None,
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 0,
        encap: None,
        mark: None,
        if_id: None,
    };

    let mut out = encode_sa_info_inner(&sa, true)?;
    debug_assert_eq!(out.len(), XFRM_USER_SA_INFO_LEN);
    push_u32_ne(&mut out, request.min_spi);
    push_u32_ne(&mut out, request.max_spi);
    debug_assert_eq!(out.len(), XFRM_USER_SPI_INFO_LEN);
    Ok(out)
}

fn encode_sa_info(parameters: &SaParameters) -> Result<SensitiveBuffer, XfrmError> {
    encode_sa_info_inner(parameters, false)
}

fn encode_sa_info_inner(
    parameters: &SaParameters,
    allow_zero_spi: bool,
) -> Result<SensitiveBuffer, XfrmError> {
    validate_sa_parameters(parameters, allow_zero_spi)?;
    let family = address_family(parameters.id.destination);
    let mut out = sensitive_buffer_with_capacity(XFRM_USER_SA_INFO_LEN + 256);
    encode_selector(&mut out, &parameters.selector)?;
    encode_xfrm_id(
        &mut out,
        parameters.id.destination,
        parameters.id.protocol,
        parameters.id.spi,
    );
    encode_address(&mut out, parameters.source_address);
    encode_lifetime_config(&mut out, parameters.lifetime);
    let len = out.len();
    out.resize(len + XFRM_LIFETIME_CURRENT_LEN, 0);
    let len = out.len();
    out.resize(len + XFRM_STATS_LEN, 0);
    push_u32_ne(&mut out, 0);
    push_u32_ne(&mut out, 0);
    push_u16_ne(&mut out, family);
    push_u8(&mut out, encode_mode(parameters.mode));
    push_u8(&mut out, parameters.replay_window);
    push_u8(&mut out, 0);
    out.resize(XFRM_USER_SA_INFO_LEN, 0);

    if let Some((auth, key)) = &parameters.auth {
        append_attr(
            &mut out,
            XFRMA_ALG_AUTH_TRUNC,
            encode_auth_algorithm(&auth.name, key.as_bytes(), auth.truncation_len_bits)?.as_slice(),
        )?;
    }
    if let Some((algorithm, key)) = &parameters.crypt {
        append_attr(
            &mut out,
            XFRMA_ALG_CRYPT,
            encode_algorithm(&algorithm.name, key.as_bytes())?.as_slice(),
        )?;
    }
    if let Some((aead, key)) = &parameters.aead {
        append_attr(
            &mut out,
            XFRMA_ALG_AEAD,
            encode_aead_algorithm(&aead.name, key.as_bytes(), aead.icv_len_bits)?.as_slice(),
        )?;
    }
    if let Some(encap) = parameters.encap {
        append_attr(&mut out, XFRMA_ENCAP, encode_udp_encap(encap).as_slice())?;
    }
    append_common_attrs(&mut out, parameters.mark, parameters.if_id)?;
    Ok(out)
}

fn encode_sa_id(
    destination: IpAddress,
    protocol: u8,
    spi: u32,
) -> Result<SensitiveBuffer, XfrmError> {
    if spi == 0 {
        return Err(XfrmError::invalid_config("spi", "spi must be nonzero"));
    }
    let mut out = sensitive_buffer_with_capacity(XFRM_USER_SA_ID_LEN);
    encode_address(&mut out, destination);
    push_u32_be(&mut out, spi);
    push_u16_ne(&mut out, address_family(destination));
    push_u8(&mut out, protocol);
    out.resize(XFRM_USER_SA_ID_LEN, 0);
    Ok(out)
}

fn encode_policy_info(parameters: &PolicyParameters) -> Result<SensitiveBuffer, XfrmError> {
    validate_policy_parameters(parameters)?;
    let mut out = sensitive_buffer_with_capacity(
        XFRM_USER_POLICY_INFO_LEN
            + ROUTE_ATTRIBUTE_HEADER_LEN
            + parameters.templates.len() * XFRM_USER_TEMPLATE_LEN,
    );
    encode_selector(&mut out, &parameters.selector)?;
    encode_lifetime_config(&mut out, LifetimeConfig::default());
    let len = out.len();
    out.resize(len + XFRM_LIFETIME_CURRENT_LEN, 0);
    push_u32_ne(&mut out, parameters.priority);
    push_u32_ne(&mut out, 0);
    push_u8(&mut out, encode_direction(parameters.direction));
    push_u8(&mut out, encode_action(parameters.action));
    push_u8(&mut out, 0);
    push_u8(&mut out, 0);
    out.resize(XFRM_USER_POLICY_INFO_LEN, 0);
    debug_assert_eq!(out.len(), XFRM_USER_POLICY_INFO_LEN);

    if !parameters.templates.is_empty() {
        let mut templates = Vec::with_capacity(parameters.templates.len() * XFRM_USER_TEMPLATE_LEN);
        for template in &parameters.templates {
            encode_template(&mut templates, template)?;
        }
        append_attr(&mut out, XFRMA_TMPL, &templates)?;
    }
    append_common_attrs(&mut out, parameters.mark, parameters.if_id)?;
    Ok(out)
}

fn encode_policy_id(
    selector: &XfrmSelector,
    direction: XfrmDirection,
) -> Result<SensitiveBuffer, XfrmError> {
    validate_selector_family(selector)?;
    let mut out = sensitive_buffer_with_capacity(XFRM_USER_POLICY_ID_LEN);
    encode_selector(&mut out, selector)?;
    push_u32_ne(&mut out, 0);
    push_u8(&mut out, encode_direction(direction));
    out.resize(XFRM_USER_POLICY_ID_LEN, 0);
    Ok(out)
}

fn encode_template(out: &mut Vec<u8>, template: &XfrmTemplate) -> Result<(), XfrmError> {
    validate_same_family(
        template.id.destination,
        template.source_address,
        "template.family",
    )?;
    let start = out.len();
    encode_xfrm_id(
        out,
        template.id.destination,
        template.id.protocol,
        template.id.spi,
    );
    push_u16_ne(out, address_family(template.id.destination));
    out.resize(start + 28, 0);
    encode_address(out, template.source_address);
    push_u32_ne(out, 0);
    push_u8(out, encode_mode(template.mode));
    push_u8(out, 0);
    push_u8(out, 0);
    out.resize(start + 52, 0);
    push_u32_ne(out, 0);
    push_u32_ne(out, 0);
    push_u32_ne(out, 0);
    debug_assert_eq!(out.len() - start, XFRM_USER_TEMPLATE_LEN);
    Ok(())
}

fn encode_selector(out: &mut Vec<u8>, selector: &XfrmSelector) -> Result<(), XfrmError> {
    validate_selector_family(selector)?;
    encode_address(out, selector.destination);
    encode_address(out, selector.source);
    push_u16_be(out, selector.destination_port);
    push_u16_be(
        out,
        if selector.destination_port == 0 {
            0
        } else {
            u16::MAX
        },
    );
    push_u16_be(out, selector.source_port);
    push_u16_be(
        out,
        if selector.source_port == 0 {
            0
        } else {
            u16::MAX
        },
    );
    push_u16_ne(out, address_family(selector.source));
    push_u8(out, selector.destination_prefix_len);
    push_u8(out, selector.source_prefix_len);
    push_u8(out, selector.protocol);
    out.resize(out.len() + 3, 0);
    push_i32_ne(out, 0);
    push_u32_ne(out, 0);
    debug_assert_eq!(out.len() % XFRM_SELECTOR_LEN, 0);
    Ok(())
}

fn encode_lifetime_config(out: &mut Vec<u8>, lifetime: LifetimeConfig) {
    push_u64_ne(out, limit_or_infinite(lifetime.soft_byte_limit));
    push_u64_ne(out, limit_or_infinite(lifetime.hard_byte_limit));
    push_u64_ne(out, limit_or_infinite(lifetime.soft_packet_limit));
    push_u64_ne(out, limit_or_infinite(lifetime.hard_packet_limit));
    push_u64_ne(out, lifetime.soft_add_expires_seconds);
    push_u64_ne(out, lifetime.hard_add_expires_seconds);
    push_u64_ne(out, 0);
    push_u64_ne(out, 0);
    debug_assert_eq!(XFRM_LIFETIME_CONFIG_LEN, 64);
}

fn limit_or_infinite(value: u64) -> u64 {
    if value == 0 {
        XFRM_INF
    } else {
        value
    }
}

fn encode_algorithm(name: &str, key: &[u8]) -> Result<SensitiveBuffer, XfrmError> {
    validate_key_material(key)?;
    let mut out = sensitive_buffer_with_capacity(XFRM_ALGO_HEADER_LEN + key.len());
    out.extend_from_slice(&encode_algorithm_name(name)?);
    push_u32_ne(&mut out, key_len_bits(key)?);
    out.extend_from_slice(key);
    Ok(out)
}

fn encode_auth_algorithm(
    name: &str,
    key: &[u8],
    truncation_len_bits: u32,
) -> Result<SensitiveBuffer, XfrmError> {
    validate_key_material(key)?;
    if truncation_len_bits == 0 {
        return Err(XfrmError::invalid_config(
            "auth.truncation_len_bits",
            "truncation length must be nonzero",
        ));
    }
    let mut out = sensitive_buffer_with_capacity(XFRM_ALGO_AUTH_HEADER_LEN + key.len());
    out.extend_from_slice(&encode_algorithm_name(name)?);
    push_u32_ne(&mut out, key_len_bits(key)?);
    push_u32_ne(&mut out, truncation_len_bits);
    out.extend_from_slice(key);
    Ok(out)
}

fn encode_aead_algorithm(
    name: &str,
    key: &[u8],
    icv_len_bits: u32,
) -> Result<SensitiveBuffer, XfrmError> {
    validate_key_material(key)?;
    if icv_len_bits == 0 {
        return Err(XfrmError::invalid_config(
            "aead.icv_len_bits",
            "icv length must be nonzero",
        ));
    }
    let mut out = sensitive_buffer_with_capacity(XFRM_ALGO_AEAD_HEADER_LEN + key.len());
    out.extend_from_slice(&encode_algorithm_name(name)?);
    push_u32_ne(&mut out, key_len_bits(key)?);
    push_u32_ne(&mut out, icv_len_bits);
    out.extend_from_slice(key);
    Ok(out)
}

fn encode_udp_encap(encap: UdpEncap) -> SensitiveBuffer {
    let mut out = sensitive_buffer_with_capacity(XFRM_ENCAP_TEMPLATE_LEN);
    push_u16_ne(&mut out, encap.encap_type);
    push_u16_be(&mut out, encap.source_port);
    push_u16_be(&mut out, encap.destination_port);
    out.resize(XFRM_ENCAP_TEMPLATE_LEN, 0);
    out
}

fn encode_mark(mark: XfrmMark) -> [u8; XFRM_MARK_LEN] {
    let mut out = [0_u8; XFRM_MARK_LEN];
    out[..4].copy_from_slice(&mark.value.to_ne_bytes());
    out[4..].copy_from_slice(&mark.mask.to_ne_bytes());
    out
}

fn append_common_attrs(
    out: &mut Vec<u8>,
    mark: Option<XfrmMark>,
    if_id: Option<u32>,
) -> Result<(), XfrmError> {
    if let Some(mark) = mark {
        append_attr(out, XFRMA_MARK, &encode_mark(mark))?;
    }
    if let Some(if_id) = if_id {
        append_attr(out, XFRMA_IF_ID, &if_id.to_ne_bytes())?;
    }
    Ok(())
}

fn append_attr(out: &mut Vec<u8>, attr_type: u16, payload: &[u8]) -> Result<(), XfrmError> {
    let length = ROUTE_ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or_else(|| XfrmError::invalid_config("netlink.attr", "attribute length overflow"))?;
    let aligned = align_to_netlink(length)
        .ok_or_else(|| XfrmError::invalid_config("netlink.attr", "attribute length overflow"))?;
    let length_u16 = u16::try_from(length)
        .map_err(|_| XfrmError::invalid_config("netlink.attr", "attribute length overflow"))?;
    push_u16_ne(out, length_u16);
    push_u16_ne(out, attr_type);
    out.extend_from_slice(payload);
    out.resize(out.len() + aligned - length, 0);
    Ok(())
}

fn parse_allocated_spi(payload: &[u8]) -> Result<u32, XfrmError> {
    if payload.len() < XFRM_SPI_OFFSET_IN_SA_INFO + 4 {
        return Err(XfrmError::io(
            "allocspi",
            invalid_data("short allocspi response"),
        ));
    }
    let offset = XFRM_SPI_OFFSET_IN_SA_INFO;
    let spi = u32::from_be_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ]);
    if spi == 0 {
        return Err(XfrmError::io(
            "allocspi",
            invalid_data("zero allocspi response"),
        ));
    }
    Ok(spi)
}

fn validate_sa_parameters(
    parameters: &SaParameters,
    allow_zero_spi: bool,
) -> Result<(), XfrmError> {
    validate_selector_family(&parameters.selector)?;
    validate_same_family(
        parameters.id.destination,
        parameters.source_address,
        "sa.tunnel_family",
    )?;
    validate_same_family(
        parameters.selector.source,
        parameters.selector.destination,
        "selector.family",
    )?;
    if parameters.id.spi == 0 && !allow_zero_spi {
        return Err(XfrmError::invalid_config("spi", "spi must be nonzero"));
    }
    if parameters.id.protocol == 0 {
        return Err(XfrmError::invalid_config(
            "protocol",
            "protocol must be nonzero",
        ));
    }
    if parameters.replay_window > 32 {
        return Err(XfrmError::invalid_config(
            "replay_window",
            "replay window >32 requires ESN support",
        ));
    }
    if parameters.aead.is_some() && (parameters.auth.is_some() || parameters.crypt.is_some()) {
        return Err(XfrmError::invalid_config(
            "aead",
            "aead is mutually exclusive with auth/crypt",
        ));
    }
    if let Some(encap) = parameters.encap {
        if encap.encap_type == 0 {
            return Err(XfrmError::invalid_config(
                "encap.encap_type",
                "encapsulation type must be nonzero",
            ));
        }
        if encap.source_port == 0 || encap.destination_port == 0 {
            return Err(XfrmError::invalid_config(
                "encap.port",
                "UDP encapsulation ports must be nonzero",
            ));
        }
    }
    if let Some((algorithm, _)) = &parameters.crypt {
        if is_known_aead_algorithm(&algorithm.name) {
            return Err(XfrmError::invalid_config(
                "crypt",
                "aead algorithm must use the aead slot",
            ));
        }
    }
    Ok(())
}

fn is_known_aead_algorithm(name: &str) -> bool {
    matches!(
        name,
        XFRM_AEAD_RFC4106_GCM_AES | "rfc4543(gcm(aes))" | "rfc7539esp(chacha20,poly1305)"
    )
}

fn validate_policy_parameters(parameters: &PolicyParameters) -> Result<(), XfrmError> {
    validate_selector_family(&parameters.selector)?;
    if matches!(parameters.action, XfrmAction::Allow) && parameters.templates.is_empty() {
        return Err(XfrmError::invalid_config(
            "templates",
            "allow policy requires at least one template",
        ));
    }
    for template in &parameters.templates {
        if template.id.spi == 0 {
            return Err(XfrmError::invalid_config(
                "template.spi",
                "spi must be nonzero",
            ));
        }
        if template.id.protocol == 0 {
            return Err(XfrmError::invalid_config(
                "template.protocol",
                "protocol must be nonzero",
            ));
        }
    }
    Ok(())
}

fn validate_selector_family(selector: &XfrmSelector) -> Result<(), XfrmError> {
    validate_same_family(selector.source, selector.destination, "selector.family")?;
    let prefix_limit = if selector.source.is_ipv4() { 32 } else { 128 };
    if selector.source_prefix_len > prefix_limit {
        return Err(XfrmError::invalid_config(
            "selector.source_prefix_len",
            "prefix length exceeds address family",
        ));
    }
    if selector.destination_prefix_len > prefix_limit {
        return Err(XfrmError::invalid_config(
            "selector.destination_prefix_len",
            "prefix length exceeds address family",
        ));
    }
    Ok(())
}

fn validate_same_family(
    left: IpAddress,
    right: IpAddress,
    field: &'static str,
) -> Result<(), XfrmError> {
    if address_family(left) != address_family(right) {
        return Err(XfrmError::invalid_config(
            field,
            "addresses must use the same family",
        ));
    }
    Ok(())
}

fn validate_spi_range(min_spi: u32, max_spi: u32) -> Result<(), XfrmError> {
    if min_spi > max_spi {
        return Err(XfrmError::invalid_config(
            "min_spi",
            "min_spi must not exceed max_spi",
        ));
    }
    if max_spi == 0 {
        return Err(XfrmError::invalid_config(
            "max_spi",
            "max_spi must be nonzero",
        ));
    }
    Ok(())
}

fn validate_key_material(key: &[u8]) -> Result<(), XfrmError> {
    if key.is_empty() {
        return Err(XfrmError::invalid_config(
            "key_material",
            "key material must be nonempty",
        ));
    }
    let _ = key_len_bits(key)?;
    Ok(())
}

fn key_len_bits(key: &[u8]) -> Result<u32, XfrmError> {
    let bits = key
        .len()
        .checked_mul(8)
        .ok_or_else(|| XfrmError::invalid_config("key_material", "key length overflow"))?;
    u32::try_from(bits)
        .map_err(|_| XfrmError::invalid_config("key_material", "key length overflow"))
}

fn encode_algorithm_name(name: &str) -> Result<[u8; XFRM_ALG_NAME_LEN], XfrmError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(XfrmError::invalid_config(
            "algorithm.name",
            "algorithm name must be nonempty",
        ));
    }
    if bytes.contains(&0) {
        return Err(XfrmError::invalid_config(
            "algorithm.name",
            "algorithm name must not contain NUL",
        ));
    }
    if bytes.len() >= XFRM_ALG_NAME_LEN {
        return Err(XfrmError::invalid_config(
            "algorithm.name",
            "algorithm name is too long",
        ));
    }
    let mut out = [0_u8; XFRM_ALG_NAME_LEN];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

fn address_family(address: IpAddress) -> u16 {
    match address {
        IpAddress::Ipv4(_) => AF_INET,
        IpAddress::Ipv6(_) => AF_INET6,
    }
}

fn encode_address(out: &mut Vec<u8>, address: IpAddress) {
    match address {
        IpAddress::Ipv4(octets) => {
            out.extend_from_slice(&octets);
            out.resize(out.len() + 12, 0);
        }
        IpAddress::Ipv6(octets) => out.extend_from_slice(&octets),
    }
}

fn encode_xfrm_id(out: &mut Vec<u8>, destination: IpAddress, protocol: u8, spi: u32) {
    encode_address(out, destination);
    push_u32_be(out, spi);
    push_u8(out, protocol);
    out.resize(out.len() + 3, 0);
}

fn encode_mode(mode: XfrmMode) -> u8 {
    match mode {
        XfrmMode::Transport => 0,
        XfrmMode::Tunnel => 1,
        XfrmMode::Beet => 4,
    }
}

fn encode_direction(direction: XfrmDirection) -> u8 {
    match direction {
        XfrmDirection::In => XFRM_POLICY_IN,
        XfrmDirection::Out => XFRM_POLICY_OUT,
        XfrmDirection::Forward => XFRM_POLICY_FWD,
    }
}

fn encode_action(action: XfrmAction) -> u8 {
    match action {
        XfrmAction::Allow => XFRM_POLICY_ALLOW,
        XfrmAction::Block => XFRM_POLICY_BLOCK,
    }
}

fn push_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn push_u16_ne(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn push_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u32_ne(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn push_i32_ne(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn push_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64_ne(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_ne_bytes());
}

fn read_u16_ne(bytes: &[u8], offset: usize) -> Result<u16, XfrmError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("offset overflow")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("short netlink field")))?;
    Ok(u16::from_ne_bytes([slice[0], slice[1]]))
}

fn read_u32_ne(bytes: &[u8], offset: usize) -> Result<u32, XfrmError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("offset overflow")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("short netlink field")))?;
    Ok(u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{
        AeadAlgorithm, Algorithm, AuthAlgorithm, InstallSaRequest, KeyMaterial,
        XFRM_AUTH_HMAC_SHA256, XFRM_ENCR_CBC_AES,
    };

    #[derive(Debug, Default, Clone)]
    struct CapturingTransport {
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        response: Option<Vec<u8>>,
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

    impl LinuxXfrmTransport for CapturingTransport {
        fn transact(
            &self,
            _operation: &'static str,
            request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<Vec<u8>>, XfrmError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request.to_vec());
            Ok(self.response.clone())
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: true,
                net_admin_capable: true,
                algorithms: XfrmCapability::Available,
                details: Some("test transport"),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct SlowTransport {
        delay: Duration,
    }

    impl LinuxXfrmTransport for SlowTransport {
        fn transact(
            &self,
            _operation: &'static str,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<Vec<u8>>, XfrmError> {
            std::thread::sleep(self.delay);
            Ok(None)
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: true,
                net_admin_capable: true,
                algorithms: XfrmCapability::Available,
                details: Some("slow test transport"),
            }
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn selector() -> XfrmSelector {
        XfrmSelector::new(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 50)
    }

    fn sa_parameters() -> SaParameters {
        SaParameters {
            selector: selector(),
            id: XfrmId {
                destination: ipv4(10, 0, 0, 2),
                spi: 0x1234_5678,
                protocol: 50,
            },
            source_address: ipv4(10, 0, 0, 1),
            auth: Some((
                AuthAlgorithm::hmac_sha256(96),
                KeyMaterial::new(vec![0xab; 32]),
            )),
            crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0xcd; 16]))),
            aead: None,
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 32,
            encap: None,
            mark: None,
            if_id: None,
        }
    }

    fn policy_parameters() -> PolicyParameters {
        PolicyParameters {
            selector: selector(),
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 100,
            templates: vec![XfrmTemplate {
                id: sa_parameters().id,
                source_address: ipv4(10, 0, 0, 1),
                mode: XfrmMode::Tunnel,
            }],
            mark: None,
            if_id: None,
        }
    }

    fn ack(sequence: u32) -> Vec<u8> {
        let mut body = Vec::new();
        push_i32_ne(&mut body, 0);
        encode_netlink_message(NLMSG_ERROR, 0, sequence, &body)
            .unwrap()
            .to_vec()
    }

    fn route_attr_payload(body: &[u8], attr_type: u16) -> Option<&[u8]> {
        route_attr_payload_from(body, XFRM_USER_SA_INFO_LEN, attr_type)
    }

    fn route_attr_payload_from(body: &[u8], mut offset: usize, attr_type: u16) -> Option<&[u8]> {
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

    fn assert_sensitive_buffer(_buffer: &SensitiveBuffer) {}

    #[test]
    fn encodes_sa_install_with_auth_and_crypt_attrs() {
        let body = encode_sa_info(&sa_parameters()).unwrap();
        assert_sensitive_buffer(&body);

        assert_eq!(&body[0..4], &[10, 0, 0, 2]);
        assert_eq!(&body[16..20], &[10, 0, 0, 1]);
        assert_eq!(&body[72..76], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(body[76], 50);
        assert_eq!(&body[80..84], &[10, 0, 0, 1]);
        assert_eq!(u16::from_ne_bytes([body[212], body[213]]), AF_INET);
        assert_eq!(body[214], 1);
        assert_eq!(body[215], 32);
        assert!(body.len() > XFRM_USER_SA_INFO_LEN);
        assert!(body[XFRM_USER_SA_INFO_LEN..]
            .windows(XFRM_AUTH_HMAC_SHA256.len())
            .any(|w| w == XFRM_AUTH_HMAC_SHA256.as_bytes()));
        assert!(body[XFRM_USER_SA_INFO_LEN..]
            .windows(XFRM_ENCR_CBC_AES.len())
            .any(|w| w == XFRM_ENCR_CBC_AES.as_bytes()));
    }

    #[test]
    fn encodes_sa_install_with_aead_attr() {
        let mut params = sa_parameters();
        params.auth = None;
        params.crypt = None;
        params.aead = Some((
            AeadAlgorithm::rfc4106_gcm_aes(128),
            KeyMaterial::new(vec![0xcd; 36]),
        ));

        let body = encode_sa_info(&params).unwrap();
        assert_sensitive_buffer(&body);
        let payload = route_attr_payload(&body, XFRMA_ALG_AEAD).expect("aead attr");

        assert_eq!(payload.len(), XFRM_ALGO_AEAD_HEADER_LEN + 36);
        assert_eq!(
            &payload[..XFRM_ALG_NAME_LEN],
            &encode_algorithm_name(XFRM_AEAD_RFC4106_GCM_AES).unwrap()
        );
        assert_eq!(
            u32::from_ne_bytes([
                payload[XFRM_ALG_NAME_LEN],
                payload[XFRM_ALG_NAME_LEN + 1],
                payload[XFRM_ALG_NAME_LEN + 2],
                payload[XFRM_ALG_NAME_LEN + 3],
            ]),
            36 * 8
        );
        assert_eq!(
            u32::from_ne_bytes([
                payload[XFRM_ALG_NAME_LEN + 4],
                payload[XFRM_ALG_NAME_LEN + 5],
                payload[XFRM_ALG_NAME_LEN + 6],
                payload[XFRM_ALG_NAME_LEN + 7],
            ]),
            128
        );
        assert_eq!(&payload[XFRM_ALGO_AEAD_HEADER_LEN..], &[0xcd; 36]);
        assert!(route_attr_payload(&body, XFRMA_ALG_CRYPT).is_none());
        assert_eq!(body.len() % 4, 0);
    }

    #[test]
    fn encodes_sa_install_with_udp_encap_mark_and_if_id_attrs() {
        let mut params = sa_parameters();
        params.encap = Some(UdpEncap::esp_in_udp(4500, 4500));
        params.mark = Some(XfrmMark {
            value: 0x1234_5678,
            mask: 0xffff_0000,
        });
        params.if_id = Some(7);

        let body = encode_sa_info(&params).unwrap();
        let encap = route_attr_payload(&body, XFRMA_ENCAP).expect("encap attr");
        let mark = route_attr_payload(&body, XFRMA_MARK).expect("mark attr");
        let if_id = route_attr_payload(&body, XFRMA_IF_ID).expect("if_id attr");

        assert_eq!(encap.len(), XFRM_ENCAP_TEMPLATE_LEN);
        assert_eq!(
            u16::from_ne_bytes([encap[0], encap[1]]),
            crate::model::UDP_ENCAP_ESPINUDP
        );
        assert_eq!(u16::from_be_bytes([encap[2], encap[3]]), 4500);
        assert_eq!(u16::from_be_bytes([encap[4], encap[5]]), 4500);
        assert_eq!(&encap[8..], &[0_u8; 16]);
        assert_eq!(mark, &encode_mark(params.mark.unwrap()));
        assert_eq!(if_id, &7_u32.to_ne_bytes());
    }

    #[test]
    fn encodes_policy_with_mark_and_if_id_attrs() {
        let mut params = policy_parameters();
        params.mark = Some(XfrmMark {
            value: 0x0000_0042,
            mask: 0xffff_ffff,
        });
        params.if_id = Some(9);

        let body = encode_policy_info(&params).unwrap();
        let mark = route_attr_payload_from(&body, XFRM_USER_POLICY_INFO_LEN, XFRMA_MARK)
            .expect("policy mark attr");
        let if_id = route_attr_payload_from(&body, XFRM_USER_POLICY_INFO_LEN, XFRMA_IF_ID)
            .expect("policy if_id attr");

        assert_eq!(mark, &encode_mark(params.mark.unwrap()));
        assert_eq!(if_id, &9_u32.to_ne_bytes());
    }

    #[test]
    fn rejects_aead_name_in_crypt_slot() {
        let mut params = sa_parameters();
        params.auth = None;
        params.crypt = Some((
            Algorithm::new(XFRM_AEAD_RFC4106_GCM_AES),
            KeyMaterial::new(vec![0xcd; 36]),
        ));

        let error = encode_sa_info(&params).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "crypt",
                reason: "aead algorithm must use the aead slot"
            }
        ));
    }

    #[test]
    fn rejects_mixed_aead_and_auth_or_crypt() {
        let mut params = sa_parameters();
        params.aead = Some((
            AeadAlgorithm::rfc4106_gcm_aes(128),
            KeyMaterial::new(vec![0xcd; 36]),
        ));

        let error = encode_sa_info(&params).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "aead",
                reason: "aead is mutually exclusive with auth/crypt"
            }
        ));
    }

    #[test]
    fn rejects_zero_aead_icv_length() {
        let mut params = sa_parameters();
        params.auth = None;
        params.crypt = None;
        params.aead = Some((
            AeadAlgorithm::rfc4106_gcm_aes(0),
            KeyMaterial::new(vec![0xcd; 36]),
        ));

        let error = encode_sa_info(&params).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "aead.icv_len_bits",
                reason: "icv length must be nonzero"
            }
        ));
    }

    #[test]
    fn rejects_replay_window_above_legacy_bitmap_limit() {
        let mut params = sa_parameters();
        params.replay_window = 33;

        let error = encode_sa_info(&params).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "replay_window",
                reason: "replay window >32 requires ESN support"
            }
        ));
    }

    #[test]
    fn encodes_policy_with_template_attr() {
        let body = encode_policy_info(&policy_parameters()).unwrap();

        assert_eq!(&body[0..4], &[10, 0, 0, 2]);
        assert_eq!(
            u32::from_ne_bytes([body[152], body[153], body[154], body[155]]),
            100
        );
        assert_eq!(body[160], XFRM_POLICY_OUT);
        assert_eq!(body[161], XFRM_POLICY_ALLOW);
        assert_eq!(
            u16::from_ne_bytes([body[168], body[169]]) as usize,
            ROUTE_ATTRIBUTE_HEADER_LEN + XFRM_USER_TEMPLATE_LEN
        );
        assert_eq!(u16::from_ne_bytes([body[170], body[171]]), XFRMA_TMPL);
    }

    #[tokio::test]
    async fn backend_sends_install_and_remove_messages() {
        let transport = CapturingTransport::default();
        let backend = LinuxXfrmBackend::with_transport(transport.clone());

        backend
            .install_sa(InstallSaRequest {
                parameters: sa_parameters(),
            })
            .await
            .unwrap();
        backend
            .remove_policy(RemovePolicyRequest {
                selector: selector(),
                direction: XfrmDirection::Out,
            })
            .await
            .unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            u16::from_ne_bytes([requests[0][4], requests[0][5]]),
            XFRM_MSG_NEWSA
        );
        assert_eq!(
            u16::from_ne_bytes([requests[0][6], requests[0][7]]),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        assert_eq!(
            u16::from_ne_bytes([requests[1][4], requests[1][5]]),
            XFRM_MSG_DELPOLICY
        );
        assert_eq!(
            requests[1].len(),
            NETLINK_HEADER_LEN + XFRM_USER_POLICY_ID_LEN
        );
    }

    #[test]
    fn backend_transaction_does_not_block_current_thread_runtime() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let backend = LinuxXfrmBackend::with_transport(SlowTransport {
                delay: Duration::from_millis(100),
            });
            let install_backend = backend.clone();

            let install = tokio::spawn(async move {
                install_backend
                    .install_sa(InstallSaRequest {
                        parameters: sa_parameters(),
                    })
                    .await
            });

            let tick = tokio::time::timeout(
                Duration::from_millis(50),
                tokio::time::sleep(Duration::from_millis(10)),
            )
            .await;
            assert!(tick.is_ok(), "runtime ticker was stalled by XFRM transact");

            install.await.unwrap().unwrap();
        });
    }

    #[tokio::test]
    async fn allocate_spi_parses_kernel_response_spi() {
        let mut response = vec![0_u8; XFRM_USER_SA_INFO_LEN];
        response[XFRM_SPI_OFFSET_IN_SA_INFO..XFRM_SPI_OFFSET_IN_SA_INFO + 4]
            .copy_from_slice(&0x8765_4321_u32.to_be_bytes());
        let transport = CapturingTransport::with_response(response);
        let backend = LinuxXfrmBackend::with_transport(transport);

        let allocation = backend
            .allocate_spi(AllocateSpiRequest {
                destination: ipv4(10, 0, 0, 2),
                protocol: 50,
                min_spi: 0x100,
                max_spi: 0xffff_ffff,
            })
            .await
            .unwrap();

        assert_eq!(allocation.spi, 0x8765_4321);
    }

    #[test]
    fn netlink_ack_errors_map_to_stable_errors() {
        let mut body = Vec::new();
        push_i32_ne(&mut body, -17);
        let message = encode_netlink_message(NLMSG_ERROR, 0, 9, &body).unwrap();

        let error = parse_netlink_response(&message, 9).unwrap_err();

        assert!(matches!(error, XfrmError::AlreadyExists));

        let mut body = Vec::new();
        push_i32_ne(&mut body, -ESRCH);
        let message = encode_netlink_message(NLMSG_ERROR, 0, 10, &body).unwrap();

        let error = parse_netlink_response(&message, 10).unwrap_err();

        assert!(matches!(error, XfrmError::NotFound));
    }

    #[test]
    fn netlink_ack_uncategorized_errno_preserves_raw_os_error() {
        // EAFNOSUPPORT (97) has no dedicated io::ErrorKind mapping, so it hits
        // the fallback arm; the raw errno must survive for caller diagnostics.
        let mut body = Vec::new();
        push_i32_ne(&mut body, -97);
        let message = encode_netlink_message(NLMSG_ERROR, 0, 11, &body).unwrap();

        let error = parse_netlink_response(&message, 11).unwrap_err();

        assert_eq!(error.raw_os_error(), Some(97));
        let display = error.to_string();
        assert!(display.contains("netlink_ack"));
        assert!(display.contains("os error 97"));
    }

    #[test]
    fn netlink_ack_sequence_mismatch_is_redaction_safe() {
        let error = parse_netlink_response(&ack(10), 9).unwrap_err();

        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(!debug.contains("1234"));
        assert!(!display.contains("1234"));
    }

    #[test]
    fn invalid_key_material_does_not_leak_key_bytes() {
        let mut params = sa_parameters();
        params.crypt = Some((Algorithm::cbc_aes(), KeyMaterial::new(Vec::new())));

        let error = encode_sa_info(&params).unwrap_err();

        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(!debug.contains("cd"));
        assert!(!display.contains("cd"));
    }

    #[test]
    fn algorithm_encoders_return_zeroizing_buffers() {
        let crypt = encode_algorithm(XFRM_ENCR_CBC_AES, &[0xcd; 16]).unwrap();
        let auth = encode_auth_algorithm(XFRM_AUTH_HMAC_SHA256, &[0xab; 32], 96).unwrap();
        let aead = encode_aead_algorithm(XFRM_AEAD_RFC4106_GCM_AES, &[0xef; 36], 128).unwrap();

        assert_sensitive_buffer(&crypt);
        assert_sensitive_buffer(&auth);
        assert_sensitive_buffer(&aead);
    }

    #[test]
    fn parses_successful_ack() {
        assert_eq!(parse_netlink_response(&ack(1), 1).unwrap(), None);
    }

    #[test]
    fn probe_uses_linux_kernel_kind() {
        let transport = CapturingTransport::default();
        let backend = LinuxXfrmBackend::with_transport(transport);

        let probe = futures_probe(&backend);

        assert_eq!(probe.kind, XfrmBackendKind::LinuxKernel);
        assert!(probe.kernel_reachable);
    }

    fn futures_probe(backend: &LinuxXfrmBackend) -> XfrmProbe {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async { backend.probe().await.unwrap() })
    }
}
