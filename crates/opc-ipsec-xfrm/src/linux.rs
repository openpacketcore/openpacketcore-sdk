//! Safe Linux XFRM backend over the raw netlink sys boundary.

use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_ipsec_xfrm_ebpf_common::{MarkProfile, IPPROTO_ESP};
use opc_linux_xfrm_sys::{
    align_to_netlink, open_netlink_socket, receive_message, send_message, NLMSG_DONE, NLMSG_ERROR,
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST, XFRMA_ALG_AEAD,
    XFRMA_ALG_AUTH_TRUNC, XFRMA_ALG_CRYPT, XFRMA_ENCAP, XFRMA_IF_ID, XFRMA_MARK,
    XFRMA_REPLAY_ESN_VAL, XFRMA_REPLAY_VAL, XFRMA_SET_MARK, XFRMA_SET_MARK_MASK, XFRMA_TMPL,
    XFRM_MSG_ALLOCSPI, XFRM_MSG_DELPOLICY, XFRM_MSG_DELSA, XFRM_MSG_GETSA, XFRM_MSG_NEWPOLICY,
    XFRM_MSG_NEWSA, XFRM_MSG_UPDPOLICY, XFRM_MSG_UPDSA, XFRM_POLICY_ALLOW, XFRM_POLICY_BLOCK,
    XFRM_POLICY_FWD, XFRM_POLICY_IN, XFRM_POLICY_OUT, XFRM_STATE_ESN,
};
use zeroize::Zeroizing;

use crate::dscp::{production_runtime, LinuxXfrmDscpMarkingConfig, XfrmDscpRuntime};
use crate::{
    AllocateSpiRequest, DscpCodepoint, InstallPolicyRequest, InstallSaRequest, IpAddress,
    LifetimeConfig, LifetimeCurrent, PolicyParameters, QuerySaRequest, RekeyPolicyRequest,
    RekeySaRequest, RemovePolicyRequest, RemoveSaRequest, SaParameters, SaReplayState, SaState,
    SaStatistics, SpiAllocation, UdpEncap, XfrmAction, XfrmBackend, XfrmBackendKind,
    XfrmCapability, XfrmDirection, XfrmError, XfrmId, XfrmMark, XfrmMode, XfrmProbe, XfrmRequestId,
    XfrmSelector, XfrmTemplate, XFRM_AEAD_RFC4106_GCM_AES,
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
const XFRM_REPLAY_STATE_LEN: usize = 12;
const XFRM_REPLAY_STATE_ESN_BASE_LEN: usize = 24;
const XFRM_SPI_OFFSET_IN_SA_INFO: usize = XFRM_SELECTOR_LEN + XFRM_ADDRESS_LEN;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const XFRM_INF: u64 = u64::MAX;
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const CAP_NET_ADMIN_BIT: u32 = 12;

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
    dscp_config: Option<LinuxXfrmDscpMarkingConfig>,
    dscp_runtime: Arc<dyn XfrmDscpRuntime>,
    dscp_xfrm_attributes_verified: AtomicBool,
}

impl fmt::Debug for LinuxXfrmBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxXfrmBackend")
            .field("config", &self.inner.config)
            .field("dscp_marking_configured", &self.inner.dscp_config.is_some())
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
                dscp_config: None,
                dscp_runtime: production_runtime(),
                dscp_xfrm_attributes_verified: AtomicBool::new(false),
            }),
        }
    }

    /// Create a backend with the post-transform fixed-DSCP companion.
    ///
    /// Construction validates and eagerly attaches/adopts the tc programs on
    /// every configured interface. No SA carrying a DSCP token can be
    /// acknowledged until this succeeds.
    pub fn with_dscp_marking(dscp_config: LinuxXfrmDscpMarkingConfig) -> Result<Self, XfrmError> {
        Self::with_config_and_dscp_marking(LinuxXfrmBackendConfig::default(), dscp_config)
    }

    /// Create a backend with custom netlink and fixed-DSCP configuration.
    pub fn with_config_and_dscp_marking(
        config: LinuxXfrmBackendConfig,
        dscp_config: LinuxXfrmDscpMarkingConfig,
    ) -> Result<Self, XfrmError> {
        dscp_config.validate()?;
        let runtime = production_runtime();
        runtime.ensure_ready(&dscp_config)?;
        Ok(Self {
            inner: Arc::new(LinuxXfrmBackendInner {
                transport: Arc::new(NetlinkXfrmTransport),
                next_sequence: AtomicU32::new(1),
                config,
                dscp_config: Some(dscp_config),
                dscp_runtime: runtime,
                dscp_xfrm_attributes_verified: AtomicBool::new(false),
            }),
        })
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
                dscp_config: None,
                dscp_runtime: production_runtime(),
                dscp_xfrm_attributes_verified: AtomicBool::new(false),
            }),
        }
    }

    #[cfg(test)]
    fn with_transport_and_dscp_runtime<T, R>(
        transport: T,
        dscp_config: LinuxXfrmDscpMarkingConfig,
        dscp_runtime: R,
    ) -> Result<Self, XfrmError>
    where
        T: LinuxXfrmTransport + 'static,
        R: XfrmDscpRuntime + 'static,
    {
        dscp_config.validate()?;
        dscp_runtime.ensure_ready(&dscp_config)?;
        Ok(Self {
            inner: Arc::new(LinuxXfrmBackendInner {
                transport: Arc::new(transport),
                next_sequence: AtomicU32::new(1),
                config: LinuxXfrmBackendConfig {
                    receive_attempts: 1,
                    receive_buffer_len: 4096,
                    retry_delay: Duration::ZERO,
                },
                dscp_config: Some(dscp_config),
                dscp_runtime: Arc::new(dscp_runtime),
                dscp_xfrm_attributes_verified: AtomicBool::new(false),
            }),
        })
    }

    fn prepare_dscp(&self, parameters: &SaParameters) -> Result<Option<MarkProfile>, XfrmError> {
        let Some(dscp) = parameters.egress_dscp else {
            return Ok(None);
        };
        let config = self
            .inner
            .dscp_config
            .as_ref()
            .ok_or(XfrmError::UnsupportedFeature {
                feature: "fixed_outer_dscp",
            })?;
        let profile = config.profile()?;
        validate_fixed_outer_dscp(parameters, profile, dscp)?;
        // Revalidate actual map/filter ownership for every marked mutation so
        // runtime readiness loss is repaired or reported before XFRM ACK.
        self.inner.dscp_runtime.ensure_ready(config)?;
        Ok(Some(profile))
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
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
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
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
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

    async fn verify_dscp_readback(
        &self,
        parameters: &SaParameters,
        profile: MarkProfile,
        operation: &'static str,
    ) -> Result<(), XfrmError> {
        let indeterminate = || XfrmError::StateIndeterminate { operation };
        let body = encode_sa_id(
            parameters.id.destination,
            parameters.id.protocol,
            parameters.id.spi,
            parameters.mark,
        )
        .map_err(|_| indeterminate())?;
        let response = self
            .transact_blocking(operation, XFRM_MSG_GETSA, NLM_F_REQUEST | NLM_F_ACK, body)
            .await
            .map_err(|_| indeterminate())?
            .ok_or_else(indeterminate)?;
        let state = parse_sa_state(&response, Some(profile)).map_err(|_| indeterminate())?;
        if state.id != parameters.id
            || state.selector != parameters.selector
            || state.source_address != parameters.source_address
            || state.request_id != parameters.request_id
            || state.mode != parameters.mode
            || state.replay_window != parameters.replay_window
            || state.lifetime_config != parameters.lifetime
            || state.egress_dscp != parameters.egress_dscp
        {
            return Err(indeterminate());
        }
        self.inner
            .dscp_xfrm_attributes_verified
            .store(true, Ordering::Release);
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
        let profile = self.prepare_dscp(&request.parameters)?;
        let body = encode_sa_info_with_dscp(&request.parameters, profile)?;
        self.run_ack(
            "install_sa",
            XFRM_MSG_NEWSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )
        .await?;
        if let Some(profile) = profile {
            // The ACK linearizes acceptance of this NEWSA request, while the
            // subsequent redacted GETSA proves only the current identity and
            // output-mark attributes. It cannot establish cryptographic
            // ownership, and an external UPDSA may race after the ACK. Never
            // issue a compensating DELSA on readback failure: that could
            // delete a newer same-identity SA installed by another writer.
            self.verify_dscp_readback(&request.parameters, profile, "install_sa_dscp_readback")
                .await?;
        }
        Ok(())
    }

    async fn query_sa(&self, request: QuerySaRequest) -> Result<SaState, XfrmError> {
        validate_sa_query(request)?;
        let body = encode_sa_id(
            request.destination,
            request.protocol,
            request.spi,
            request.mark,
        )?;
        let response = self
            .transact_blocking("query_sa", XFRM_MSG_GETSA, NLM_F_REQUEST | NLM_F_ACK, body)
            .await?
            .ok_or_else(|| XfrmError::io("query_sa", invalid_data("missing getsa response")))?;
        let profile = self
            .inner
            .dscp_config
            .as_ref()
            .map(LinuxXfrmDscpMarkingConfig::profile)
            .transpose()?;
        let state = parse_sa_state(&response, profile)?;
        if state.egress_dscp.is_some() {
            self.inner
                .dscp_xfrm_attributes_verified
                .store(true, Ordering::Release);
        }
        Ok(state)
    }

    async fn rekey_sa(&self, request: RekeySaRequest) -> Result<(), XfrmError> {
        let profile = self.prepare_dscp(&request.parameters)?;
        let body = encode_sa_info_with_dscp(&request.parameters, profile)?;
        self.run_ack(
            "rekey_sa",
            XFRM_MSG_UPDSA,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE,
            body,
        )
        .await?;
        if let Some(profile) = profile {
            // An update replaces pre-existing state, and `SaState`
            // intentionally excludes key material, so a safe automatic
            // rollback cannot reconstruct the old SA. Any failed mandatory
            // readback therefore remains explicitly indeterminate.
            self.verify_dscp_readback(&request.parameters, profile, "rekey_sa_dscp_readback")
                .await?;
        }
        Ok(())
    }

    async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError> {
        let body = encode_sa_id(
            request.destination,
            request.protocol,
            request.spi,
            request.mark,
        )?;
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
        let body = encode_policy_id(&request.selector, request.direction, request.mark)?;
        self.run_ack(
            "remove_policy",
            XFRM_MSG_DELPOLICY,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )
        .await
    }

    async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
        let mut probe = self.inner.transport.probe(self.inner.config);
        probe.egress_dscp_marking =
            self.inner
                .dscp_config
                .as_ref()
                .map_or(XfrmCapability::Missing, |config| {
                    let companion = self.inner.dscp_runtime.capability(config);
                    if companion == XfrmCapability::Available
                        && !self
                            .inner
                            .dscp_xfrm_attributes_verified
                            .load(Ordering::Acquire)
                    {
                        XfrmCapability::Unknown
                    } else {
                        companion
                    }
                });
        Ok(probe)
    }
}

trait LinuxXfrmTransport: Send + Sync + fmt::Debug {
    fn transact(
        &self,
        operation: &'static str,
        request: &[u8],
        expected_sequence: u32,
        config: LinuxXfrmBackendConfig,
    ) -> Result<Option<SensitiveBuffer>, XfrmError>;

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
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
        let socket = open_netlink_socket().map_err(|error| map_open_error(operation, error))?;
        let sent =
            send_message(&socket, request).map_err(|error| XfrmError::io("netlink_send", error))?;
        if sent != request.len() {
            return Err(XfrmError::io(
                "netlink_send",
                io::Error::new(io::ErrorKind::WriteZero, "short netlink send"),
            ));
        }

        let mut buffer = Zeroizing::new(vec![0_u8; config.receive_buffer_len]);
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
            Ok(_) => {
                let net_admin_capable = process_has_cap_net_admin();
                XfrmProbe {
                    kind: XfrmBackendKind::LinuxKernel,
                    platform_supported: true,
                    kernel_reachable: true,
                    net_admin_capable: net_admin_capable.unwrap_or(false),
                    algorithms: if net_admin_capable == Some(false) {
                        XfrmCapability::PermissionDenied
                    } else {
                        XfrmCapability::Available
                    },
                    egress_dscp_marking: XfrmCapability::Missing,
                    details: match net_admin_capable {
                        Some(true) => {
                            Some("linux XFRM netlink socket reachable with CAP_NET_ADMIN")
                        }
                        Some(false) => {
                            Some("linux XFRM netlink socket reachable without CAP_NET_ADMIN")
                        }
                        None => Some("linux XFRM netlink socket reachable; CAP_NET_ADMIN unknown"),
                    },
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Unsupported => XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: false,
                kernel_reachable: false,
                net_admin_capable: false,
                algorithms: XfrmCapability::Unknown,
                egress_dscp_marking: XfrmCapability::Missing,
                details: Some("linux XFRM netlink unsupported on this platform"),
            },
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: false,
                net_admin_capable: false,
                algorithms: XfrmCapability::PermissionDenied,
                egress_dscp_marking: XfrmCapability::Missing,
                details: Some("linux XFRM netlink permission denied"),
            },
            Err(_) => XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: false,
                net_admin_capable: false,
                algorithms: XfrmCapability::Unknown,
                egress_dscp_marking: XfrmCapability::Missing,
                details: Some("linux XFRM netlink socket unavailable"),
            },
        }
    }
}

fn process_has_cap_net_admin() -> Option<bool> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_cap_net_admin_from_status(&status)
}

fn parse_cap_net_admin_from_status(status: &str) -> Option<bool> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    let effective = u64::from_str_radix(value, 16).ok()?;
    Some((effective & (1_u64 << CAP_NET_ADMIN_BIT)) != 0)
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
) -> Result<Option<SensitiveBuffer>, XfrmError> {
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
        _ => Ok(Some(Zeroizing::new(body.to_vec()))),
    }
}

fn parse_netlink_error(body: &[u8]) -> Result<Option<SensitiveBuffer>, XfrmError> {
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
        request_id: None,
        auth: None,
        crypt: None,
        aead: None,
        mode: XfrmMode::Tunnel,
        lifetime: LifetimeConfig::default(),
        replay_window: 0,
        replay_state: None,
        encap: None,
        mark: None,
        if_id: None,
        egress_dscp: None,
    };

    let mut out = encode_sa_info_inner(&sa, true, None)?;
    debug_assert_eq!(out.len(), XFRM_USER_SA_INFO_LEN);
    push_u32_ne(&mut out, request.min_spi);
    push_u32_ne(&mut out, request.max_spi);
    debug_assert_eq!(out.len(), XFRM_USER_SPI_INFO_LEN);
    Ok(out)
}

#[cfg(test)]
fn encode_sa_info(parameters: &SaParameters) -> Result<SensitiveBuffer, XfrmError> {
    if parameters.egress_dscp.is_some() {
        return Err(XfrmError::UnsupportedFeature {
            feature: "fixed_outer_dscp",
        });
    }
    encode_sa_info_inner(parameters, false, None)
}

fn encode_sa_info_with_dscp(
    parameters: &SaParameters,
    profile: Option<MarkProfile>,
) -> Result<SensitiveBuffer, XfrmError> {
    encode_sa_info_inner(parameters, false, profile)
}

fn encode_sa_info_inner(
    parameters: &SaParameters,
    allow_zero_spi: bool,
    dscp_profile: Option<MarkProfile>,
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
    push_u32_ne(
        &mut out,
        parameters
            .replay_state
            .as_ref()
            .map(|state| state.inbound_sequence)
            .unwrap_or(0),
    );
    push_u32_ne(
        &mut out,
        parameters.request_id.map_or(0, XfrmRequestId::get),
    );
    push_u16_ne(&mut out, family);
    push_u8(&mut out, encode_mode(parameters.mode));
    push_u8(
        &mut out,
        parameters.replay_window.min(u32::from(u8::MAX)) as u8,
    );
    push_u8(&mut out, encode_sa_flags(parameters));
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
    append_replay_state_attr(&mut out, parameters)?;
    append_common_attrs(&mut out, parameters.mark, parameters.if_id)?;
    match (parameters.egress_dscp, dscp_profile) {
        (Some(dscp), Some(profile)) => {
            validate_fixed_outer_dscp(parameters, profile, dscp)?;
            let token = profile.encode_token(dscp.get()).ok_or_else(|| {
                XfrmError::invalid_config("sa.egress_dscp", "DSCP must be between 0 and 63")
            })?;
            append_attr(&mut out, XFRMA_SET_MARK, &token.to_ne_bytes())?;
            append_attr(&mut out, XFRMA_SET_MARK_MASK, &profile.mask.to_ne_bytes())?;
        }
        (Some(_), None) => {
            return Err(XfrmError::UnsupportedFeature {
                feature: "fixed_outer_dscp",
            });
        }
        (None, _) => {}
    }
    Ok(out)
}

fn encode_sa_id(
    destination: IpAddress,
    protocol: u8,
    spi: u32,
    mark: Option<XfrmMark>,
) -> Result<SensitiveBuffer, XfrmError> {
    if spi == 0 {
        return Err(XfrmError::invalid_config("spi", "spi must be nonzero"));
    }
    let mut out = sensitive_buffer_with_capacity(
        XFRM_USER_SA_ID_LEN + mark.map_or(0, |_| ROUTE_ATTRIBUTE_HEADER_LEN + XFRM_MARK_LEN),
    );
    encode_address(&mut out, destination);
    push_u32_be(&mut out, spi);
    push_u16_ne(&mut out, address_family(destination));
    push_u8(&mut out, protocol);
    out.resize(XFRM_USER_SA_ID_LEN, 0);
    if let Some(mark) = mark {
        append_attr(&mut out, XFRMA_MARK, &encode_mark(mark))?;
    }
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
    mark: Option<XfrmMark>,
) -> Result<SensitiveBuffer, XfrmError> {
    validate_selector_family(selector)?;
    let mut out = sensitive_buffer_with_capacity(XFRM_USER_POLICY_ID_LEN);
    encode_selector(&mut out, selector)?;
    push_u32_ne(&mut out, 0);
    push_u8(&mut out, encode_direction(direction));
    out.resize(XFRM_USER_POLICY_ID_LEN, 0);
    append_common_attrs(&mut out, mark, None)?;
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
    push_u32_ne(out, template.request_id.map_or(0, XfrmRequestId::get));
    push_u8(out, encode_mode(template.mode));
    push_u8(out, 0);
    push_u8(out, 0);
    out.resize(start + 52, 0);
    push_u32_ne(out, u32::MAX);
    push_u32_ne(out, u32::MAX);
    push_u32_ne(out, u32::MAX);
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

fn encode_sa_flags(parameters: &SaParameters) -> u8 {
    if parameters.replay_window > 32
        || parameters
            .replay_state
            .as_ref()
            .map(|state| state.esn)
            .unwrap_or(false)
    {
        XFRM_STATE_ESN
    } else {
        0
    }
}

fn append_replay_state_attr(out: &mut Vec<u8>, parameters: &SaParameters) -> Result<(), XfrmError> {
    let state;
    let replay_state = if let Some(replay_state) = parameters.replay_state.as_ref() {
        replay_state
    } else if parameters.replay_window > 32 {
        state = SaReplayState::fresh(parameters.replay_window);
        &state
    } else {
        return Ok(());
    };

    validate_replay_state(replay_state, parameters.replay_window)?;
    if replay_state.esn {
        append_attr(
            out,
            XFRMA_REPLAY_ESN_VAL,
            &encode_replay_state_esn(replay_state)?,
        )?;
    } else {
        append_attr(
            out,
            XFRMA_REPLAY_VAL,
            &encode_replay_state_legacy(replay_state)?,
        )?;
    }
    Ok(())
}

fn encode_replay_state_legacy(replay_state: &SaReplayState) -> Result<SensitiveBuffer, XfrmError> {
    if replay_state.esn {
        return Err(XfrmError::invalid_config(
            "replay_state.esn",
            "legacy replay state must not set ESN",
        ));
    }
    if replay_state.replay_window > 32 {
        return Err(XfrmError::invalid_config(
            "replay_state.replay_window",
            "legacy replay state supports at most 32 packets",
        ));
    }
    let bitmap = replay_state.bitmap.first().copied().unwrap_or(0);
    let mut out = sensitive_buffer_with_capacity(XFRM_REPLAY_STATE_LEN);
    push_u32_ne(&mut out, replay_state.outbound_sequence);
    push_u32_ne(&mut out, replay_state.inbound_sequence);
    push_u32_ne(&mut out, bitmap);
    Ok(out)
}

fn encode_replay_state_esn(replay_state: &SaReplayState) -> Result<SensitiveBuffer, XfrmError> {
    if !replay_state.esn {
        return Err(XfrmError::invalid_config(
            "replay_state.esn",
            "ESN replay state must set ESN",
        ));
    }
    let bitmap_words = u32::try_from(replay_state.bitmap.len()).map_err(|_| {
        XfrmError::invalid_config("replay_state.bitmap", "bitmap word count overflow")
    })?;
    let capacity = XFRM_REPLAY_STATE_ESN_BASE_LEN
        .checked_add(replay_state.bitmap.len().saturating_mul(4))
        .ok_or_else(|| {
            XfrmError::invalid_config("replay_state.bitmap", "bitmap length overflow")
        })?;
    let mut out = sensitive_buffer_with_capacity(capacity);
    push_u32_ne(&mut out, bitmap_words);
    push_u32_ne(&mut out, replay_state.outbound_sequence);
    push_u32_ne(&mut out, replay_state.inbound_sequence);
    push_u32_ne(&mut out, replay_state.outbound_sequence_hi);
    push_u32_ne(&mut out, replay_state.inbound_sequence_hi);
    push_u32_ne(&mut out, replay_state.replay_window);
    for word in &replay_state.bitmap {
        push_u32_ne(&mut out, *word);
    }
    Ok(out)
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

fn parse_sa_state(payload: &[u8], dscp_profile: Option<MarkProfile>) -> Result<SaState, XfrmError> {
    if payload.len() < XFRM_USER_SA_INFO_LEN {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("short getsa response"),
        ));
    }
    let selector = decode_selector(payload, 0)?;
    let destination = decode_address(payload, 56, read_u16_ne(payload, 212)?)?;
    let spi = read_u32_be(payload, 72)?;
    let protocol = read_u8(payload, 76)?;
    let source_address = decode_address(payload, 80, read_u16_ne(payload, 212)?)?;
    let lifetime_config = decode_lifetime_config(payload, 96)?;
    let lifetime_current = decode_lifetime_current(payload, 160)?;
    let statistics = decode_statistics(payload, 192)?;
    let sequence = read_u32_ne(payload, 204)?;
    let request_id = XfrmRequestId::new(read_u32_ne(payload, 208)?);
    let mode = decode_mode(read_u8(payload, 214)?)?;
    let replay_window = u32::from(read_u8(payload, 215)?);
    let flags = read_u8(payload, 216)?;
    let replay_state = parse_replay_state_attrs(
        payload,
        sequence,
        replay_window,
        flags & XFRM_STATE_ESN != 0,
    )?;
    let egress_dscp = parse_fixed_outer_dscp_attrs(payload, dscp_profile)?;
    Ok(SaState {
        selector,
        id: XfrmId {
            destination,
            spi,
            protocol,
        },
        source_address,
        request_id,
        mode,
        replay_window: replay_state.replay_window.max(replay_window),
        replay_state,
        lifetime_config,
        lifetime_current,
        statistics,
        egress_dscp,
    })
}

fn parse_fixed_outer_dscp_attrs(
    payload: &[u8],
    profile: Option<MarkProfile>,
) -> Result<Option<DscpCodepoint>, XfrmError> {
    let value = find_attr_payload(payload, XFRM_USER_SA_INFO_LEN, XFRMA_SET_MARK)?;
    let mask = find_attr_payload(payload, XFRM_USER_SA_INFO_LEN, XFRMA_SET_MARK_MASK)?;
    let Some(profile) = profile else {
        return if value.is_none() && mask.is_none() {
            Ok(None)
        } else {
            Err(XfrmError::UnsupportedFeature {
                feature: "unconfigured_output_mark_state",
            })
        };
    };
    let (Some(value), Some(mask)) = (value, mask) else {
        if value.is_some() || mask.is_some() {
            return Err(XfrmError::io(
                "query_sa",
                invalid_data("incomplete output-mark token attributes"),
            ));
        }
        return Ok(None);
    };
    if value.len() != 4 || mask.len() != 4 {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("invalid output-mark token attribute length"),
        ));
    }
    let value = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
    let mask = u32::from_ne_bytes([mask[0], mask[1], mask[2], mask[3]]);
    if mask != profile.mask {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("output-mark mask does not match configured DSCP profile"),
        ));
    }
    let opc_ipsec_xfrm_ebpf_common::MarkToken::Dscp(dscp) = profile.decode_token(value) else {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("malformed output-mark DSCP token"),
        ));
    };
    DscpCodepoint::new(dscp)
        .map(Some)
        .map_err(|_| XfrmError::io("query_sa", invalid_data("invalid DSCP token")))
}

fn parse_replay_state_attrs(
    payload: &[u8],
    sequence: u32,
    replay_window: u32,
    esn_flag: bool,
) -> Result<SaReplayState, XfrmError> {
    if let Some(attr) = find_attr_payload(payload, XFRM_USER_SA_INFO_LEN, XFRMA_REPLAY_ESN_VAL)? {
        return decode_replay_state_esn(attr);
    }
    if let Some(attr) = find_attr_payload(payload, XFRM_USER_SA_INFO_LEN, XFRMA_REPLAY_VAL)? {
        return decode_replay_state_legacy(attr, replay_window);
    }
    Ok(SaReplayState {
        esn: esn_flag,
        outbound_sequence: 0,
        inbound_sequence: sequence,
        outbound_sequence_hi: 0,
        inbound_sequence_hi: 0,
        replay_window,
        bitmap: Vec::new(),
    })
}

fn decode_replay_state_legacy(
    payload: &[u8],
    replay_window: u32,
) -> Result<SaReplayState, XfrmError> {
    if payload.len() != XFRM_REPLAY_STATE_LEN {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("invalid legacy replay state length"),
        ));
    }
    Ok(SaReplayState {
        esn: false,
        outbound_sequence: read_u32_ne(payload, 0)?,
        inbound_sequence: read_u32_ne(payload, 4)?,
        outbound_sequence_hi: 0,
        inbound_sequence_hi: 0,
        replay_window,
        bitmap: vec![read_u32_ne(payload, 8)?],
    })
}

fn decode_replay_state_esn(payload: &[u8]) -> Result<SaReplayState, XfrmError> {
    if payload.len() < XFRM_REPLAY_STATE_ESN_BASE_LEN {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("short ESN replay state"),
        ));
    }
    let bitmap_words = read_u32_ne(payload, 0)? as usize;
    let expected_len = XFRM_REPLAY_STATE_ESN_BASE_LEN
        .checked_add(bitmap_words.checked_mul(4).ok_or_else(|| {
            XfrmError::io(
                "query_sa",
                invalid_data("ESN replay bitmap length overflow"),
            )
        })?)
        .ok_or_else(|| XfrmError::io("query_sa", invalid_data("ESN replay length overflow")))?;
    if payload.len() != expected_len {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("invalid ESN replay state length"),
        ));
    }
    let mut bitmap = Vec::with_capacity(bitmap_words);
    let mut offset = XFRM_REPLAY_STATE_ESN_BASE_LEN;
    for _ in 0..bitmap_words {
        bitmap.push(read_u32_ne(payload, offset)?);
        offset += 4;
    }
    Ok(SaReplayState {
        esn: true,
        outbound_sequence: read_u32_ne(payload, 4)?,
        inbound_sequence: read_u32_ne(payload, 8)?,
        outbound_sequence_hi: read_u32_ne(payload, 12)?,
        inbound_sequence_hi: read_u32_ne(payload, 16)?,
        replay_window: read_u32_ne(payload, 20)?,
        bitmap,
    })
}

fn find_attr_payload(
    body: &[u8],
    mut offset: usize,
    attr_type: u16,
) -> Result<Option<&[u8]>, XfrmError> {
    while offset + ROUTE_ATTRIBUTE_HEADER_LEN <= body.len() {
        let len = usize::from(read_u16_ne(body, offset)?);
        let found_type = read_u16_ne(body, offset + 2)?;
        if len < ROUTE_ATTRIBUTE_HEADER_LEN || offset + len > body.len() {
            return Err(XfrmError::io(
                "netlink_receive",
                invalid_data("invalid route attribute"),
            ));
        }
        if found_type == attr_type {
            return Ok(Some(
                &body[offset + ROUTE_ATTRIBUTE_HEADER_LEN..offset + len],
            ));
        }
        offset += align_to_netlink(len).ok_or_else(|| {
            XfrmError::io(
                "netlink_receive",
                invalid_data("route attribute alignment overflow"),
            )
        })?;
    }
    Ok(None)
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
    if let Some(replay_state) = parameters.replay_state.as_ref() {
        validate_replay_state(replay_state, parameters.replay_window)?;
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

fn validate_fixed_outer_dscp(
    parameters: &SaParameters,
    profile: MarkProfile,
    dscp: DscpCodepoint,
) -> Result<(), XfrmError> {
    if parameters.mode != XfrmMode::Tunnel {
        return Err(XfrmError::invalid_config(
            "sa.egress_dscp",
            "fixed outer DSCP requires tunnel mode",
        ));
    }
    if parameters.id.protocol != IPPROTO_ESP {
        return Err(XfrmError::invalid_config(
            "sa.egress_dscp",
            "fixed outer DSCP supports ESP SAs only",
        ));
    }
    if parameters
        .mark
        .is_some_and(|mark| mark.mask & profile.mask != 0)
    {
        return Err(XfrmError::invalid_config(
            "sa.mark",
            "SA lookup mark overlaps the reserved DSCP output-mark window",
        ));
    }
    if profile.encode_token(dscp.get()).is_none() {
        return Err(XfrmError::invalid_config(
            "sa.egress_dscp",
            "DSCP must be between 0 and 63",
        ));
    }
    Ok(())
}

fn validate_sa_query(request: QuerySaRequest) -> Result<(), XfrmError> {
    if request.spi == 0 {
        return Err(XfrmError::invalid_config("spi", "spi must be nonzero"));
    }
    if request.protocol == 0 {
        return Err(XfrmError::invalid_config(
            "protocol",
            "protocol must be nonzero",
        ));
    }
    Ok(())
}

fn validate_replay_state(
    replay_state: &SaReplayState,
    replay_window: u32,
) -> Result<(), XfrmError> {
    if replay_state.replay_window != replay_window {
        return Err(XfrmError::invalid_config(
            "replay_state.replay_window",
            "replay state window must match SA replay window",
        ));
    }
    if replay_state.replay_window > 32 && !replay_state.esn {
        return Err(XfrmError::invalid_config(
            "replay_state.esn",
            "replay windows above 32 require ESN",
        ));
    }
    let required_words = replay_state.replay_window.div_ceil(32).max(1) as usize;
    if replay_state.esn {
        if replay_state.bitmap.len() != required_words {
            return Err(XfrmError::invalid_config(
                "replay_state.bitmap",
                "ESN bitmap word count must match replay window",
            ));
        }
    } else if replay_state.bitmap.len() > 1 {
        return Err(XfrmError::invalid_config(
            "replay_state.bitmap",
            "legacy replay state supports one bitmap word",
        ));
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
        if template.id.spi == 0 && template.request_id.is_none() {
            return Err(XfrmError::invalid_config(
                "template.request_id",
                "wildcard SPI requires a nonzero request ID",
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

fn decode_selector(bytes: &[u8], offset: usize) -> Result<XfrmSelector, XfrmError> {
    let family = read_u16_ne(bytes, offset + 40)?;
    Ok(XfrmSelector {
        destination: decode_address(bytes, offset, family)?,
        source: decode_address(bytes, offset + 16, family)?,
        destination_port: read_u16_be(bytes, offset + 32)?,
        source_port: read_u16_be(bytes, offset + 36)?,
        protocol: read_u8(bytes, offset + 44)?,
        destination_prefix_len: read_u8(bytes, offset + 42)?,
        source_prefix_len: read_u8(bytes, offset + 43)?,
    })
}

fn decode_address(bytes: &[u8], offset: usize, family: u16) -> Result<IpAddress, XfrmError> {
    match family {
        AF_INET => {
            let end = offset
                .checked_add(4)
                .ok_or_else(|| XfrmError::io("query_sa", invalid_data("offset overflow")))?;
            let slice = bytes
                .get(offset..end)
                .ok_or_else(|| XfrmError::io("query_sa", invalid_data("short IPv4 address")))?;
            Ok(IpAddress::Ipv4([slice[0], slice[1], slice[2], slice[3]]))
        }
        AF_INET6 => {
            let end = offset
                .checked_add(16)
                .ok_or_else(|| XfrmError::io("query_sa", invalid_data("offset overflow")))?;
            let slice = bytes
                .get(offset..end)
                .ok_or_else(|| XfrmError::io("query_sa", invalid_data("short IPv6 address")))?;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(slice);
            Ok(IpAddress::Ipv6(octets))
        }
        _ => Err(XfrmError::io(
            "query_sa",
            invalid_data("unsupported address family"),
        )),
    }
}

fn decode_lifetime_config(bytes: &[u8], offset: usize) -> Result<LifetimeConfig, XfrmError> {
    Ok(LifetimeConfig {
        soft_byte_limit: decode_lifetime_limit(read_u64_ne(bytes, offset)?),
        hard_byte_limit: decode_lifetime_limit(read_u64_ne(bytes, offset + 8)?),
        soft_packet_limit: decode_lifetime_limit(read_u64_ne(bytes, offset + 16)?),
        hard_packet_limit: decode_lifetime_limit(read_u64_ne(bytes, offset + 24)?),
        soft_add_expires_seconds: read_u64_ne(bytes, offset + 32)?,
        hard_add_expires_seconds: read_u64_ne(bytes, offset + 40)?,
    })
}

fn decode_lifetime_limit(value: u64) -> u64 {
    if value == XFRM_INF {
        0
    } else {
        value
    }
}

fn decode_lifetime_current(bytes: &[u8], offset: usize) -> Result<LifetimeCurrent, XfrmError> {
    Ok(LifetimeCurrent {
        bytes: read_u64_ne(bytes, offset)?,
        packets: read_u64_ne(bytes, offset + 8)?,
        add_time_seconds: read_u64_ne(bytes, offset + 16)?,
        use_time_seconds: read_u64_ne(bytes, offset + 24)?,
    })
}

fn decode_statistics(bytes: &[u8], offset: usize) -> Result<SaStatistics, XfrmError> {
    Ok(SaStatistics {
        replay_window: read_u32_ne(bytes, offset)?,
        replay_failures: read_u32_ne(bytes, offset + 4)?,
        integrity_failures: read_u32_ne(bytes, offset + 8)?,
    })
}

fn decode_mode(mode: u8) -> Result<XfrmMode, XfrmError> {
    match mode {
        0 => Ok(XfrmMode::Transport),
        1 => Ok(XfrmMode::Tunnel),
        4 => Ok(XfrmMode::Beet),
        _ => Err(XfrmError::io(
            "query_sa",
            invalid_data("unsupported XFRM mode"),
        )),
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

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, XfrmError> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("short netlink field")))
}

fn read_u16_be(bytes: &[u8], offset: usize) -> Result<u16, XfrmError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("offset overflow")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("short netlink field")))?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
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

fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32, XfrmError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("offset overflow")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("short netlink field")))?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_ne(bytes: &[u8], offset: usize) -> Result<u64, XfrmError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("offset overflow")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("short netlink field")))?;
    Ok(u64::from_ne_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
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
        requests: Arc<Mutex<Vec<SensitiveBuffer>>>,
        response: Option<SensitiveBuffer>,
    }

    impl CapturingTransport {
        fn with_response(response: Vec<u8>) -> Self {
            Self {
                response: Some(Zeroizing::new(response)),
                ..Self::default()
            }
        }

        fn requests(&self) -> Vec<SensitiveBuffer> {
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
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(Zeroizing::new(request.to_vec()));
            Ok(self.response.clone())
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: true,
                net_admin_capable: true,
                algorithms: XfrmCapability::Available,
                egress_dscp_marking: XfrmCapability::Missing,
                details: Some("test transport"),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct FakeDscpRuntime {
        state: Arc<Mutex<FakeDscpRuntimeState>>,
    }

    #[derive(Debug)]
    struct FakeDscpRuntimeState {
        ensure_calls: usize,
        ready: bool,
        capability: XfrmCapability,
    }

    impl Default for FakeDscpRuntime {
        fn default() -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeDscpRuntimeState {
                    ensure_calls: 0,
                    ready: true,
                    capability: XfrmCapability::Available,
                })),
            }
        }
    }

    impl FakeDscpRuntime {
        fn ensure_calls(&self) -> usize {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .ensure_calls
        }

        fn lose_readiness(&self) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.ready = false;
            state.capability = XfrmCapability::Missing;
        }
    }

    impl XfrmDscpRuntime for FakeDscpRuntime {
        fn ensure_ready(&self, _config: &LinuxXfrmDscpMarkingConfig) -> Result<(), XfrmError> {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.ensure_calls += 1;
            if state.ready {
                Ok(())
            } else {
                Err(XfrmError::Unavailable)
            }
        }

        fn capability(&self, _config: &LinuxXfrmDscpMarkingConfig) -> XfrmCapability {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .capability
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
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
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
                egress_dscp_marking: XfrmCapability::Missing,
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
            request_id: None,
            auth: Some((
                AuthAlgorithm::hmac_sha256(96),
                KeyMaterial::new(vec![0xab; 32]),
            )),
            crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0xcd; 16]))),
            aead: None,
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 32,
            replay_state: None,
            encap: None,
            mark: None,
            if_id: None,
            egress_dscp: None,
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
                request_id: None,
                mode: XfrmMode::Tunnel,
            }],
            mark: None,
            if_id: None,
        }
    }

    fn dscp_config() -> LinuxXfrmDscpMarkingConfig {
        let mut config = LinuxXfrmDscpMarkingConfig::new([String::from("eth0")], 25).unwrap();
        config.bpffs_pin_root = "/sys/fs/bpf/opc-ipsec-xfrm-dscp-test".into();
        config
    }

    fn ack(sequence: u32) -> Vec<u8> {
        let mut body = Vec::new();
        push_i32_ne(&mut body, 0);
        encode_netlink_message(NLMSG_ERROR, 0, sequence, &body)
            .unwrap()
            .to_vec()
    }

    fn netlink_message_type(message: &[u8]) -> u16 {
        u16::from_ne_bytes([message[4], message[5]])
    }

    fn netlink_body(message: &[u8]) -> &[u8] {
        let len = u32::from_ne_bytes([message[0], message[1], message[2], message[3]]) as usize;
        &message[NETLINK_HEADER_LEN..len]
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

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn netlink_response_and_transport_clones_remain_zeroizing_buffers() {
        assert_zeroize_on_drop::<SensitiveBuffer>();
        let body = Zeroizing::new(vec![0x5a; XFRM_USER_SA_INFO_LEN]);
        let message = encode_netlink_message(XFRM_MSG_GETSA, 0, 7, &body).unwrap();
        let parsed = parse_netlink_response(&message, 7)
            .unwrap()
            .expect("GETSA response body");
        assert_sensitive_buffer(&parsed);

        let transport = CapturingTransport::with_response(parsed.to_vec());
        let cloned = transport.response.clone().expect("cloned test response");
        assert_sensitive_buffer(&cloned);
    }

    #[test]
    fn absent_dscp_preserves_exact_legacy_sa_bytes() {
        let parameters = sa_parameters();
        let legacy = encode_sa_info(&parameters).unwrap();
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();

        let unconfigured = encode_sa_info_with_dscp(&parameters, None).unwrap();
        let configured = encode_sa_info_with_dscp(&parameters, Some(profile)).unwrap();

        assert_eq!(unconfigured.as_slice(), legacy.as_slice());
        assert_eq!(configured.as_slice(), legacy.as_slice());
        assert!(route_attr_payload(&configured, XFRMA_SET_MARK).is_none());
        assert!(route_attr_payload(&configured, XFRMA_SET_MARK_MASK).is_none());
    }

    #[test]
    fn fixed_outer_dscp_encodes_exact_output_mark_boundaries() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        for dscp in [0, DscpCodepoint::MAX] {
            let mut parameters = sa_parameters();
            parameters.egress_dscp = Some(DscpCodepoint::new(dscp).unwrap());

            let body = encode_sa_info_with_dscp(&parameters, Some(profile)).unwrap();
            let value = route_attr_payload(&body, XFRMA_SET_MARK).unwrap();
            let mask = route_attr_payload(&body, XFRMA_SET_MARK_MASK).unwrap();

            assert_eq!(value, &profile.encode_token(dscp).unwrap().to_ne_bytes());
            assert_eq!(mask, &profile.mask.to_ne_bytes());
        }
    }

    #[test]
    fn fixed_outer_dscp_rejects_unsupported_or_colliding_sa_contracts() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(46).unwrap());

        assert!(matches!(
            encode_sa_info_with_dscp(&marked, None).unwrap_err(),
            XfrmError::UnsupportedFeature {
                feature: "fixed_outer_dscp"
            }
        ));

        let mut transport = marked.clone();
        transport.mode = XfrmMode::Transport;
        assert!(matches!(
            encode_sa_info_with_dscp(&transport, Some(profile)).unwrap_err(),
            XfrmError::InvalidConfig {
                field: "sa.egress_dscp",
                ..
            }
        ));

        let mut non_esp = marked.clone();
        non_esp.id.protocol = 51;
        assert!(matches!(
            encode_sa_info_with_dscp(&non_esp, Some(profile)).unwrap_err(),
            XfrmError::InvalidConfig {
                field: "sa.egress_dscp",
                ..
            }
        ));

        marked.mark = Some(XfrmMark {
            value: 0,
            mask: profile.mask,
        });
        assert!(matches!(
            encode_sa_info_with_dscp(&marked, Some(profile)).unwrap_err(),
            XfrmError::InvalidConfig {
                field: "sa.mark",
                ..
            }
        ));
    }

    #[test]
    fn fixed_outer_dscp_query_round_trips_and_rejects_ambiguous_state() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let mut parameters = sa_parameters();
        parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let body = encode_sa_info_with_dscp(&parameters, Some(profile)).unwrap();

        assert_eq!(
            parse_sa_state(&body, Some(profile)).unwrap().egress_dscp,
            parameters.egress_dscp
        );
        assert!(matches!(
            parse_sa_state(&body, None).unwrap_err(),
            XfrmError::UnsupportedFeature {
                feature: "unconfigured_output_mark_state"
            }
        ));

        let mut incomplete = encode_sa_info(&sa_parameters()).unwrap();
        append_attr(
            &mut incomplete,
            XFRMA_SET_MARK,
            &profile.encode_token(46).unwrap().to_ne_bytes(),
        )
        .unwrap();
        assert_eq!(
            parse_sa_state(&incomplete, Some(profile))
                .unwrap_err()
                .io_kind(),
            Some(io::ErrorKind::InvalidData)
        );

        let mut malformed = encode_sa_info(&sa_parameters()).unwrap();
        append_attr(
            &mut malformed,
            XFRMA_SET_MARK,
            &(1_u32 << profile.shift).to_ne_bytes(),
        )
        .unwrap();
        append_attr(
            &mut malformed,
            XFRMA_SET_MARK_MASK,
            &profile.mask.to_ne_bytes(),
        )
        .unwrap();
        assert_eq!(
            parse_sa_state(&malformed, Some(profile))
                .unwrap_err()
                .io_kind(),
            Some(io::ErrorKind::InvalidData)
        );

        let mut wrong_mask = encode_sa_info(&sa_parameters()).unwrap();
        append_attr(
            &mut wrong_mask,
            XFRMA_SET_MARK,
            &profile.encode_token(46).unwrap().to_ne_bytes(),
        )
        .unwrap();
        append_attr(
            &mut wrong_mask,
            XFRMA_SET_MARK_MASK,
            &0x7f_u32.to_ne_bytes(),
        )
        .unwrap();
        assert_eq!(
            parse_sa_state(&wrong_mask, Some(profile))
                .unwrap_err()
                .io_kind(),
            Some(io::ErrorKind::InvalidData)
        );
    }

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
    fn encodes_esn_replay_state_for_window_above_32() {
        let mut params = sa_parameters();
        params.replay_window = 64;
        params.replay_state = Some(SaReplayState {
            esn: true,
            outbound_sequence: 10,
            inbound_sequence: 11,
            outbound_sequence_hi: 1,
            inbound_sequence_hi: 2,
            replay_window: 64,
            bitmap: vec![0xaabb_ccdd, 0xeeff_0011],
        });

        let body = encode_sa_info(&params).unwrap();
        let payload = route_attr_payload(&body, XFRMA_REPLAY_ESN_VAL).expect("ESN attr");

        assert_eq!(body[216], XFRM_STATE_ESN);
        assert_eq!(payload.len(), XFRM_REPLAY_STATE_ESN_BASE_LEN + 8);
        assert_eq!(u32::from_ne_bytes(payload[0..4].try_into().unwrap()), 2);
        assert_eq!(u32::from_ne_bytes(payload[4..8].try_into().unwrap()), 10);
        assert_eq!(u32::from_ne_bytes(payload[8..12].try_into().unwrap()), 11);
        assert_eq!(u32::from_ne_bytes(payload[12..16].try_into().unwrap()), 1);
        assert_eq!(u32::from_ne_bytes(payload[16..20].try_into().unwrap()), 2);
        assert_eq!(u32::from_ne_bytes(payload[20..24].try_into().unwrap()), 64);
    }

    #[test]
    fn rejects_inconsistent_replay_state() {
        let mut params = sa_parameters();
        params.replay_window = 64;
        params.replay_state = Some(SaReplayState {
            esn: false,
            outbound_sequence: 0,
            inbound_sequence: 0,
            outbound_sequence_hi: 0,
            inbound_sequence_hi: 0,
            replay_window: 64,
            bitmap: vec![0],
        });

        let error = encode_sa_info(&params).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "replay_state.esn",
                reason: "replay windows above 32 require ESN"
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

    #[test]
    fn encodes_request_id_on_sa_and_wildcard_policy_template() {
        let request_id = XfrmRequestId::new(7_001).expect("nonzero request ID");
        let mut sa = sa_parameters();
        sa.request_id = Some(request_id);
        let sa_body = encode_sa_info(&sa).expect("SA encodes");
        assert_eq!(read_u32_ne(&sa_body, 208).expect("SA request ID"), 7_001);

        let mut policy = policy_parameters();
        policy.templates[0].id.spi = 0;
        policy.templates[0].request_id = Some(request_id);
        let policy_body = encode_policy_info(&policy).expect("policy encodes");
        let template = route_attr_payload_from(&policy_body, XFRM_USER_POLICY_INFO_LEN, XFRMA_TMPL)
            .expect("template attr");
        assert_eq!(read_u32_be(template, 16).expect("wildcard SPI"), 0);
        assert_eq!(
            read_u32_ne(template, 44).expect("template request ID"),
            7_001
        );
    }

    #[test]
    fn rejects_wildcard_policy_template_without_request_id() {
        let mut policy = policy_parameters();
        policy.templates[0].id.spi = 0;

        let error = encode_policy_info(&policy).expect_err("unbound wildcard must fail closed");

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "template.request_id",
                reason: "wildcard SPI requires a nonzero request ID"
            }
        ));
    }

    #[test]
    fn encodes_policy_template_algorithm_masks_as_all_algorithms() {
        let body = encode_policy_info(&policy_parameters()).unwrap();
        let templates = route_attr_payload_from(&body, XFRM_USER_POLICY_INFO_LEN, XFRMA_TMPL)
            .expect("template attr");

        assert_eq!(templates.len(), XFRM_USER_TEMPLATE_LEN);
        assert_eq!(
            u32::from_ne_bytes(templates[52..56].try_into().unwrap()),
            u32::MAX
        );
        assert_eq!(
            u32::from_ne_bytes(templates[56..60].try_into().unwrap()),
            u32::MAX
        );
        assert_eq!(
            u32::from_ne_bytes(templates[60..64].try_into().unwrap()),
            u32::MAX
        );
        assert_ne!(&templates[52..64], [0; 12]);
    }

    #[test]
    fn parses_getsa_response_with_esn_replay_state() {
        let mut params = sa_parameters();
        params.request_id = XfrmRequestId::new(7_001);
        params.replay_window = 64;
        params.replay_state = Some(SaReplayState {
            esn: true,
            outbound_sequence: 100,
            inbound_sequence: 101,
            outbound_sequence_hi: 5,
            inbound_sequence_hi: 6,
            replay_window: 64,
            bitmap: vec![0x1111_2222, 0x3333_4444],
        });
        let body = encode_sa_info(&params).unwrap();

        let state = parse_sa_state(&body, None).unwrap();

        assert_eq!(state.id, params.id);
        assert_eq!(state.selector, params.selector);
        assert_eq!(state.source_address, params.source_address);
        assert_eq!(state.mode, XfrmMode::Tunnel);
        assert_eq!(state.replay_window, 64);
        assert_eq!(state.replay_state, params.replay_state.unwrap());
        assert_eq!(state.request_id, XfrmRequestId::new(7_001));
    }

    #[test]
    fn rejects_malformed_getsa_replay_attrs() {
        let mut body = encode_sa_info(&sa_parameters()).unwrap();
        append_attr(&mut body, XFRMA_REPLAY_ESN_VAL, &[0, 0, 0]).unwrap();

        let error = parse_sa_state(&body, None).unwrap_err();

        assert_eq!(error.io_kind(), Some(io::ErrorKind::InvalidData));
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
                mark: None,
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

    #[tokio::test]
    async fn marked_policy_removal_encodes_exact_lookup_mark() {
        let transport = CapturingTransport::default();
        let backend = LinuxXfrmBackend::with_transport(transport.clone());
        let mark = XfrmMark {
            value: 0x0000_0042,
            mask: 0x0000_00ff,
        };

        backend
            .remove_policy(RemovePolicyRequest {
                selector: selector(),
                direction: XfrmDirection::Out,
                mark: Some(mark),
            })
            .await
            .unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_DELPOLICY);
        assert_eq!(
            route_attr_payload_from(
                netlink_body(&requests[0]),
                XFRM_USER_POLICY_ID_LEN,
                XFRMA_MARK,
            ),
            Some(encode_mark(mark).as_slice())
        );
    }

    #[tokio::test]
    async fn configured_backend_proves_dscp_capability_only_after_exact_readback() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let response = encode_sa_info_with_dscp(&marked, Some(profile))
            .unwrap()
            .to_vec();
        let transport = CapturingTransport::with_response(response);
        let runtime = FakeDscpRuntime::default();
        let backend = LinuxXfrmBackend::with_transport_and_dscp_runtime(
            transport.clone(),
            dscp_config(),
            runtime.clone(),
        )
        .unwrap();
        assert_eq!(
            runtime.ensure_calls(),
            1,
            "constructor eagerly validates tc"
        );
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Unknown,
            "tc readiness alone cannot prove kernel output-mark support"
        );

        backend
            .install_sa(InstallSaRequest {
                parameters: sa_parameters(),
            })
            .await
            .unwrap();
        assert_eq!(
            runtime.ensure_calls(),
            1,
            "the legacy None path must not depend on the companion"
        );
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Unknown
        );

        backend
            .install_sa(InstallSaRequest { parameters: marked })
            .await
            .unwrap();
        assert_eq!(runtime.ensure_calls(), 2);
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Available
        );

        let requests = transport.requests();
        let legacy_body = netlink_body(&requests[0]);
        assert!(route_attr_payload(legacy_body, XFRMA_SET_MARK).is_none());
        let marked_body = netlink_body(&requests[1]);
        let expected_token = profile.encode_token(46).unwrap().to_ne_bytes();
        assert_eq!(
            route_attr_payload(marked_body, XFRMA_SET_MARK),
            Some(expected_token.as_slice())
        );
        assert_eq!(netlink_message_type(&requests[2]), XFRM_MSG_GETSA);
    }

    #[tokio::test]
    async fn marked_rekey_revalidates_runtime_before_kernel_mutation() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(63).unwrap());
        let response = encode_sa_info_with_dscp(&marked, Some(profile))
            .unwrap()
            .to_vec();
        let transport = CapturingTransport::with_response(response);
        let runtime = FakeDscpRuntime::default();
        let backend = LinuxXfrmBackend::with_transport_and_dscp_runtime(
            transport.clone(),
            dscp_config(),
            runtime.clone(),
        )
        .unwrap();
        backend
            .rekey_sa(RekeySaRequest { parameters: marked })
            .await
            .unwrap();

        assert_eq!(runtime.ensure_calls(), 2);
        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_UPDSA);
        assert_eq!(
            u16::from_ne_bytes([requests[0][6], requests[0][7]]),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE
        );
        assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_GETSA);
    }

    #[tokio::test]
    async fn marked_rekey_readback_failure_is_explicitly_indeterminate() {
        let transport = CapturingTransport::default();
        let runtime = FakeDscpRuntime::default();
        let backend = LinuxXfrmBackend::with_transport_and_dscp_runtime(
            transport.clone(),
            dscp_config(),
            runtime,
        )
        .unwrap();
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        marked.mark = Some(XfrmMark {
            value: 0x0000_0042,
            mask: 0x0000_00ff,
        });

        assert!(matches!(
            backend
                .rekey_sa(RekeySaRequest { parameters: marked })
                .await,
            Err(XfrmError::StateIndeterminate {
                operation: "rekey_sa_dscp_readback"
            })
        ));
        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_UPDSA);
        assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_GETSA);
        assert!(route_attr_payload_from(
            netlink_body(&requests[1]),
            XFRM_USER_SA_ID_LEN,
            XFRMA_MARK,
        )
        .is_some());
    }

    #[tokio::test]
    async fn marked_ack_without_exact_getsa_readback_is_indeterminate_without_delete() {
        let transport = CapturingTransport::default();
        let runtime = FakeDscpRuntime::default();
        let backend = LinuxXfrmBackend::with_transport_and_dscp_runtime(
            transport.clone(),
            dscp_config(),
            runtime,
        )
        .unwrap();
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        marked.mark = Some(XfrmMark {
            value: 0x0000_0042,
            mask: 0x0000_00ff,
        });
        let marked_lookup = marked.mark.unwrap();

        assert!(matches!(
            backend
                .install_sa(InstallSaRequest { parameters: marked })
                .await
                .unwrap_err(),
            XfrmError::StateIndeterminate {
                operation: "install_sa_dscp_readback"
            }
        ));
        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_NEWSA);
        assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_GETSA);
        let expected_mark = encode_mark(marked_lookup);
        assert_eq!(
            route_attr_payload_from(netlink_body(&requests[1]), XFRM_USER_SA_ID_LEN, XFRMA_MARK,),
            Some(expected_mark.as_slice())
        );
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Unknown
        );
    }

    #[tokio::test]
    async fn mismatched_static_getsa_field_is_indeterminate_without_delete() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let mut requested = sa_parameters();
        requested.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        requested.mark = Some(XfrmMark {
            value: 0x42,
            mask: 0xff,
        });
        let mut returned = requested.clone();
        returned.source_address = ipv4(192, 0, 2, 99);
        let response = encode_sa_info_with_dscp(&returned, Some(profile))
            .unwrap()
            .to_vec();
        let transport = CapturingTransport::with_response(response);
        let backend = LinuxXfrmBackend::with_transport_and_dscp_runtime(
            transport.clone(),
            dscp_config(),
            FakeDscpRuntime::default(),
        )
        .unwrap();

        assert!(matches!(
            backend
                .install_sa(InstallSaRequest {
                    parameters: requested,
                })
                .await,
            Err(XfrmError::StateIndeterminate {
                operation: "install_sa_dscp_readback"
            })
        ));
        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_NEWSA);
        assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_GETSA);
    }

    #[tokio::test]
    async fn runtime_readiness_loss_blocks_marked_sa_before_netlink() {
        let transport = CapturingTransport::default();
        let runtime = FakeDscpRuntime::default();
        let backend = LinuxXfrmBackend::with_transport_and_dscp_runtime(
            transport.clone(),
            dscp_config(),
            runtime.clone(),
        )
        .unwrap();
        runtime.lose_readiness();
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(46).unwrap());

        assert!(matches!(
            backend
                .install_sa(InstallSaRequest { parameters: marked })
                .await
                .unwrap_err(),
            XfrmError::Unavailable
        ));
        assert!(transport.requests().is_empty());
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Missing
        );
    }

    #[tokio::test]
    async fn marked_query_proves_kernel_output_mark_support() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let mut parameters = sa_parameters();
        parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let response = encode_sa_info_with_dscp(&parameters, Some(profile))
            .unwrap()
            .to_vec();
        let transport = CapturingTransport::with_response(response);
        let runtime = FakeDscpRuntime::default();
        let backend =
            LinuxXfrmBackend::with_transport_and_dscp_runtime(transport, dscp_config(), runtime)
                .unwrap();

        let state = backend
            .query_sa(QuerySaRequest {
                destination: parameters.id.destination,
                protocol: parameters.id.protocol,
                spi: parameters.id.spi,
                mark: parameters.mark,
            })
            .await
            .unwrap();

        assert_eq!(state.egress_dscp, parameters.egress_dscp);
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Available
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

    #[tokio::test]
    async fn query_sa_sends_getsa_and_decodes_replay_state() {
        let mut params = sa_parameters();
        params.replay_window = 64;
        params.replay_state = Some(SaReplayState {
            esn: true,
            outbound_sequence: 7,
            inbound_sequence: 8,
            outbound_sequence_hi: 1,
            inbound_sequence_hi: 2,
            replay_window: 64,
            bitmap: vec![0x0102_0304, 0x0506_0708],
        });
        let transport =
            CapturingTransport::with_response(encode_sa_info(&params).unwrap().to_vec());
        let backend = LinuxXfrmBackend::with_transport(transport.clone());

        let state = backend
            .query_sa(QuerySaRequest {
                destination: params.id.destination,
                protocol: params.id.protocol,
                spi: params.id.spi,
                mark: params.mark,
            })
            .await
            .unwrap();

        assert_eq!(state.replay_state, params.replay_state.unwrap());
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_GETSA);
        assert_eq!(
            u16::from_ne_bytes([requests[0][6], requests[0][7]]),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(netlink_body(&requests[0]).len(), XFRM_USER_SA_ID_LEN);
        assert_eq!(
            &netlink_body(&requests[0])[16..20],
            &[0x12, 0x34, 0x56, 0x78]
        );
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
    fn proc_status_cap_eff_reports_net_admin_bit() {
        assert_eq!(
            parse_cap_net_admin_from_status("Name:\ttest\nCapEff:\t0000000000001000\n"),
            Some(true)
        );
        assert_eq!(
            parse_cap_net_admin_from_status("Name:\ttest\nCapEff:\t0000000000000000\n"),
            Some(false)
        );
        assert_eq!(parse_cap_net_admin_from_status("Name:\ttest\n"), None);
        assert_eq!(parse_cap_net_admin_from_status("CapEff:\tnot-hex\n"), None);
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
