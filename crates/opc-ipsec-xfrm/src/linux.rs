//! Safe Linux XFRM backend over the raw netlink sys boundary.

use std::fmt;
use std::io;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_ipsec_xfrm_ebpf_common::{MarkProfile, IPPROTO_ESP};
use opc_linux_xfrm_sys::{
    align_to_netlink, open_netlink_socket, receive_message_outcome, send_message,
    ReceiveMessageOutcome, LINUX_EINVAL, LINUX_ENOPROTOOPT, NLMSG_DONE, NLMSG_ERROR, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST, XFRMA_ALG_AEAD, XFRMA_ALG_AUTH,
    XFRMA_ALG_AUTH_TRUNC, XFRMA_ALG_CRYPT, XFRMA_ENCAP, XFRMA_IF_ID, XFRMA_LASTUSED, XFRMA_MARK,
    XFRMA_OFFLOAD_DEV, XFRMA_PAD, XFRMA_POLICY_TYPE, XFRMA_REPLAY_ESN_VAL, XFRMA_REPLAY_VAL,
    XFRMA_SA_DIR, XFRMA_SET_MARK, XFRMA_SET_MARK_MASK, XFRMA_TMPL, XFRM_AE_RVAL, XFRM_MSG_ALLOCSPI,
    XFRM_MSG_DELPOLICY, XFRM_MSG_DELSA, XFRM_MSG_GETPOLICY, XFRM_MSG_GETSA, XFRM_MSG_MIGRATE_STATE,
    XFRM_MSG_NEWAE, XFRM_MSG_NEWPOLICY, XFRM_MSG_NEWSA, XFRM_MSG_UPDPOLICY, XFRM_MSG_UPDSA,
    XFRM_POLICY_ALLOW, XFRM_POLICY_BLOCK, XFRM_POLICY_FWD, XFRM_POLICY_IN, XFRM_POLICY_OUT,
    XFRM_POLICY_TYPE_MAIN, XFRM_SA_DIR_IN, XFRM_SA_DIR_OUT, XFRM_STATE_ESN,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::dscp::{production_runtime, LinuxXfrmDscpMarkingConfig, XfrmDscpRuntime};
use crate::model::{
    sa_uses_esn, validate_relocate_sa_request, validate_sa_output_mark, validate_sa_query,
};
use crate::namespace::{self, NamespaceBoundLinuxXfrmBackend, NetworkNamespaceBinding};
use crate::observation::{EspPeerObservationKey, EspPeerObservationRegistration};
use crate::outbound_binding::{
    expected_policy, expected_sa, readback_mismatch, OutboundSaCryptoExpectation,
    OutboundSaPolicyExpectation,
};
use crate::{
    AllocateSpiRequest, DscpCodepoint, InstallPolicyRequest, InstallSaRequest, IpAddress,
    LifetimeConfig, LifetimeCurrent, OutboundSaBindingError, PolicyParameters, QuerySaRequest,
    RekeyPolicyRequest, RekeySaRequest, RelocateSaRequest, RemovePolicyRequest, RemoveSaRequest,
    SaParameters, SaRelocationEncap, SaRelocationIdentity, SaRelocationSelector, SaReplayState,
    SaState, SaStatistics, SpiAllocation, UdpEncap, XfrmAction, XfrmBackend, XfrmBackendKind,
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
const XFRM_USER_MIGRATE_STATE_LEN: usize = 132;
const XFRM_AEVENT_ID_LEN: usize = 48;
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
const RELOCATION_CAPABILITY_UNKNOWN: u8 = 0;
const RELOCATION_CAPABILITY_AVAILABLE: u8 = 1;
const RELOCATION_CAPABILITY_MISSING: u8 = 2;
const SA_RELOCATION_PROBE_SPI: u32 = 0xffff_fffe;
const XFRM_KEY_READBACK_REDACTED: &str = "xfrm_key_readback_redacted";

pub(crate) type SensitiveBuffer = Zeroizing<Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetlinkOperationClass {
    Mutation,
    ReadOnly,
}

fn netlink_operation_class(message_type: u16) -> NetlinkOperationClass {
    match message_type {
        XFRM_MSG_GETSA | XFRM_MSG_GETPOLICY => NetlinkOperationClass::ReadOnly,
        _ => NetlinkOperationClass::Mutation,
    }
}

/// Runtime behavior for the safe Linux XFRM backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxXfrmBackendConfig {
    /// Number of nonblocking receive attempts before returning a timeout.
    pub receive_attempts: u16,
    /// Hard netlink receive bound in bytes.
    ///
    /// A consumed response above this bound makes a mutation
    /// [`XfrmError::StateIndeterminate`] and makes a read
    /// [`XfrmError::ResponseTooLarge`].
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
    sa_relocation_capability: AtomicU8,
    namespace_binding: Option<NetworkNamespaceBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SaRelocationSnapshot {
    state: SaState,
    identity: SaRelocationIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyState {
    parameters: PolicyParameters,
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
                sa_relocation_capability: AtomicU8::new(RELOCATION_CAPABILITY_UNKNOWN),
                namespace_binding: None,
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
                sa_relocation_capability: AtomicU8::new(RELOCATION_CAPABILITY_UNKNOWN),
                namespace_binding: None,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_transport<T>(transport: T) -> Self
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
                sa_relocation_capability: AtomicU8::new(RELOCATION_CAPABILITY_UNKNOWN),
                namespace_binding: None,
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_transport_and_dscp_runtime<T, R>(
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
                sa_relocation_capability: AtomicU8::new(RELOCATION_CAPABILITY_UNKNOWN),
                namespace_binding: None,
            }),
        })
    }

    /// Bind this backend to the calling thread's current Linux network
    /// namespace.
    ///
    /// The returned backend owns a bounded actor on a dedicated OS thread that
    /// inherits the caller's namespace. Every XFRM and fixed-DSCP operation is
    /// executed on that thread and cross-checks the opaque namespace identity
    /// before opening a socket or touching the DSCP companion.
    ///
    /// Waiting for queue admission is cancellation-safe: dropping the future
    /// before admission performs no operation. Once admitted, an operation is
    /// always drained by the actor even if its caller goes away. A lost reply
    /// from an admitted mutation is reported as
    /// [`XfrmError::StateIndeterminate`].
    pub fn bind_current_network_namespace(
        self,
    ) -> Result<NamespaceBoundLinuxXfrmBackend, XfrmError> {
        namespace::bind_current_network_namespace(self)
    }

    pub(crate) fn for_namespace_actor(self, binding: NetworkNamespaceBinding) -> Self {
        let inner = self.inner;
        Self {
            inner: Arc::new(LinuxXfrmBackendInner {
                transport: Arc::clone(&inner.transport),
                next_sequence: AtomicU32::new(inner.next_sequence.load(Ordering::Acquire)),
                config: inner.config,
                dscp_config: inner.dscp_config.clone(),
                dscp_runtime: inner.dscp_runtime.fresh_namespace_runtime(),
                // Both observations were made through the source backend's
                // execution context. They are not authority in a newly bound
                // namespace, even when the underlying kernel is shared.
                dscp_xfrm_attributes_verified: AtomicBool::new(false),
                sa_relocation_capability: AtomicU8::new(RELOCATION_CAPABILITY_UNKNOWN),
                namespace_binding: Some(binding),
            }),
        }
    }

    pub(crate) fn prepare_namespace_actor(&self) -> Result<(), XfrmError> {
        self.ensure_namespace_binding()?;
        if let Some(config) = &self.inner.dscp_config {
            // DSCP program/map adoption is namespace-scoped too. Repeat the
            // identity check immediately before entering that runtime.
            self.ensure_namespace_binding()?;
            self.inner.dscp_runtime.ensure_ready(config)?;
        }
        Ok(())
    }

    pub(crate) fn verify_namespace_actor(&self) -> Result<(), XfrmError> {
        self.ensure_namespace_binding()
    }

    fn ensure_namespace_binding(&self) -> Result<(), XfrmError> {
        match self.inner.namespace_binding {
            Some(binding) => binding.ensure_current(),
            None => Ok(()),
        }
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
        self.ensure_namespace_binding()?;
        self.inner.dscp_runtime.ensure_ready(config)?;
        Ok(Some(profile))
    }

    fn current_sa_relocation_capability(&self) -> XfrmCapability {
        match self.inner.sa_relocation_capability.load(Ordering::Acquire) {
            RELOCATION_CAPABILITY_AVAILABLE => XfrmCapability::Available,
            RELOCATION_CAPABILITY_MISSING => XfrmCapability::Missing,
            _ => XfrmCapability::UnknownUntilUse,
        }
    }

    fn record_sa_relocation_capability(&self, capability: XfrmCapability) {
        let value = match capability {
            XfrmCapability::Available => RELOCATION_CAPABILITY_AVAILABLE,
            XfrmCapability::Missing => RELOCATION_CAPABILITY_MISSING,
            _ => RELOCATION_CAPABILITY_UNKNOWN,
        };
        self.inner
            .sa_relocation_capability
            .store(value, Ordering::Release);
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
        // Keep the identity check adjacent to transport socket creation. A
        // namespace-bound backend calls this inline on its actor thread.
        self.ensure_namespace_binding()?;
        let sequence = self.next_sequence();
        let request = encode_netlink_message(message_type, flags, sequence, &body)?;
        self.inner.transport.transact(
            operation,
            netlink_operation_class(message_type),
            &request,
            sequence,
            self.inner.config,
        )
    }

    async fn transact_blocking(
        &self,
        operation: &'static str,
        message_type: u16,
        flags: u16,
        body: SensitiveBuffer,
    ) -> Result<Option<SensitiveBuffer>, XfrmError> {
        if self.inner.namespace_binding.is_some() {
            return self.transact(operation, message_type, flags, body);
        }
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

    async fn verify_output_mark_readback(
        &self,
        parameters: &SaParameters,
        dscp_profile: Option<MarkProfile>,
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
        // Mutation admission already knows whether this SA requested DSCP.
        // Compare the exact raw pair instead of inferring intent from an
        // overlapping mark profile; query-time inference is intentionally
        // conservative because arbitrary generic marks may overlap it.
        let state = parse_sa_state(&response, None).map_err(|_| indeterminate())?;
        let expected_output_mark =
            compose_output_mark(parameters, dscp_profile).map_err(|_| indeterminate())?;
        if state.id != parameters.id
            || state.selector != parameters.selector
            || state.source_address != parameters.source_address
            || state.request_id != parameters.request_id
            || state.mode != parameters.mode
            || state.replay_window != parameters.replay_window
            || state.lifetime_config != parameters.lifetime
            || state.output_mark != expected_output_mark
        {
            return Err(indeterminate());
        }
        if parameters.egress_dscp.is_some() {
            self.inner
                .dscp_xfrm_attributes_verified
                .store(true, Ordering::Release);
        }
        Ok(())
    }

    async fn query_sa_for_relocation(
        &self,
        id: XfrmId,
        mark: Option<XfrmMark>,
        operation: &'static str,
    ) -> Result<SaRelocationSnapshot, XfrmError> {
        let body = encode_sa_id(id.destination, id.protocol, id.spi, mark)?;
        let response = self
            .transact_blocking(operation, XFRM_MSG_GETSA, NLM_F_REQUEST | NLM_F_ACK, body)
            .await?
            .ok_or_else(|| XfrmError::io(operation, invalid_data("missing getsa response")))?;
        parse_sa_relocation_snapshot(&response)
    }

    pub(crate) async fn query_esp_peer_observation_registration(
        &self,
        requested: EspPeerObservationKey,
    ) -> Result<EspPeerObservationRegistration, XfrmError> {
        const OPERATION: &str = "query_esp_peer_observation_registration";

        if !matches!(requested.direction, XfrmDirection::In) {
            return Err(XfrmError::invalid_config(
                "esp_peer_observation.direction",
                "only inbound SAs produce decap observations",
            ));
        }
        let body = encode_sa_id(
            requested.id.destination,
            requested.id.protocol,
            requested.id.spi,
            requested.mark,
        )?;
        let response = self
            .transact_blocking(OPERATION, XFRM_MSG_GETSA, NLM_F_REQUEST | NLM_F_ACK, body)
            .await?
            .ok_or_else(|| XfrmError::io(OPERATION, invalid_data("missing getsa response")))?;
        parse_esp_peer_observation_registration(&response, requested)
    }

    async fn query_policy_for_outbound_binding(
        &self,
        parameters: &PolicyParameters,
    ) -> Result<PolicyState, XfrmError> {
        let body = encode_policy_query(parameters)?;
        let response = self
            .transact_blocking(
                "query_outbound_policy_binding",
                XFRM_MSG_GETPOLICY,
                NLM_F_REQUEST | NLM_F_ACK,
                body,
            )
            .await?
            .ok_or_else(|| {
                XfrmError::io(
                    "query_outbound_policy_binding",
                    invalid_data("missing getpolicy response"),
                )
            })?;
        parse_policy_state(&response)
    }

    async fn query_sa_for_outbound_binding(
        &self,
        parameters: &SaParameters,
    ) -> Result<SensitiveBuffer, XfrmError> {
        let body = encode_sa_id(
            parameters.id.destination,
            parameters.id.protocol,
            parameters.id.spi,
            parameters.mark,
        )?;
        self.transact_blocking(
            "query_outbound_sa_binding",
            XFRM_MSG_GETSA,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )
        .await?
        .ok_or_else(|| {
            XfrmError::io(
                "query_outbound_sa_binding",
                invalid_data("missing getsa response"),
            )
        })
    }

    /// Update only the replay state of an exactly preflighted outbound SA.
    ///
    /// `UPDSA` replaces SA configuration and does not restore live replay
    /// counters on Linux. `NEWAE` is the dedicated replay/lifetime UAPI; its
    /// kernel handler holds the SA lock while copying the supplied replay
    /// state. Callers must still perform exact GETSA readback afterward.
    pub(crate) async fn update_outbound_sa_replay_state(
        &self,
        parameters: &SaParameters,
        replay_state: &SaReplayState,
    ) -> Result<(), XfrmError> {
        let body = encode_sa_replay_update(parameters, replay_state)?;
        self.run_ack(
            "update_outbound_sa_replay_state",
            XFRM_MSG_NEWAE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE,
            body,
        )
        .await
    }

    pub(crate) async fn validate_outbound_sa_binding(
        &self,
        expectation: &OutboundSaPolicyExpectation,
        supplied_sa: &SaParameters,
    ) -> Result<(), OutboundSaBindingError> {
        self.read_outbound_sa_binding(expectation, supplied_sa)
            .await
            .map(|_| ())
    }

    pub(crate) async fn read_outbound_sa_binding(
        &self,
        expectation: &OutboundSaPolicyExpectation,
        supplied_sa: &SaParameters,
    ) -> Result<SaState, OutboundSaBindingError> {
        self.read_outbound_sa_binding_inner(expectation, Some(supplied_sa))
            .await
    }

    pub(crate) async fn read_outbound_sa_binding_metadata(
        &self,
        expectation: &OutboundSaPolicyExpectation,
    ) -> Result<SaState, OutboundSaBindingError> {
        self.read_outbound_sa_binding_inner(expectation, None).await
    }

    async fn read_outbound_sa_binding_inner(
        &self,
        expectation: &OutboundSaPolicyExpectation,
        supplied_sa: Option<&SaParameters>,
    ) -> Result<SaState, OutboundSaBindingError> {
        let expected_policy = expected_policy(expectation);
        let observed_policy = match self
            .query_policy_for_outbound_binding(expected_policy)
            .await
        {
            Ok(policy) => policy,
            Err(XfrmError::NotFound) => {
                return readback_mismatch("xfrm_outbound_sa_binding_current_policy_missing")
            }
            Err(source) => return Err(OutboundSaBindingError::Readback { source }),
        };
        if observed_policy.parameters != *expected_policy {
            return readback_mismatch("xfrm_outbound_sa_binding_current_policy_mismatch");
        }

        let expected_sa = expected_sa(expectation);
        let observed_sa_body = match self.query_sa_for_outbound_binding(expected_sa).await {
            Ok(body) => body,
            Err(XfrmError::NotFound) => {
                return readback_mismatch("xfrm_outbound_sa_binding_current_sa_missing")
            }
            Err(source) => return Err(OutboundSaBindingError::Readback { source }),
        };
        let observed_sa =
            match parse_outbound_sa_binding_snapshot(&observed_sa_body, expectation, supplied_sa) {
                Ok(sa) => sa,
                Err(XfrmError::UnsupportedFeature {
                    feature: XFRM_KEY_READBACK_REDACTED,
                }) => {
                    return readback_mismatch("xfrm_outbound_sa_binding_key_readback_unavailable");
                }
                Err(_) => {
                    return readback_mismatch("xfrm_outbound_sa_binding_current_sa_mismatch");
                }
            };
        let dscp_profile = self
            .inner
            .dscp_config
            .as_ref()
            .map(LinuxXfrmDscpMarkingConfig::profile)
            .transpose()
            .map_err(|source| OutboundSaBindingError::Readback { source })?;
        let expected_output_mark = compose_output_mark(expected_sa, dscp_profile)
            .map_err(|source| OutboundSaBindingError::Readback { source })?;
        let expected_identity = SaRelocationIdentity {
            selector: SaRelocationSelector::from_selector(&expected_sa.selector),
            id: expected_sa.id,
            source_address: expected_sa.source_address,
            request_id: expected_sa.request_id,
            mode: expected_sa.mode,
            encap: expected_sa.encap,
            mark: expected_sa.mark,
            if_id: expected_sa.if_id,
            output_mark: expected_output_mark,
        };
        if observed_sa.identity != expected_identity
            || observed_sa.state.lifetime_config != expected_sa.lifetime
            || observed_sa.state.replay_window != expected_sa.replay_window
        {
            return readback_mismatch("xfrm_outbound_sa_binding_current_sa_mismatch");
        }

        Ok(observed_sa.state)
    }

    async fn reconcile_sa_relocation(
        &self,
        request: &RelocateSaRequest,
        before: &SaRelocationSnapshot,
        ack_error: Option<XfrmError>,
    ) -> Result<(), XfrmError> {
        let relocated_id = relocated_sa_id(request);
        let relocated = self
            .query_sa_for_relocation(relocated_id, request.current.mark, "relocate_sa_readback")
            .await;
        let relocated_matches = relocated
            .as_ref()
            .is_ok_and(|state| relocated_state_matches(request, before, state));

        let Some(error) = ack_error else {
            if !relocated_matches {
                return Err(XfrmError::StateIndeterminate {
                    operation: "relocate_sa_readback",
                });
            }

            if relocated_id != request.current.id {
                let old = self
                    .query_sa_for_relocation(
                        request.current.id,
                        request.current.mark,
                        "relocate_sa_reconcile",
                    )
                    .await;
                if !matches!(old, Err(XfrmError::NotFound)) {
                    return Err(XfrmError::StateIndeterminate {
                        operation: "relocate_sa_reconcile",
                    });
                }
            }

            self.record_sa_relocation_capability(XfrmCapability::Available);
            return Ok(());
        };

        let old_intact = if relocated_id == request.current.id {
            if relocated_matches {
                self.record_sa_relocation_capability(XfrmCapability::Available);
                return Ok(());
            }
            relocated
                .as_ref()
                .is_ok_and(|state| original_state_matches(before, state))
        } else {
            let old = self
                .query_sa_for_relocation(
                    request.current.id,
                    request.current.mark,
                    "relocate_sa_reconcile",
                )
                .await;

            if relocated_matches && matches!(&old, Err(XfrmError::NotFound)) {
                self.record_sa_relocation_capability(XfrmCapability::Available);
                return Ok(());
            }

            matches!(relocated, Err(XfrmError::NotFound))
                && old
                    .as_ref()
                    .is_ok_and(|state| original_state_matches(before, state))
        };

        if !old_intact {
            return Err(XfrmError::StateIndeterminate {
                operation: "relocate_sa_reconcile",
            });
        }

        if error.raw_os_error() == Some(LINUX_ENOPROTOOPT) {
            self.record_sa_relocation_capability(XfrmCapability::Missing);
            return Err(XfrmError::UnsupportedFeature {
                feature: "sa_relocation",
            });
        }
        Err(error)
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
        if request.parameters.output_mark.is_some() || request.parameters.egress_dscp.is_some() {
            // The ACK linearizes acceptance of this NEWSA request, while the
            // subsequent redacted GETSA proves only the current identity and
            // output-mark attributes. It cannot establish cryptographic
            // ownership, and an external UPDSA may race after the ACK. Never
            // issue a compensating DELSA on readback failure: that could
            // delete a newer same-identity SA installed by another writer.
            let operation = if request.parameters.egress_dscp.is_some() {
                "install_sa_dscp_readback"
            } else {
                "install_sa_output_mark_readback"
            };
            self.verify_output_mark_readback(&request.parameters, profile, operation)
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

    async fn query_sa_relocation_identity(
        &self,
        request: QuerySaRequest,
    ) -> Result<SaRelocationIdentity, XfrmError> {
        validate_sa_query(request)?;
        let snapshot = self
            .query_sa_for_relocation(
                XfrmId {
                    destination: request.destination,
                    spi: request.spi,
                    protocol: request.protocol,
                },
                request.mark,
                "query_sa_relocation_identity",
            )
            .await?;
        Ok(snapshot.identity)
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
        if request.parameters.output_mark.is_some() || request.parameters.egress_dscp.is_some() {
            // An update replaces pre-existing state, and `SaState`
            // intentionally excludes key material, so a safe automatic
            // rollback cannot reconstruct the old SA. Any failed mandatory
            // readback therefore remains explicitly indeterminate.
            let operation = if request.parameters.egress_dscp.is_some() {
                "rekey_sa_dscp_readback"
            } else {
                "rekey_sa_output_mark_readback"
            };
            self.verify_output_mark_readback(&request.parameters, profile, operation)
                .await?;
        }
        Ok(())
    }

    async fn relocate_sa(&self, request: RelocateSaRequest) -> Result<(), XfrmError> {
        validate_relocate_sa_request(&request)?;
        let before = self
            .query_sa_for_relocation(
                request.current.id,
                request.current.mark,
                "relocate_sa_preflight",
            )
            .await?;
        if request.current != before.identity {
            return Err(XfrmError::StateMismatch {
                operation: "relocate_sa_preflight",
            });
        }

        let relocated_id = relocated_sa_id(&request);
        if relocated_id != request.current.id {
            match self
                .query_sa_for_relocation(
                    relocated_id,
                    request.current.mark,
                    "relocate_sa_destination_preflight",
                )
                .await
            {
                Err(XfrmError::NotFound) => {}
                Ok(_) => return Err(XfrmError::AlreadyExists),
                Err(error) => return Err(error),
            }
        }

        let body = encode_relocate_sa_request(&request)?;
        let ack_error = self
            .transact_blocking(
                "relocate_sa",
                XFRM_MSG_MIGRATE_STATE,
                NLM_F_REQUEST | NLM_F_ACK,
                body,
            )
            .await
            .err();
        self.reconcile_sa_relocation(&request, &before, ack_error)
            .await
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
        self.ensure_namespace_binding()?;
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

    async fn sa_relocation_capability(&self) -> Result<XfrmCapability, XfrmError> {
        self.ensure_namespace_binding()?;
        let probe = self.inner.transport.probe(self.inner.config);
        if !probe.platform_supported {
            return Ok(XfrmCapability::Missing);
        }
        if !probe.net_admin_capable {
            return Ok(XfrmCapability::PermissionDenied);
        }
        let current = self.current_sa_relocation_capability();
        if current != XfrmCapability::UnknownUntilUse {
            return Ok(current);
        }

        let result = self
            .transact_blocking(
                "sa_relocation_capability_probe",
                XFRM_MSG_MIGRATE_STATE,
                NLM_F_REQUEST | NLM_F_ACK,
                encode_sa_relocation_capability_probe()?,
            )
            .await;
        let capability = match result {
            Err(XfrmError::NotFound) => XfrmCapability::Available,
            Err(error)
                if matches!(error.raw_os_error(), Some(LINUX_EINVAL | LINUX_ENOPROTOOPT)) =>
            {
                XfrmCapability::Missing
            }
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(XfrmError::io(
                    "sa_relocation_capability_probe",
                    invalid_data("unexpected successful missing-SA probe"),
                ));
            }
        };
        self.record_sa_relocation_capability(capability);
        Ok(capability)
    }
}

pub(crate) trait LinuxXfrmTransport: Send + Sync + fmt::Debug {
    fn transact(
        &self,
        operation: &'static str,
        operation_class: NetlinkOperationClass,
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
        operation_class: NetlinkOperationClass,
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

        receive_netlink_response(
            operation,
            operation_class,
            expected_sequence,
            config,
            |buffer| receive_message_outcome(&socket, buffer),
        )
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

fn receive_netlink_response(
    operation: &'static str,
    operation_class: NetlinkOperationClass,
    expected_sequence: u32,
    config: LinuxXfrmBackendConfig,
    mut receive: impl FnMut(&mut [u8]) -> io::Result<ReceiveMessageOutcome>,
) -> Result<Option<SensitiveBuffer>, XfrmError> {
    let mut buffer = Zeroizing::new(vec![0_u8; config.receive_buffer_len]);
    for _ in 0..config.receive_attempts {
        match receive(&mut buffer) {
            Ok(ReceiveMessageOutcome::Complete { bytes_received: 0 }) => {}
            Ok(ReceiveMessageOutcome::Complete { bytes_received }) => {
                let response = buffer.get(..bytes_received).ok_or_else(|| {
                    XfrmError::io(
                        "netlink_receive",
                        invalid_data("receive length exceeded bounded buffer"),
                    )
                })?;
                return parse_netlink_response(response, expected_sequence);
            }
            Ok(ReceiveMessageOutcome::ConsumedOversize {
                buffer_bytes,
                datagram_bytes,
            }) => {
                return Err(match operation_class {
                    NetlinkOperationClass::Mutation => XfrmError::StateIndeterminate { operation },
                    NetlinkOperationClass::ReadOnly => XfrmError::ResponseTooLarge {
                        operation,
                        buffer_bytes,
                        datagram_bytes,
                    },
                });
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(XfrmError::io("netlink_receive", error)),
            Ok(_) => {
                return Err(match operation_class {
                    NetlinkOperationClass::Mutation => XfrmError::StateIndeterminate { operation },
                    NetlinkOperationClass::ReadOnly => XfrmError::io(
                        "netlink_receive",
                        invalid_data("unsupported receive outcome"),
                    ),
                });
            }
        }
        if !config.retry_delay.is_zero() {
            std::thread::sleep(config.retry_delay);
        }
    }

    Err(XfrmError::StateIndeterminate { operation })
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
        output_mark: None,
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
    encode_sa_info_inner_observed(parameters, allow_zero_spi, dscp_profile, |_, _, _| {})
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaEncodingAllocationStage {
    BeforeSensitiveAttributes,
    Complete,
}

#[derive(Debug, Clone, Copy)]
struct SaEncodingPlan {
    encoded_len: usize,
    output_mark: Option<XfrmMark>,
}

fn encode_sa_info_inner_observed(
    parameters: &SaParameters,
    allow_zero_spi: bool,
    dscp_profile: Option<MarkProfile>,
    mut observe_allocation: impl FnMut(SaEncodingAllocationStage, *const u8, usize),
) -> Result<SensitiveBuffer, XfrmError> {
    validate_sa_parameters(parameters, allow_zero_spi)?;
    let plan = sa_encoding_plan(parameters, dscp_profile)?;
    let family = address_family(parameters.id.destination);
    let mut out = sensitive_buffer_with_capacity(plan.encoded_len);
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
    let flags = encode_sa_flags(parameters);
    // Linux requires the legacy one-byte replay window to be zero whenever
    // ESN is selected. The complete window belongs exclusively to
    // XFRMA_REPLAY_ESN_VAL in that profile.
    let fixed_replay_window = encode_fixed_replay_window(parameters);
    push_u8(&mut out, fixed_replay_window);
    push_u8(&mut out, flags);
    out.resize(XFRM_USER_SA_INFO_LEN, 0);

    observe_allocation(
        SaEncodingAllocationStage::BeforeSensitiveAttributes,
        out.as_ptr(),
        out.capacity(),
    );
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
    if let Some(output_mark) = plan.output_mark {
        append_attr(&mut out, XFRMA_SET_MARK, &output_mark.value.to_ne_bytes())?;
        append_attr(
            &mut out,
            XFRMA_SET_MARK_MASK,
            &output_mark.mask.to_ne_bytes(),
        )?;
    }
    if out.len() != plan.encoded_len {
        return Err(XfrmError::io(
            "sa_encode",
            invalid_data("encoded SA length differed from checked plan"),
        ));
    }
    observe_allocation(
        SaEncodingAllocationStage::Complete,
        out.as_ptr(),
        out.capacity(),
    );
    Ok(out)
}

fn sa_encoding_plan(
    parameters: &SaParameters,
    dscp_profile: Option<MarkProfile>,
) -> Result<SaEncodingPlan, XfrmError> {
    let output_mark = compose_output_mark(parameters, dscp_profile)?;
    let mut encoded_len = XFRM_USER_SA_INFO_LEN;

    if let Some((auth, key)) = &parameters.auth {
        let _ = encode_algorithm_name(&auth.name)?;
        validate_key_material(key.as_bytes())?;
        if auth.truncation_len_bits == 0 {
            return Err(XfrmError::invalid_config(
                "auth.truncation_len_bits",
                "truncation length must be nonzero",
            ));
        }
        checked_add_sa_attr(
            &mut encoded_len,
            checked_algorithm_payload_len(XFRM_ALGO_AUTH_HEADER_LEN, key.len())?,
        )?;
    }
    if let Some((algorithm, key)) = &parameters.crypt {
        let _ = encode_algorithm_name(&algorithm.name)?;
        validate_encryption_key_material(&algorithm.name, key.as_bytes())?;
        checked_add_sa_attr(
            &mut encoded_len,
            checked_algorithm_payload_len(XFRM_ALGO_HEADER_LEN, key.len())?,
        )?;
    }
    if let Some((aead, key)) = &parameters.aead {
        let _ = encode_algorithm_name(&aead.name)?;
        validate_key_material(key.as_bytes())?;
        if aead.icv_len_bits == 0 {
            return Err(XfrmError::invalid_config(
                "aead.icv_len_bits",
                "icv length must be nonzero",
            ));
        }
        checked_add_sa_attr(
            &mut encoded_len,
            checked_algorithm_payload_len(XFRM_ALGO_AEAD_HEADER_LEN, key.len())?,
        )?;
    }
    if parameters.encap.is_some() {
        checked_add_sa_attr(&mut encoded_len, XFRM_ENCAP_TEMPLATE_LEN)?;
    }
    if let Some(replay_payload_len) = replay_state_payload_len(parameters)? {
        checked_add_sa_attr(&mut encoded_len, replay_payload_len)?;
    }
    if parameters.mark.is_some() {
        checked_add_sa_attr(&mut encoded_len, XFRM_MARK_LEN)?;
    }
    if parameters.if_id.is_some() {
        checked_add_sa_attr(&mut encoded_len, size_of::<u32>())?;
    }
    if output_mark.is_some() {
        checked_add_sa_attr(&mut encoded_len, size_of::<u32>())?;
        checked_add_sa_attr(&mut encoded_len, size_of::<u32>())?;
    }

    Ok(SaEncodingPlan {
        encoded_len,
        output_mark,
    })
}

fn checked_algorithm_payload_len(header_len: usize, key_len: usize) -> Result<usize, XfrmError> {
    header_len
        .checked_add(key_len)
        .ok_or_else(|| XfrmError::invalid_config("netlink.attr", "attribute length overflow"))
}

fn replay_state_payload_len(parameters: &SaParameters) -> Result<Option<usize>, XfrmError> {
    let (esn, bitmap_words) = match parameters.replay_state.as_ref() {
        Some(replay_state) => (replay_state.esn, replay_state.bitmap.len()),
        None if parameters.replay_window > 32 => {
            (true, parameters.replay_window.div_ceil(32).max(1) as usize)
        }
        None => return Ok(None),
    };
    if !esn {
        return Ok(Some(XFRM_REPLAY_STATE_LEN));
    }
    let bitmap_len = bitmap_words.checked_mul(size_of::<u32>()).ok_or_else(|| {
        XfrmError::invalid_config("replay_state.bitmap", "bitmap length overflow")
    })?;
    XFRM_REPLAY_STATE_ESN_BASE_LEN
        .checked_add(bitmap_len)
        .map(Some)
        .ok_or_else(|| XfrmError::invalid_config("replay_state.bitmap", "bitmap length overflow"))
}

fn checked_add_sa_attr(encoded_len: &mut usize, payload_len: usize) -> Result<(), XfrmError> {
    let length = ROUTE_ATTRIBUTE_HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| XfrmError::invalid_config("netlink.attr", "attribute length overflow"))?;
    let _ = u16::try_from(length)
        .map_err(|_| XfrmError::invalid_config("netlink.attr", "attribute length overflow"))?;
    let aligned = align_to_netlink(length)
        .ok_or_else(|| XfrmError::invalid_config("netlink.attr", "attribute length overflow"))?;
    *encoded_len = encoded_len
        .checked_add(aligned)
        .ok_or_else(|| XfrmError::invalid_config("netlink.length", "message length overflow"))?;
    Ok(())
}

fn compose_output_mark(
    parameters: &SaParameters,
    dscp_profile: Option<MarkProfile>,
) -> Result<Option<XfrmMark>, XfrmError> {
    let Some(dscp) = parameters.egress_dscp else {
        return Ok(parameters.output_mark);
    };
    let profile = dscp_profile.ok_or(XfrmError::UnsupportedFeature {
        feature: "fixed_outer_dscp",
    })?;
    validate_fixed_outer_dscp(parameters, profile, dscp)?;
    let token = profile.encode_token(dscp.get()).ok_or_else(|| {
        XfrmError::invalid_config("sa.egress_dscp", "DSCP must be between 0 and 63")
    })?;
    Ok(Some(match parameters.output_mark {
        Some(output_mark) => XfrmMark {
            value: output_mark.value | token,
            mask: output_mark.mask | profile.mask,
        },
        None => XfrmMark {
            value: token,
            mask: profile.mask,
        },
    }))
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

fn encode_sa_replay_update(
    parameters: &SaParameters,
    replay_state: &SaReplayState,
) -> Result<SensitiveBuffer, XfrmError> {
    if parameters.id.protocol != IPPROTO_ESP || parameters.id.spi == 0 {
        return Err(XfrmError::invalid_config(
            "sa.id",
            "replay update requires a nonzero ESP SA",
        ));
    }
    validate_replay_state(replay_state, parameters.replay_window)?;
    if replay_state.esn != sa_uses_esn(parameters) {
        return Err(XfrmError::invalid_config(
            "replay_state.esn",
            "replay mode must match the installed SA",
        ));
    }

    let mut out = sensitive_buffer_with_capacity(XFRM_AEVENT_ID_LEN + 128);
    // struct xfrm_usersa_id
    encode_address(&mut out, parameters.id.destination);
    push_u32_be(&mut out, parameters.id.spi);
    push_u16_ne(&mut out, address_family(parameters.id.destination));
    push_u8(&mut out, parameters.id.protocol);
    push_u8(&mut out, 0);
    // struct xfrm_aevent_id trailing fields
    encode_address(&mut out, parameters.source_address);
    push_u32_ne(&mut out, XFRM_AE_RVAL);
    push_u32_ne(
        &mut out,
        parameters.request_id.map_or(0, XfrmRequestId::get),
    );
    debug_assert_eq!(out.len(), XFRM_AEVENT_ID_LEN);

    if replay_state.esn {
        append_attr(
            &mut out,
            XFRMA_REPLAY_ESN_VAL,
            &encode_replay_state_esn(replay_state)?,
        )?;
    } else {
        append_attr(
            &mut out,
            XFRMA_REPLAY_VAL,
            &encode_replay_state_legacy(replay_state)?,
        )?;
    }
    if let Some(mark) = parameters.mark {
        append_attr(&mut out, XFRMA_MARK, &encode_mark(mark))?;
    }
    Ok(out)
}

fn encode_relocate_sa_request(request: &RelocateSaRequest) -> Result<SensitiveBuffer, XfrmError> {
    validate_relocate_sa_request(request)?;
    let encap_attr_len = match request.encap {
        SaRelocationEncap::Preserve => 0,
        SaRelocationEncap::Set(_) | SaRelocationEncap::Remove => {
            ROUTE_ATTRIBUTE_HEADER_LEN + XFRM_ENCAP_TEMPLATE_LEN
        }
    };
    let mut out = sensitive_buffer_with_capacity(XFRM_USER_MIGRATE_STATE_LEN + encap_attr_len);

    encode_address(&mut out, request.current.id.destination);
    push_u32_be(&mut out, request.current.id.spi);
    push_u16_ne(&mut out, address_family(request.current.id.destination));
    push_u8(&mut out, request.current.id.protocol);
    push_u8(&mut out, 0);
    encode_address(&mut out, request.new_destination);
    encode_address(&mut out, request.new_source_address);
    out.extend_from_slice(&request.current.mark.map_or([0; XFRM_MARK_LEN], encode_mark));
    encode_sa_relocation_selector(&mut out, &request.current.selector)?;
    push_u32_ne(
        &mut out,
        request.current.request_id.map_or(0, XfrmRequestId::get),
    );
    push_u32_ne(&mut out, 0);
    push_u16_ne(&mut out, address_family(request.new_destination));
    push_u16_ne(&mut out, 0);
    debug_assert_eq!(out.len(), XFRM_USER_MIGRATE_STATE_LEN);

    match request.encap {
        SaRelocationEncap::Preserve => {}
        SaRelocationEncap::Set(encap) => {
            append_attr(&mut out, XFRMA_ENCAP, encode_udp_encap(encap).as_slice())?;
        }
        SaRelocationEncap::Remove => {
            append_attr(&mut out, XFRMA_ENCAP, &[0; XFRM_ENCAP_TEMPLATE_LEN])?;
        }
    }
    Ok(out)
}

fn encode_sa_relocation_capability_probe() -> Result<SensitiveBuffer, XfrmError> {
    let unspecified = IpAddress::Ipv4([0; 4]);
    let selector = SaRelocationSelector {
        source: unspecified,
        destination: unspecified,
        source_port: 0,
        source_port_mask: 0,
        destination_port: 0,
        destination_port_mask: 0,
        protocol: 0,
        source_prefix_len: 0,
        destination_prefix_len: 0,
        ifindex: 0,
        user_id: 0,
    };
    let mut out = sensitive_buffer_with_capacity(XFRM_USER_MIGRATE_STATE_LEN);

    // The upstream feature probe requires a non-zero, non-existent SPI. An
    // old protocol value of zero is deliberately used because Linux rejects
    // protocol zero when installing an SA, making this lookup collision-free
    // even in a live namespace. The new-family and selector fields remain
    // structurally valid so a supporting kernel reaches lookup and returns
    // ESRCH rather than rejecting the probe itself.
    encode_address(&mut out, unspecified);
    push_u32_be(&mut out, SA_RELOCATION_PROBE_SPI);
    push_u16_ne(&mut out, AF_INET);
    push_u8(&mut out, 0);
    push_u8(&mut out, 0);
    encode_address(&mut out, unspecified);
    encode_address(&mut out, unspecified);
    let old_mark_end = out.len() + XFRM_MARK_LEN;
    out.resize(old_mark_end, 0);
    encode_sa_relocation_selector(&mut out, &selector)?;
    push_u32_ne(&mut out, 0);
    push_u32_ne(&mut out, 0);
    push_u16_ne(&mut out, AF_INET);
    push_u16_ne(&mut out, 0);
    debug_assert_eq!(out.len(), XFRM_USER_MIGRATE_STATE_LEN);
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

fn encode_policy_query(parameters: &PolicyParameters) -> Result<SensitiveBuffer, XfrmError> {
    validate_selector_family(&parameters.selector)?;
    let mut out = sensitive_buffer_with_capacity(
        XFRM_USER_POLICY_ID_LEN
            + parameters
                .mark
                .map_or(0, |_| ROUTE_ATTRIBUTE_HEADER_LEN + XFRM_MARK_LEN)
            + parameters
                .if_id
                .map_or(0, |_| ROUTE_ATTRIBUTE_HEADER_LEN + 4),
    );
    encode_selector(&mut out, &parameters.selector)?;
    push_u32_ne(&mut out, 0);
    push_u8(&mut out, encode_direction(parameters.direction));
    out.resize(XFRM_USER_POLICY_ID_LEN, 0);
    append_common_attrs(&mut out, parameters.mark, parameters.if_id)?;
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
    let start = out.len();
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
    debug_assert_eq!(out.len() - start, XFRM_SELECTOR_LEN);
    Ok(())
}

fn encode_sa_relocation_selector(
    out: &mut Vec<u8>,
    selector: &SaRelocationSelector,
) -> Result<(), XfrmError> {
    let start = out.len();
    encode_address(out, selector.destination);
    encode_address(out, selector.source);
    push_u16_be(out, selector.destination_port);
    push_u16_be(out, selector.destination_port_mask);
    push_u16_be(out, selector.source_port);
    push_u16_be(out, selector.source_port_mask);
    push_u16_ne(out, address_family(selector.source));
    push_u8(out, selector.destination_prefix_len);
    push_u8(out, selector.source_prefix_len);
    push_u8(out, selector.protocol);
    out.resize(out.len() + 3, 0);
    push_i32_ne(out, selector.ifindex);
    push_u32_ne(out, selector.user_id);
    if out.len() - start != XFRM_SELECTOR_LEN {
        return Err(XfrmError::io(
            "relocate_sa_encode",
            invalid_data("invalid exact selector encoding length"),
        ));
    }
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
    let encoded_name = encode_algorithm_name(name)?;
    validate_encryption_key_material(name, key)?;
    let mut out = sensitive_buffer_with_capacity(XFRM_ALGO_HEADER_LEN + key.len());
    out.extend_from_slice(&encoded_name);
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
    if sa_uses_esn(parameters) {
        XFRM_STATE_ESN
    } else {
        0
    }
}

fn encode_fixed_replay_window(parameters: &SaParameters) -> u8 {
    if encode_sa_flags(parameters) & XFRM_STATE_ESN != 0 {
        0
    } else {
        parameters.replay_window.min(u32::from(u8::MAX)) as u8
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
    let bitmap_len = replay_state
        .bitmap
        .len()
        .checked_mul(size_of::<u32>())
        .ok_or_else(|| {
            XfrmError::invalid_config("replay_state.bitmap", "bitmap length overflow")
        })?;
    let capacity = XFRM_REPLAY_STATE_ESN_BASE_LEN
        .checked_add(bitmap_len)
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
    let output_mark = parse_output_mark_attrs(payload)?;
    let egress_dscp = parse_fixed_outer_dscp(output_mark, dscp_profile)?;
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
        output_mark,
        egress_dscp,
    })
}

fn parse_sa_relocation_snapshot(payload: &[u8]) -> Result<SaRelocationSnapshot, XfrmError> {
    validate_route_attribute_stream(
        payload,
        XFRM_USER_SA_INFO_LEN,
        "query_sa_relocation_identity",
    )?;
    let state = parse_sa_state(payload, None)?;
    let identity = SaRelocationIdentity {
        selector: decode_sa_relocation_selector(payload, 0)?,
        id: state.id,
        source_address: state.source_address,
        request_id: state.request_id,
        mode: state.mode,
        encap: parse_udp_encap_attr(payload)?,
        mark: parse_lookup_mark_attr(payload)?,
        if_id: parse_if_id_attr(payload)?,
        output_mark: state.output_mark,
    };
    Ok(SaRelocationSnapshot { state, identity })
}

fn parse_esp_peer_observation_registration(
    payload: &[u8],
    requested: EspPeerObservationKey,
) -> Result<EspPeerObservationRegistration, XfrmError> {
    const OPERATION: &str = "query_esp_peer_observation_registration";

    validate_allowed_route_attributes(
        payload,
        XFRM_USER_SA_INFO_LEN,
        &[
            XFRMA_ALG_AUTH,
            XFRMA_ALG_AUTH_TRUNC,
            XFRMA_ALG_CRYPT,
            XFRMA_ENCAP,
            XFRMA_REPLAY_VAL,
            XFRMA_LASTUSED,
            XFRMA_ALG_AEAD,
            XFRMA_MARK,
            XFRMA_REPLAY_ESN_VAL,
            XFRMA_PAD,
            XFRMA_OFFLOAD_DEV,
            XFRMA_SET_MARK,
            XFRMA_SET_MARK_MASK,
            XFRMA_IF_ID,
            XFRMA_SA_DIR,
        ],
        OPERATION,
    )?;
    if unique_route_attribute(payload, XFRM_USER_SA_INFO_LEN, XFRMA_OFFLOAD_DEV, OPERATION)?
        .is_some()
    {
        return Err(XfrmError::UnsupportedFeature {
            feature: "esp_peer_observation_xfrm_offload",
        });
    }

    let snapshot = parse_sa_relocation_snapshot(payload)?;
    if snapshot.state.id != requested.id {
        return Err(XfrmError::StateMismatch {
            operation: OPERATION,
        });
    }
    if snapshot.identity.if_id != requested.if_id
        || !observation_mark_selects(requested.mark, snapshot.identity.mark)
    {
        return Err(XfrmError::StateMismatch {
            operation: OPERATION,
        });
    }
    if snapshot.identity.mark.is_some_and(|mark| mark.mask == 0)
        || snapshot.identity.if_id == Some(0)
    {
        return Err(XfrmError::io(
            OPERATION,
            invalid_data("noncanonical SA identity"),
        ));
    }

    if let Some(direction) =
        unique_route_attribute(payload, XFRM_USER_SA_INFO_LEN, XFRMA_SA_DIR, OPERATION)?
    {
        if direction != [XFRM_SA_DIR_IN] {
            return Err(XfrmError::StateMismatch {
                operation: OPERATION,
            });
        }
    }
    validate_esp_peer_observation_replay(payload)?;
    if snapshot.state.source_address.is_unspecified()
        || snapshot.state.id.destination.is_unspecified()
        || family_of_ip(snapshot.state.source_address)
            != family_of_ip(snapshot.state.id.destination)
    {
        return Err(XfrmError::io(
            OPERATION,
            invalid_data("invalid SA outer address"),
        ));
    }

    let encap = snapshot
        .identity
        .encap
        .ok_or(XfrmError::UnsupportedFeature {
            feature: "esp_peer_observation_requires_esp_in_udp",
        })?;
    encap
        .validate_esp_in_udp()
        .map_err(|_| XfrmError::UnsupportedFeature {
            feature: "esp_peer_observation_requires_esp_in_udp",
        })?;
    validate_esp_peer_observation_crypto(payload)?;

    Ok(EspPeerObservationRegistration {
        key: EspPeerObservationKey {
            id: snapshot.state.id,
            mark: snapshot.identity.mark,
            if_id: snapshot.identity.if_id,
            direction: XfrmDirection::In,
        },
        current_outer_source: snapshot.state.source_address,
        current_outer_source_port: encap.source_port,
        integrity_protected: true,
    })
}

fn observation_mark_selects(requested: Option<XfrmMark>, observed: Option<XfrmMark>) -> bool {
    match (requested, observed) {
        (None, None) => true,
        (Some(requested), Some(observed)) => {
            requested.mask == observed.mask
                && requested.value & observed.mask == observed.value & observed.mask
        }
        _ => false,
    }
}

fn validate_esp_peer_observation_crypto(payload: &[u8]) -> Result<(), XfrmError> {
    const OPERATION: &str = "query_esp_peer_observation_registration";

    let legacy_auth =
        unique_route_attribute(payload, XFRM_USER_SA_INFO_LEN, XFRMA_ALG_AUTH, OPERATION)?
            .map(|attribute| parse_observed_sa_algorithm(attribute, XFRM_ALGO_HEADER_LEN))
            .transpose()?;
    let auth = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ALG_AUTH_TRUNC,
        OPERATION,
    )?
    .map(parse_observed_sa_auth)
    .transpose()?;
    let crypt = unique_route_attribute(payload, XFRM_USER_SA_INFO_LEN, XFRMA_ALG_CRYPT, OPERATION)?
        .map(|attribute| parse_observed_sa_algorithm(attribute, XFRM_ALGO_HEADER_LEN))
        .transpose()?;
    let aead = unique_route_attribute(payload, XFRM_USER_SA_INFO_LEN, XFRMA_ALG_AEAD, OPERATION)?
        .map(parse_observed_sa_aead)
        .transpose()?;

    if let Some(aead) = aead {
        if legacy_auth.is_some() || auth.is_some() || crypt.is_some() {
            return Err(XfrmError::io(
                OPERATION,
                invalid_data("contradictory SA algorithm attributes"),
            ));
        }
        if aead.icv_len_bits == 0 || aead.algorithm.key.is_empty() || aead.algorithm.name.is_empty()
        {
            return Err(XfrmError::UnsupportedFeature {
                feature: "esp_peer_observation_unauthenticated_sa",
            });
        }
        return Ok(());
    }

    let auth = auth.ok_or(XfrmError::UnsupportedFeature {
        feature: "esp_peer_observation_unauthenticated_sa",
    })?;
    if crypt.is_none()
        || auth.truncation_len_bits == 0
        || auth.algorithm.key.is_empty()
        || auth.algorithm.name.is_empty()
        || auth.algorithm.name == "digest_null"
    {
        return Err(XfrmError::UnsupportedFeature {
            feature: "esp_peer_observation_unauthenticated_sa",
        });
    }
    if let Some(legacy_auth) = legacy_auth {
        let redundant_key_matches = bool::from(legacy_auth.key.ct_eq(auth.algorithm.key));
        if legacy_auth.name != auth.algorithm.name || !redundant_key_matches {
            return Err(XfrmError::io(
                OPERATION,
                invalid_data("contradictory SA authentication attributes"),
            ));
        }
    }
    Ok(())
}

fn validate_esp_peer_observation_replay(payload: &[u8]) -> Result<(), XfrmError> {
    const OPERATION: &str = "query_esp_peer_observation_registration";

    let legacy =
        unique_route_attribute(payload, XFRM_USER_SA_INFO_LEN, XFRMA_REPLAY_VAL, OPERATION)?;
    let extended = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_REPLAY_ESN_VAL,
        OPERATION,
    )?;
    if legacy.is_some() && extended.is_some() {
        return Err(XfrmError::io(
            OPERATION,
            invalid_data("contradictory SA replay attributes"),
        ));
    }

    let fixed_window = u32::from(read_u8(payload, 215)?);
    let esn_flag = read_u8(payload, 216)? & XFRM_STATE_ESN != 0;
    let enabled = if let Some(extended) = extended {
        decode_replay_state_esn(extended)?.replay_window > 0
    } else if let Some(legacy) = legacy {
        !esn_flag && decode_replay_state_legacy(legacy, fixed_window)?.replay_window > 0
    } else {
        !esn_flag && fixed_window > 0
    };
    if !enabled {
        return Err(XfrmError::UnsupportedFeature {
            feature: "esp_peer_observation_replay_disabled",
        });
    }
    Ok(())
}

const fn family_of_ip(address: IpAddress) -> u8 {
    match address {
        IpAddress::Ipv4(_) => 4,
        IpAddress::Ipv6(_) => 6,
    }
}

fn parse_outbound_sa_binding_snapshot(
    payload: &[u8],
    expectation: &OutboundSaPolicyExpectation,
    supplied_sa: Option<&SaParameters>,
) -> Result<SaRelocationSnapshot, XfrmError> {
    let expected = expected_sa(expectation);
    validate_route_attribute_stream(payload, XFRM_USER_SA_INFO_LEN, "query_outbound_sa_binding")?;
    validate_allowed_route_attributes(
        payload,
        XFRM_USER_SA_INFO_LEN,
        &[
            XFRMA_ALG_AUTH,
            XFRMA_ALG_AUTH_TRUNC,
            XFRMA_ALG_CRYPT,
            XFRMA_ENCAP,
            XFRMA_REPLAY_VAL,
            XFRMA_LASTUSED,
            XFRMA_ALG_AEAD,
            XFRMA_MARK,
            XFRMA_REPLAY_ESN_VAL,
            XFRMA_PAD,
            XFRMA_SET_MARK,
            XFRMA_SET_MARK_MASK,
            XFRMA_IF_ID,
            XFRMA_SA_DIR,
        ],
        "query_outbound_sa_binding",
    )?;
    validate_outbound_sa_fixed_header(payload, expected, expectation.replay_esn())?;
    validate_outbound_sa_dynamic_attributes(payload)?;
    validate_outbound_sa_replay_attributes(payload, expectation.replay_esn())?;
    match supplied_sa {
        Some(supplied_sa) => validate_outbound_sa_crypto(payload, supplied_sa)?,
        None => validate_outbound_sa_crypto_metadata(payload, expectation.crypto())?,
    }
    parse_sa_relocation_snapshot(payload)
}

fn validate_outbound_sa_fixed_header(
    payload: &[u8],
    expected: &SaParameters,
    expected_esn: bool,
) -> Result<(), XfrmError> {
    if payload.len() < XFRM_USER_SA_INFO_LEN {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("short getsa response"),
        ));
    }
    let family = read_u16_ne(payload, 212)?;
    let noncanonical_ipv4 = family == AF_INET
        && (payload[60..72].iter().any(|octet| *octet != 0)
            || payload[84..96].iter().any(|octet| *octet != 0));
    if family != address_family(expected.id.destination)
        || noncanonical_ipv4
        || payload[77..80].iter().any(|octet| *octet != 0)
        // The SDK does not model soft/hard use-time expiry and always installs
        // both values as zero. They are immutable configuration, not the
        // dynamic lifetime-current timestamps at bytes 160..192.
        || payload[144..160].iter().any(|octet| *octet != 0)
        || read_u8(payload, 215)?
            != if expected_esn {
                0
            } else {
                expected.replay_window.min(u32::from(u8::MAX)) as u8
            }
        || read_u8(payload, 216)? != if expected_esn { XFRM_STATE_ESN } else { 0 }
        || payload[217..XFRM_USER_SA_INFO_LEN]
            .iter()
            .any(|octet| *octet != 0)
    {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("unsupported SA metadata"),
        ));
    }
    Ok(())
}

fn validate_outbound_sa_dynamic_attributes(payload: &[u8]) -> Result<(), XfrmError> {
    if let Some(last_used) = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_LASTUSED,
        "query_outbound_sa_binding",
    )? {
        if last_used.len() != size_of::<u64>() {
            return Err(XfrmError::io(
                "query_outbound_sa_binding",
                invalid_data("invalid last-used attribute length"),
            ));
        }
    }
    if let Some(pad) = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_PAD,
        "query_outbound_sa_binding",
    )? {
        if !pad.is_empty() {
            return Err(XfrmError::io(
                "query_outbound_sa_binding",
                invalid_data("invalid netlink alignment attribute"),
            ));
        }
    }
    if let Some(direction) = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_SA_DIR,
        "query_outbound_sa_binding",
    )? {
        if direction != [XFRM_SA_DIR_OUT] {
            return Err(XfrmError::io(
                "query_outbound_sa_binding",
                invalid_data("SA direction is not outbound"),
            ));
        }
    }
    Ok(())
}

fn validate_outbound_sa_replay_attributes(
    payload: &[u8],
    expected_esn: bool,
) -> Result<(), XfrmError> {
    let legacy = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_REPLAY_VAL,
        "query_outbound_sa_binding",
    )?;
    let esn = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_REPLAY_ESN_VAL,
        "query_outbound_sa_binding",
    )?;
    if legacy.is_some() && esn.is_some() {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("contradictory SA replay attributes"),
        ));
    }
    if expected_esn {
        let esn = esn.ok_or_else(|| {
            XfrmError::io(
                "query_outbound_sa_binding",
                invalid_data("missing ESN replay attribute"),
            )
        })?;
        let _ = decode_replay_state_esn(esn)?;
    } else {
        if esn.is_some() {
            return Err(XfrmError::io(
                "query_outbound_sa_binding",
                invalid_data("unexpected ESN replay attribute"),
            ));
        }
        if let Some(legacy) = legacy {
            let _ = decode_replay_state_legacy(legacy, u32::from(read_u8(payload, 215)?))?;
        }
    }
    Ok(())
}

struct ObservedSaAlgorithm<'a> {
    name: &'a str,
    key: &'a [u8],
}

struct ObservedSaAuth<'a> {
    algorithm: ObservedSaAlgorithm<'a>,
    truncation_len_bits: u32,
}

struct ObservedSaAead<'a> {
    algorithm: ObservedSaAlgorithm<'a>,
    icv_len_bits: u32,
}

fn validate_outbound_sa_crypto(payload: &[u8], expected: &SaParameters) -> Result<(), XfrmError> {
    // Linux GETSA emits both authentication encodings for an installed
    // truncation-aware algorithm. Treat them as one redundant assertion and
    // require both copies to match the transient zeroizing install intent.
    let legacy_auth = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ALG_AUTH,
        "query_outbound_sa_binding",
    )?
    .map(|attribute| parse_observed_sa_algorithm(attribute, XFRM_ALGO_HEADER_LEN))
    .transpose()?;
    let auth = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ALG_AUTH_TRUNC,
        "query_outbound_sa_binding",
    )?
    .map(parse_observed_sa_auth)
    .transpose()?;
    let crypt = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ALG_CRYPT,
        "query_outbound_sa_binding",
    )?
    .map(|attribute| parse_observed_sa_algorithm(attribute, XFRM_ALGO_HEADER_LEN))
    .transpose()?;
    let aead = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ALG_AEAD,
        "query_outbound_sa_binding",
    )?
    .map(parse_observed_sa_aead)
    .transpose()?;
    if aead.is_some() && (legacy_auth.is_some() || auth.is_some() || crypt.is_some()) {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("contradictory SA algorithm attributes"),
        ));
    }
    // Lockdown's `xfrm_redact()` preserves algorithm metadata but replaces
    // every nonempty key with zero octets. Netlink does not mark the response
    // as redacted, so an all-zero key is intrinsically ambiguous (including a
    // genuinely configured all-zero key). Fail closed with a stable capability
    // result instead of treating those bytes as an exact key proof.
    if legacy_auth
        .as_ref()
        .is_some_and(|algorithm| key_is_ambiguous_redaction(algorithm.key))
        || auth
            .as_ref()
            .is_some_and(|algorithm| key_is_ambiguous_redaction(algorithm.algorithm.key))
        || crypt
            .as_ref()
            .is_some_and(|algorithm| key_is_ambiguous_redaction(algorithm.key))
        || aead
            .as_ref()
            .is_some_and(|algorithm| key_is_ambiguous_redaction(algorithm.algorithm.key))
    {
        return Err(XfrmError::UnsupportedFeature {
            feature: XFRM_KEY_READBACK_REDACTED,
        });
    }

    let auth_matches = match (legacy_auth, auth, expected.auth.as_ref()) {
        (Some(legacy), Some(observed), Some((algorithm, key))) => {
            let legacy_key_matches = bool::from(legacy.key.ct_eq(key.as_bytes()));
            let trunc_key_matches = bool::from(observed.algorithm.key.ct_eq(key.as_bytes()));
            legacy.name == algorithm.name
                && legacy_key_matches
                && observed.algorithm.name == algorithm.name
                && observed.truncation_len_bits == algorithm.truncation_len_bits
                && trunc_key_matches
        }
        (None, None, None) => true,
        _ => false,
    };
    let crypt_matches = match (crypt, expected.crypt.as_ref()) {
        (Some(observed), Some((algorithm, key))) => {
            let key_matches = bool::from(observed.key.ct_eq(key.as_bytes()));
            observed.name == algorithm.name && key_matches
        }
        (None, None) => true,
        _ => false,
    };
    let aead_matches = match (aead, expected.aead.as_ref()) {
        (Some(observed), Some((algorithm, key))) => {
            let key_matches = bool::from(observed.algorithm.key.ct_eq(key.as_bytes()));
            observed.algorithm.name == algorithm.name
                && observed.icv_len_bits == algorithm.icv_len_bits
                && key_matches
        }
        (None, None) => true,
        _ => false,
    };
    if !auth_matches || !crypt_matches || !aead_matches {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("SA crypto does not match install intent"),
        ));
    }
    Ok(())
}

fn validate_outbound_sa_crypto_metadata(
    payload: &[u8],
    expected: &OutboundSaCryptoExpectation,
) -> Result<(), XfrmError> {
    let legacy_auth = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ALG_AUTH,
        "query_outbound_sa_binding",
    )?
    .map(|attribute| parse_observed_sa_algorithm(attribute, XFRM_ALGO_HEADER_LEN))
    .transpose()?;
    let auth = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ALG_AUTH_TRUNC,
        "query_outbound_sa_binding",
    )?
    .map(parse_observed_sa_auth)
    .transpose()?;
    let crypt = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ALG_CRYPT,
        "query_outbound_sa_binding",
    )?
    .map(|attribute| parse_observed_sa_algorithm(attribute, XFRM_ALGO_HEADER_LEN))
    .transpose()?;
    let aead = unique_route_attribute(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ALG_AEAD,
        "query_outbound_sa_binding",
    )?
    .map(parse_observed_sa_aead)
    .transpose()?;
    if aead.is_some() && (legacy_auth.is_some() || auth.is_some() || crypt.is_some()) {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("contradictory SA algorithm attributes"),
        ));
    }
    if legacy_auth
        .as_ref()
        .is_some_and(|algorithm| key_is_ambiguous_redaction(algorithm.key))
        || auth
            .as_ref()
            .is_some_and(|algorithm| key_is_ambiguous_redaction(algorithm.algorithm.key))
        || crypt
            .as_ref()
            .is_some_and(|algorithm| key_is_ambiguous_redaction(algorithm.key))
        || aead
            .as_ref()
            .is_some_and(|algorithm| key_is_ambiguous_redaction(algorithm.algorithm.key))
    {
        return Err(XfrmError::UnsupportedFeature {
            feature: XFRM_KEY_READBACK_REDACTED,
        });
    }

    let auth_matches = match (legacy_auth, auth, expected.auth.as_ref()) {
        (Some(legacy), Some(observed), Some(expected)) => {
            let redundant_keys_match = bool::from(legacy.key.ct_eq(observed.algorithm.key));
            legacy.name == expected.algorithm.name
                && legacy.key.len() == expected.algorithm.key_len
                && observed.algorithm.name == expected.algorithm.name
                && observed.algorithm.key.len() == expected.algorithm.key_len
                && observed.truncation_len_bits == expected.truncation_len_bits
                && redundant_keys_match
        }
        (None, None, None) => true,
        _ => false,
    };
    let crypt_matches = match (crypt, expected.crypt.as_ref()) {
        (Some(observed), Some(expected)) => {
            observed.name == expected.name && observed.key.len() == expected.key_len
        }
        (None, None) => true,
        _ => false,
    };
    let aead_matches = match (aead, expected.aead.as_ref()) {
        (Some(observed), Some(expected)) => {
            observed.algorithm.name == expected.algorithm.name
                && observed.algorithm.key.len() == expected.algorithm.key_len
                && observed.icv_len_bits == expected.icv_len_bits
        }
        (None, None) => true,
        _ => false,
    };
    if !auth_matches || !crypt_matches || !aead_matches {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("SA crypto metadata does not match binding"),
        ));
    }
    Ok(())
}

fn key_is_ambiguous_redaction(key: &[u8]) -> bool {
    !key.is_empty() && key.iter().all(|octet| *octet == 0)
}

fn parse_observed_sa_auth(payload: &[u8]) -> Result<ObservedSaAuth<'_>, XfrmError> {
    Ok(ObservedSaAuth {
        algorithm: parse_observed_sa_algorithm(payload, XFRM_ALGO_AUTH_HEADER_LEN)?,
        truncation_len_bits: read_u32_ne(payload, XFRM_ALG_NAME_LEN + 4)?,
    })
}

fn parse_observed_sa_algorithm(
    payload: &[u8],
    header_len: usize,
) -> Result<ObservedSaAlgorithm<'_>, XfrmError> {
    let key_len = parse_algorithm_key_len(payload, header_len)?;
    Ok(ObservedSaAlgorithm {
        name: parse_algorithm_name(payload)?,
        key: &payload[header_len..header_len + key_len],
    })
}

fn parse_observed_sa_aead(payload: &[u8]) -> Result<ObservedSaAead<'_>, XfrmError> {
    Ok(ObservedSaAead {
        algorithm: parse_observed_sa_algorithm(payload, XFRM_ALGO_AEAD_HEADER_LEN)?,
        icv_len_bits: read_u32_ne(payload, XFRM_ALG_NAME_LEN + 4)?,
    })
}

fn parse_algorithm_key_len(payload: &[u8], header_len: usize) -> Result<usize, XfrmError> {
    if payload.len() < header_len {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("short SA algorithm attribute"),
        ));
    }
    let key_len_bits = read_u32_ne(payload, XFRM_ALG_NAME_LEN)?;
    if key_len_bits % 8 != 0 {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("non-octet SA key length"),
        ));
    }
    let key_len = usize::try_from(key_len_bits / 8).map_err(|_| {
        XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("SA key length overflow"),
        )
    })?;
    let expected_len = header_len.checked_add(key_len).ok_or_else(|| {
        XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("SA algorithm attribute length overflow"),
        )
    })?;
    if payload.len() != expected_len {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("invalid SA algorithm attribute length"),
        ));
    }
    Ok(key_len)
}

fn parse_algorithm_name(payload: &[u8]) -> Result<&str, XfrmError> {
    let name = payload.get(..XFRM_ALG_NAME_LEN).ok_or_else(|| {
        XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("short SA algorithm name"),
        )
    })?;
    let end = name.iter().position(|octet| *octet == 0).ok_or_else(|| {
        XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("unterminated SA algorithm name"),
        )
    })?;
    if end == 0 || name[end + 1..].iter().any(|octet| *octet != 0) {
        return Err(XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("noncanonical SA algorithm name"),
        ));
    }
    std::str::from_utf8(&name[..end]).map_err(|_| {
        XfrmError::io(
            "query_outbound_sa_binding",
            invalid_data("invalid SA algorithm name"),
        )
    })
}

fn parse_policy_state(payload: &[u8]) -> Result<PolicyState, XfrmError> {
    if payload.len() < XFRM_USER_POLICY_INFO_LEN {
        return Err(XfrmError::io(
            "query_outbound_policy_binding",
            invalid_data("short getpolicy response"),
        ));
    }
    validate_route_attribute_stream(
        payload,
        XFRM_USER_POLICY_INFO_LEN,
        "query_outbound_policy_binding",
    )?;
    validate_allowed_route_attributes(
        payload,
        XFRM_USER_POLICY_INFO_LEN,
        &[XFRMA_TMPL, XFRMA_POLICY_TYPE, XFRMA_MARK, XFRMA_IF_ID],
        "query_outbound_policy_binding",
    )?;
    if decode_lifetime_config(payload, XFRM_SELECTOR_LEN)? != LifetimeConfig::default()
        || payload[104..120].iter().any(|octet| *octet != 0)
        || read_u8(payload, 162)? != 0
        || read_u8(payload, 163)? != 0
        || payload[164..XFRM_USER_POLICY_INFO_LEN]
            .iter()
            .any(|octet| *octet != 0)
    {
        return Err(XfrmError::io(
            "query_outbound_policy_binding",
            invalid_data("unsupported policy metadata"),
        ));
    }
    let exact_selector = decode_sa_relocation_selector(payload, 0)?;
    let selector = exact_selector.selector();
    if exact_selector != SaRelocationSelector::from_selector(&selector) {
        return Err(XfrmError::io(
            "query_outbound_policy_binding",
            invalid_data("noncanonical or unsupported policy selector"),
        ));
    }
    let templates = unique_route_attribute(
        payload,
        XFRM_USER_POLICY_INFO_LEN,
        XFRMA_TMPL,
        "query_outbound_policy_binding",
    )?
    .ok_or_else(|| {
        XfrmError::io(
            "query_outbound_policy_binding",
            invalid_data("missing policy template"),
        )
    })?;
    if templates.len() != XFRM_USER_TEMPLATE_LEN {
        return Err(XfrmError::io(
            "query_outbound_policy_binding",
            invalid_data("policy must contain exactly one template"),
        ));
    }
    let template = decode_exact_template(templates)?;
    let mark = parse_exact_mark_attribute(
        payload,
        XFRM_USER_POLICY_INFO_LEN,
        "query_outbound_policy_binding",
    )?;
    let if_id = parse_exact_if_id_attribute(
        payload,
        XFRM_USER_POLICY_INFO_LEN,
        "query_outbound_policy_binding",
    )?;
    if let Some(policy_type) = unique_route_attribute(
        payload,
        XFRM_USER_POLICY_INFO_LEN,
        XFRMA_POLICY_TYPE,
        "query_outbound_policy_binding",
    )? {
        // C layout is six bytes: type, one alignment byte, reserved1 (u16),
        // reserved2, and one tail-alignment byte. MAIN is therefore the
        // all-zero canonical payload.
        if policy_type != [XFRM_POLICY_TYPE_MAIN, 0, 0, 0, 0, 0] {
            return Err(XfrmError::io(
                "query_outbound_policy_binding",
                invalid_data("unsupported policy type"),
            ));
        }
    }
    Ok(PolicyState {
        parameters: PolicyParameters {
            selector,
            direction: decode_policy_direction(read_u8(payload, 160)?)?,
            action: decode_policy_action(read_u8(payload, 161)?)?,
            priority: read_u32_ne(payload, 152)?,
            templates: vec![template],
            mark,
            if_id,
        },
    })
}

fn decode_exact_template(payload: &[u8]) -> Result<XfrmTemplate, XfrmError> {
    if payload.len() != XFRM_USER_TEMPLATE_LEN {
        return Err(XfrmError::io(
            "query_outbound_policy_binding",
            invalid_data("invalid policy template length"),
        ));
    }
    let family = read_u16_ne(payload, 24)?;
    let template = XfrmTemplate {
        id: XfrmId {
            destination: decode_address(payload, 0, family)?,
            spi: read_u32_be(payload, 16)?,
            protocol: read_u8(payload, 20)?,
        },
        source_address: decode_address(payload, 28, family)?,
        request_id: XfrmRequestId::new(read_u32_ne(payload, 44)?),
        mode: decode_mode(read_u8(payload, 48)?)?,
    };
    let mut canonical = Vec::with_capacity(XFRM_USER_TEMPLATE_LEN);
    encode_template(&mut canonical, &template)?;
    if canonical != payload {
        return Err(XfrmError::io(
            "query_outbound_policy_binding",
            invalid_data("noncanonical policy template"),
        ));
    }
    Ok(template)
}

fn decode_policy_direction(direction: u8) -> Result<XfrmDirection, XfrmError> {
    match direction {
        XFRM_POLICY_IN => Ok(XfrmDirection::In),
        XFRM_POLICY_OUT => Ok(XfrmDirection::Out),
        XFRM_POLICY_FWD => Ok(XfrmDirection::Forward),
        _ => Err(XfrmError::io(
            "query_outbound_policy_binding",
            invalid_data("unsupported policy direction"),
        )),
    }
}

fn decode_policy_action(action: u8) -> Result<XfrmAction, XfrmError> {
    match action {
        XFRM_POLICY_ALLOW => Ok(XfrmAction::Allow),
        XFRM_POLICY_BLOCK => Ok(XfrmAction::Block),
        _ => Err(XfrmError::io(
            "query_outbound_policy_binding",
            invalid_data("unsupported policy action"),
        )),
    }
}

fn parse_exact_mark_attribute(
    payload: &[u8],
    base_len: usize,
    operation: &'static str,
) -> Result<Option<XfrmMark>, XfrmError> {
    let Some(mark) = unique_route_attribute(payload, base_len, XFRMA_MARK, operation)? else {
        return Ok(None);
    };
    if mark.len() != XFRM_MARK_LEN {
        return Err(XfrmError::io(
            operation,
            invalid_data("invalid lookup-mark attribute length"),
        ));
    }
    Ok(Some(XfrmMark {
        value: read_u32_ne(mark, 0)?,
        mask: read_u32_ne(mark, 4)?,
    }))
}

fn parse_exact_if_id_attribute(
    payload: &[u8],
    base_len: usize,
    operation: &'static str,
) -> Result<Option<u32>, XfrmError> {
    let Some(if_id) = unique_route_attribute(payload, base_len, XFRMA_IF_ID, operation)? else {
        return Ok(None);
    };
    if if_id.len() != 4 {
        return Err(XfrmError::io(
            operation,
            invalid_data("invalid interface-id attribute length"),
        ));
    }
    Ok(Some(read_u32_ne(if_id, 0)?))
}

fn parse_udp_encap_attr(payload: &[u8]) -> Result<Option<UdpEncap>, XfrmError> {
    let Some(encap) = find_unique_attr_payload(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_ENCAP,
        "duplicate UDP encapsulation attribute",
    )?
    else {
        return Ok(None);
    };
    if encap.len() != XFRM_ENCAP_TEMPLATE_LEN {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("invalid UDP encapsulation attribute length"),
        ));
    }
    if encap.get(6..8) != Some(&[0, 0]) {
        return Err(XfrmError::io(
            "query_sa_relocation_identity",
            invalid_data("noncanonical UDP encapsulation padding"),
        ));
    }
    if encap
        .get(8..XFRM_ENCAP_TEMPLATE_LEN)
        .is_some_and(|original_address| original_address.iter().any(|octet| *octet != 0))
    {
        return Err(XfrmError::UnsupportedFeature {
            feature: "sa_relocation_encap_original_address",
        });
    }
    Ok(Some(UdpEncap {
        encap_type: read_u16_ne(encap, 0)?,
        source_port: read_u16_be(encap, 2)?,
        destination_port: read_u16_be(encap, 4)?,
    }))
}

fn parse_lookup_mark_attr(payload: &[u8]) -> Result<Option<XfrmMark>, XfrmError> {
    let Some(mark) = find_unique_attr_payload(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_MARK,
        "duplicate lookup-mark attribute",
    )?
    else {
        return Ok(None);
    };
    if mark.len() != XFRM_MARK_LEN {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("invalid lookup-mark attribute length"),
        ));
    }
    Ok(Some(XfrmMark {
        value: read_u32_ne(mark, 0)?,
        mask: read_u32_ne(mark, 4)?,
    }))
}

fn parse_if_id_attr(payload: &[u8]) -> Result<Option<u32>, XfrmError> {
    let Some(if_id) = find_unique_attr_payload(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_IF_ID,
        "duplicate interface-id attribute",
    )?
    else {
        return Ok(None);
    };
    if if_id.len() != 4 {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("invalid interface-id attribute length"),
        ));
    }
    Ok(Some(read_u32_ne(if_id, 0)?))
}

fn parse_output_mark_attrs(payload: &[u8]) -> Result<Option<XfrmMark>, XfrmError> {
    let value = find_unique_attr_payload(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_SET_MARK,
        "duplicate output-mark value attribute",
    )?;
    let mask = find_unique_attr_payload(
        payload,
        XFRM_USER_SA_INFO_LEN,
        XFRMA_SET_MARK_MASK,
        "duplicate output-mark mask attribute",
    )?;
    let (Some(value), Some(mask)) = (value, mask) else {
        if value.is_some() || mask.is_some() {
            return Err(XfrmError::io(
                "query_sa",
                invalid_data("incomplete output-mark attributes"),
            ));
        }
        return Ok(None);
    };
    if value.len() != 4 || mask.len() != 4 {
        return Err(XfrmError::io(
            "query_sa",
            invalid_data("invalid output-mark attribute length"),
        ));
    }
    Ok(Some(XfrmMark {
        value: u32::from_ne_bytes([value[0], value[1], value[2], value[3]]),
        mask: u32::from_ne_bytes([mask[0], mask[1], mask[2], mask[3]]),
    }))
}

fn parse_fixed_outer_dscp(
    output_mark: Option<XfrmMark>,
    profile: Option<MarkProfile>,
) -> Result<Option<DscpCodepoint>, XfrmError> {
    let (Some(output_mark), Some(profile)) = (output_mark, profile) else {
        return Ok(None);
    };
    // Query has no durable record of whether an SA opted into fixed DSCP. Only
    // an exclusive, complete token window is unambiguous; every broader or
    // partial mask remains a generic output mark. Mutation readback separately
    // proves composed DSCP state by comparing the exact raw pair.
    if output_mark.mask != profile.mask || output_mark.value & !profile.mask != 0 {
        return Ok(None);
    }
    let dscp = match profile.decode_token(output_mark.value) {
        opc_ipsec_xfrm_ebpf_common::MarkToken::Dscp(dscp) => dscp,
        opc_ipsec_xfrm_ebpf_common::MarkToken::Absent
        | opc_ipsec_xfrm_ebpf_common::MarkToken::Malformed => return Ok(None),
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

fn find_unique_attr_payload<'a>(
    body: &'a [u8],
    mut offset: usize,
    attr_type: u16,
    duplicate_error: &'static str,
) -> Result<Option<&'a [u8]>, XfrmError> {
    let mut found = None;
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
            if found.is_some() {
                return Err(XfrmError::io("query_sa", invalid_data(duplicate_error)));
            }
            found = Some(&body[offset + ROUTE_ATTRIBUTE_HEADER_LEN..offset + len]);
        }
        offset += align_to_netlink(len).ok_or_else(|| {
            XfrmError::io(
                "netlink_receive",
                invalid_data("route attribute alignment overflow"),
            )
        })?;
    }
    Ok(found)
}

fn validate_route_attribute_stream(
    body: &[u8],
    mut offset: usize,
    operation: &'static str,
) -> Result<(), XfrmError> {
    if offset > body.len() {
        return Err(XfrmError::io(
            operation,
            invalid_data("route attribute offset exceeds response"),
        ));
    }
    while offset < body.len() {
        let remaining = body.len() - offset;
        if remaining < ROUTE_ATTRIBUTE_HEADER_LEN {
            return Err(XfrmError::io(
                operation,
                invalid_data("trailing route attribute bytes"),
            ));
        }
        let len = usize::from(read_u16_ne(body, offset)?);
        if len < ROUTE_ATTRIBUTE_HEADER_LEN {
            return Err(XfrmError::io(
                operation,
                invalid_data("invalid route attribute length"),
            ));
        }
        let aligned = align_to_netlink(len).ok_or_else(|| {
            XfrmError::io(
                operation,
                invalid_data("route attribute alignment overflow"),
            )
        })?;
        if aligned > remaining {
            return Err(XfrmError::io(
                operation,
                invalid_data("truncated route attribute"),
            ));
        }
        let payload_end = offset + len;
        let aligned_end = offset + aligned;
        if body[payload_end..aligned_end]
            .iter()
            .any(|octet| *octet != 0)
        {
            return Err(XfrmError::io(
                operation,
                invalid_data("noncanonical route attribute padding"),
            ));
        }
        offset = aligned_end;
    }
    Ok(())
}

fn unique_route_attribute<'a>(
    body: &'a [u8],
    base_len: usize,
    attr_type: u16,
    operation: &'static str,
) -> Result<Option<&'a [u8]>, XfrmError> {
    validate_route_attribute_stream(body, base_len, operation)?;
    let mut offset = base_len;
    let mut found = None;
    while offset < body.len() {
        let len = usize::from(read_u16_ne(body, offset)?);
        let found_type = read_u16_ne(body, offset + 2)?;
        if found_type == attr_type {
            if found.is_some() {
                return Err(XfrmError::io(
                    operation,
                    invalid_data("duplicate route attribute"),
                ));
            }
            found = Some(&body[offset + ROUTE_ATTRIBUTE_HEADER_LEN..offset + len]);
        }
        offset += align_to_netlink(len).ok_or_else(|| {
            XfrmError::io(
                operation,
                invalid_data("route attribute alignment overflow"),
            )
        })?;
    }
    Ok(found)
}

fn validate_allowed_route_attributes(
    body: &[u8],
    base_len: usize,
    allowed: &[u16],
    operation: &'static str,
) -> Result<(), XfrmError> {
    validate_route_attribute_stream(body, base_len, operation)?;
    let mut offset = base_len;
    while offset < body.len() {
        let len = usize::from(read_u16_ne(body, offset)?);
        let attr_type = read_u16_ne(body, offset + 2)?;
        if !allowed.contains(&attr_type) {
            return Err(XfrmError::io(
                operation,
                invalid_data("unsupported route attribute"),
            ));
        }
        offset += align_to_netlink(len).ok_or_else(|| {
            XfrmError::io(
                operation,
                invalid_data("route attribute alignment overflow"),
            )
        })?;
    }
    Ok(())
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
    if parameters.id.protocol == IPPROTO_ESP
        && parameters.auth.is_some()
        && parameters.crypt.is_none()
        && parameters.aead.is_none()
    {
        return Err(XfrmError::invalid_config(
            "crypt",
            "authenticated-only ESP requires the explicit Linux NULL cipher",
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
    validate_sa_output_mark(parameters.output_mark)?;
    if let Some((algorithm, _)) = &parameters.crypt {
        if is_known_aead_algorithm(&algorithm.name) {
            return Err(XfrmError::invalid_config(
                "crypt",
                "aead algorithm must use the aead slot",
            ));
        }
        if algorithm.name == crate::XFRM_ENCR_NULL && parameters.auth.is_none() {
            return Err(XfrmError::invalid_config(
                "auth",
                "NULL encryption requires a separate authentication algorithm",
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
    if let Some(output_mark) = parameters.output_mark {
        validate_output_mark_dscp_disjoint(output_mark, profile)?;
    }
    if profile.encode_token(dscp.get()).is_none() {
        return Err(XfrmError::invalid_config(
            "sa.egress_dscp",
            "DSCP must be between 0 and 63",
        ));
    }
    Ok(())
}

fn validate_output_mark_dscp_disjoint(
    output_mark: XfrmMark,
    profile: MarkProfile,
) -> Result<(), XfrmError> {
    if (output_mark.mask | output_mark.value) & profile.mask != 0 {
        return Err(XfrmError::invalid_config(
            "sa.output_mark",
            "generic output mark overlaps the reserved DSCP token window",
        ));
    }
    Ok(())
}

fn relocated_sa_id(request: &RelocateSaRequest) -> XfrmId {
    XfrmId {
        destination: request.new_destination,
        ..request.current.id
    }
}

fn original_state_matches(
    expected: &SaRelocationSnapshot,
    observed: &SaRelocationSnapshot,
) -> bool {
    observed.identity == expected.identity
        && observed.state.replay_window == expected.state.replay_window
        && observed.state.lifetime_config == expected.state.lifetime_config
        && observed.state.output_mark == expected.state.output_mark
}

fn relocated_state_matches(
    request: &RelocateSaRequest,
    before: &SaRelocationSnapshot,
    observed: &SaRelocationSnapshot,
) -> bool {
    let mut expected_identity = before.identity.clone();
    expected_identity.id = relocated_sa_id(request);
    expected_identity.source_address = request.new_source_address;
    expected_identity.encap = request.encap.resulting(before.identity.encap);

    observed.identity == expected_identity
        && observed.state.replay_window == before.state.replay_window
        && observed.state.lifetime_config == before.state.lifetime_config
        && observed.state.output_mark == before.state.output_mark
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

fn validate_encryption_key_material(name: &str, key: &[u8]) -> Result<(), XfrmError> {
    if name == crate::XFRM_ENCR_NULL {
        if key.is_empty() {
            return Ok(());
        }
        return Err(XfrmError::invalid_config(
            "crypt.key_material",
            "NULL encryption key material must be empty",
        ));
    }
    validate_key_material(key)
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

fn decode_sa_relocation_selector(
    bytes: &[u8],
    offset: usize,
) -> Result<SaRelocationSelector, XfrmError> {
    let end = offset
        .checked_add(XFRM_SELECTOR_LEN)
        .ok_or_else(|| XfrmError::io("query_sa", invalid_data("selector offset overflow")))?;
    let selector = bytes
        .get(offset..end)
        .ok_or_else(|| XfrmError::io("query_sa", invalid_data("short XFRM selector")))?;
    let family = read_u16_ne(selector, 40)?;
    if selector.get(45..48) != Some(&[0, 0, 0]) {
        return Err(XfrmError::io(
            "query_sa_relocation_identity",
            invalid_data("noncanonical XFRM selector reserved bytes"),
        ));
    }
    if family == AF_INET
        && (selector[4..16].iter().any(|octet| *octet != 0)
            || selector[20..32].iter().any(|octet| *octet != 0))
    {
        return Err(XfrmError::io(
            "query_sa_relocation_identity",
            invalid_data("noncanonical IPv4 XFRM selector address"),
        ));
    }

    let relocation_selector = SaRelocationSelector {
        destination: decode_address(selector, 0, family)?,
        source: decode_address(selector, 16, family)?,
        destination_port: read_u16_be(selector, 32)?,
        destination_port_mask: read_u16_be(selector, 34)?,
        source_port: read_u16_be(selector, 36)?,
        source_port_mask: read_u16_be(selector, 38)?,
        protocol: read_u8(selector, 44)?,
        destination_prefix_len: read_u8(selector, 42)?,
        source_prefix_len: read_u8(selector, 43)?,
        ifindex: read_i32_ne(selector, 48)?,
        user_id: read_u32_ne(selector, 52)?,
    };
    let prefix_limit = if family == AF_INET { 32 } else { 128 };
    if relocation_selector.source_prefix_len > prefix_limit
        || relocation_selector.destination_prefix_len > prefix_limit
    {
        return Err(XfrmError::io(
            "query_sa_relocation_identity",
            invalid_data("XFRM selector prefix exceeds address family"),
        ));
    }
    Ok(relocation_selector)
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

fn read_i32_ne(bytes: &[u8], offset: usize) -> Result<i32, XfrmError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("offset overflow")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| XfrmError::io("netlink_receive", invalid_data("short netlink field")))?;
    Ok(i32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
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
pub(crate) fn test_outbound_binding_readback_bodies(
    request: &crate::XfrmCompositeInstallRequest,
) -> Result<(SensitiveBuffer, SensitiveBuffer), XfrmError> {
    let mut policy = encode_policy_info(&request.policy.parameters)?;
    append_attr(
        &mut policy,
        XFRMA_POLICY_TYPE,
        &[XFRM_POLICY_TYPE_MAIN, 0, 0, 0, 0, 0],
    )?;

    let mut sa = encode_sa_info(&request.sa.parameters)?;
    if let Some((algorithm, key)) = request.sa.parameters.auth.as_ref() {
        let mut legacy = sensitive_buffer_with_capacity(XFRM_ALGO_HEADER_LEN + key.len());
        legacy.extend_from_slice(&encode_algorithm_name(&algorithm.name)?);
        push_u32_ne(&mut legacy, key_len_bits(key.as_bytes())?);
        legacy.extend_from_slice(key.as_bytes());
        append_attr(&mut sa, XFRMA_ALG_AUTH, &legacy)?;
    }
    append_attr(&mut sa, XFRMA_SA_DIR, &[XFRM_SA_DIR_OUT])?;
    Ok((policy, sa))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::outbound_binding::validate_outbound_request;
    use crate::{
        AeadAlgorithm, Algorithm, AuthAlgorithm, InstallSaRequest, KeyMaterial,
        SaRelocationDirection, XfrmCompositeInstallRequest, UDP_ENCAP_ESPINUDP,
        XFRM_AUTH_HMAC_SHA256, XFRM_ENCR_CBC_AES, XFRM_ENCR_NULL,
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
            _operation_class: NetlinkOperationClass,
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

    type ScriptedResponse = Result<Option<SensitiveBuffer>, XfrmError>;

    #[derive(Debug, Clone)]
    struct ScriptedTransport {
        requests: Arc<Mutex<Vec<SensitiveBuffer>>>,
        responses: Arc<Mutex<VecDeque<ScriptedResponse>>>,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<Result<Option<Vec<u8>>, XfrmError>>) -> Self {
            Self {
                requests: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(
                    responses
                        .into_iter()
                        .map(|response| response.map(|body| body.map(Zeroizing::new)))
                        .collect(),
                )),
            }
        }

        fn requests(&self) -> Vec<SensitiveBuffer> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl LinuxXfrmTransport for ScriptedTransport {
        fn transact(
            &self,
            _operation: &'static str,
            _operation_class: NetlinkOperationClass,
            request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(Zeroizing::new(request.to_vec()));
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or_else(|| {
                    Err(XfrmError::io(
                        "test_transport",
                        io::Error::new(io::ErrorKind::UnexpectedEof, "missing scripted response"),
                    ))
                })
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: true,
                net_admin_capable: true,
                algorithms: XfrmCapability::Available,
                egress_dscp_marking: XfrmCapability::Missing,
                details: Some("scripted test transport"),
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
        fn fresh_namespace_runtime(&self) -> Arc<dyn XfrmDscpRuntime> {
            Arc::new(self.clone())
        }

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
            _operation_class: NetlinkOperationClass,
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
            output_mark: None,
            if_id: None,
            egress_dscp: None,
        }
    }

    fn relocation_parameters() -> SaParameters {
        let mut parameters = sa_parameters();
        parameters.id.destination = ipv4(192, 0, 2, 20);
        parameters.source_address = ipv4(192, 0, 2, 10);
        parameters.request_id = XfrmRequestId::new(0x0102_0304);
        parameters.encap = Some(UdpEncap::esp_in_udp(4500, 4500));
        parameters.mark = Some(XfrmMark {
            value: 0xaabb_ccdd,
            mask: 0xffff_0000,
        });
        parameters.output_mark = Some(XfrmMark {
            value: 0x0000_1200,
            mask: 0x0000_ff00,
        });
        parameters.if_id = Some(7);
        parameters
    }

    fn relocation_request() -> RelocateSaRequest {
        let body = encode_sa_info(&relocation_parameters()).unwrap();
        let snapshot = parse_sa_relocation_snapshot(&body).unwrap();
        RelocateSaRequest {
            current: snapshot.identity,
            new_source_address: ipv4(198, 51, 100, 10),
            new_destination: ipv4(198, 51, 100, 20),
            encap: SaRelocationEncap::Set(UdpEncap::esp_in_udp(4500, 62_000)),
            direction: SaRelocationDirection::OutboundBlockPolicyInstalled,
        }
    }

    fn relocated_parameters() -> SaParameters {
        let mut parameters = relocation_parameters();
        let request = relocation_request();
        parameters.id.destination = request.new_destination;
        parameters.source_address = request.new_source_address;
        parameters.encap = request.encap.resulting(parameters.encap);
        parameters
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

    fn outbound_binding_request() -> XfrmCompositeInstallRequest {
        let sa = relocation_parameters();
        let policy = PolicyParameters {
            selector: sa.selector.clone(),
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 100,
            templates: vec![XfrmTemplate {
                id: sa.id,
                source_address: sa.source_address,
                request_id: sa.request_id,
                mode: sa.mode,
            }],
            mark: sa.mark,
            if_id: sa.if_id,
        };
        XfrmCompositeInstallRequest {
            sa: InstallSaRequest { parameters: sa },
            policy: InstallPolicyRequest { parameters: policy },
        }
    }

    fn encode_sa_binding_readback(parameters: &SaParameters) -> SensitiveBuffer {
        let request = XfrmCompositeInstallRequest {
            sa: InstallSaRequest {
                parameters: parameters.clone(),
            },
            policy: InstallPolicyRequest {
                parameters: policy_parameters(),
            },
        };
        test_outbound_binding_readback_bodies(&request).unwrap().1
    }

    fn observation_key(parameters: &SaParameters) -> EspPeerObservationKey {
        EspPeerObservationKey {
            id: parameters.id,
            mark: parameters.mark,
            if_id: parameters.if_id,
            direction: XfrmDirection::In,
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

    fn route_attr_payload_offset_from(
        body: &[u8],
        mut offset: usize,
        attr_type: u16,
    ) -> Option<usize> {
        while offset + ROUTE_ATTRIBUTE_HEADER_LEN <= body.len() {
            let len = usize::from(u16::from_ne_bytes([body[offset], body[offset + 1]]));
            let found_type = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]);
            if len < ROUTE_ATTRIBUTE_HEADER_LEN || offset + len > body.len() {
                return None;
            }
            if found_type == attr_type {
                return offset.checked_add(ROUTE_ATTRIBUTE_HEADER_LEN);
            }
            offset += align_to_netlink(len)?;
        }
        None
    }

    fn remove_route_attr(body: &mut SensitiveBuffer, base_len: usize, attr_type: u16) {
        let payload_offset = route_attr_payload_offset_from(body, base_len, attr_type).unwrap();
        let header_offset = payload_offset - ROUTE_ATTRIBUTE_HEADER_LEN;
        let len = usize::from(u16::from_ne_bytes([
            body[header_offset],
            body[header_offset + 1],
        ]));
        let aligned = align_to_netlink(len).unwrap();
        body.drain(header_offset..header_offset + aligned);
    }

    fn assert_sensitive_buffer(_buffer: &SensitiveBuffer) {}

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn consumed_oversize_mutation_is_indeterminate_without_second_receive() {
        let config = LinuxXfrmBackendConfig {
            receive_attempts: 8,
            receive_buffer_len: 8,
            retry_delay: Duration::ZERO,
        };
        let mut receive_calls = 0;

        let error = receive_netlink_response(
            "install_sa",
            NetlinkOperationClass::Mutation,
            7,
            config,
            |buffer| {
                receive_calls += 1;
                Ok(ReceiveMessageOutcome::ConsumedOversize {
                    buffer_bytes: buffer.len(),
                    datagram_bytes: 64,
                })
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            XfrmError::StateIndeterminate {
                operation: "install_sa"
            }
        ));
        assert_eq!(receive_calls, 1);
    }

    #[test]
    fn consumed_oversize_read_preserves_bounded_size_evidence() {
        let config = LinuxXfrmBackendConfig {
            receive_attempts: 8,
            receive_buffer_len: 16,
            retry_delay: Duration::ZERO,
        };
        let mut receive_calls = 0;

        let error = receive_netlink_response(
            "query_sa",
            NetlinkOperationClass::ReadOnly,
            9,
            config,
            |buffer| {
                receive_calls += 1;
                Ok(ReceiveMessageOutcome::ConsumedOversize {
                    buffer_bytes: buffer.len(),
                    datagram_bytes: 128,
                })
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            XfrmError::ResponseTooLarge {
                operation: "query_sa",
                buffer_bytes: 16,
                datagram_bytes: 128,
            }
        ));
        assert_eq!(receive_calls, 1);
    }

    #[test]
    fn operation_classification_keeps_reads_distinct_from_mutations() {
        assert_eq!(
            netlink_operation_class(XFRM_MSG_GETSA),
            NetlinkOperationClass::ReadOnly
        );
        assert_eq!(
            netlink_operation_class(XFRM_MSG_GETPOLICY),
            NetlinkOperationClass::ReadOnly
        );
        for message_type in [
            XFRM_MSG_ALLOCSPI,
            XFRM_MSG_NEWSA,
            XFRM_MSG_UPDSA,
            XFRM_MSG_DELSA,
            XFRM_MSG_NEWPOLICY,
            XFRM_MSG_UPDPOLICY,
            XFRM_MSG_DELPOLICY,
            XFRM_MSG_NEWAE,
            XFRM_MSG_MIGRATE_STATE,
        ] {
            assert_eq!(
                netlink_operation_class(message_type),
                NetlinkOperationClass::Mutation
            );
        }
    }

    #[test]
    fn cbc_hmac_natt_sa_destination_does_not_reallocate_after_key_copy() {
        let mut parameters = sa_parameters();
        parameters.auth = Some((
            AuthAlgorithm::hmac_sha512(256),
            KeyMaterial::new(vec![0xab; 64]),
        ));
        parameters.crypt = Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0xcd; 32])));
        parameters.encap = Some(UdpEncap::esp_in_udp(4500, 4500));
        let mut allocations = Vec::new();

        let body =
            encode_sa_info_inner_observed(&parameters, false, None, |stage, pointer, capacity| {
                allocations.push((stage, pointer, capacity))
            })
            .unwrap();

        assert_eq!(body.len(), 496);
        assert_eq!(allocations.len(), 2);
        assert_eq!(
            allocations[0].0,
            SaEncodingAllocationStage::BeforeSensitiveAttributes
        );
        assert_eq!(allocations[1].0, SaEncodingAllocationStage::Complete);
        assert_eq!(allocations[0].1, allocations[1].1);
        assert_eq!(allocations[0].2, allocations[1].2);
        assert!(allocations[0].2 >= body.len());
        assert_sensitive_buffer(&body);
    }

    #[test]
    fn aead_largest_replay_shape_and_marks_do_not_reallocate_after_key_copy() {
        const MAX_ESN_BITMAP_WORDS_PER_ATTR: u32 = 16_376;

        let mut parameters = sa_parameters();
        parameters.auth = None;
        parameters.crypt = None;
        parameters.aead = Some((
            AeadAlgorithm::rfc4106_gcm_aes(128),
            KeyMaterial::new(vec![0xef; 36]),
        ));
        parameters.replay_window = MAX_ESN_BITMAP_WORDS_PER_ATTR * 32;
        parameters.mark = Some(XfrmMark {
            value: 0x1234_0000,
            mask: 0xffff_0000,
        });
        parameters.if_id = Some(7);
        parameters.output_mark = Some(XfrmMark {
            value: 0x0000_1200,
            mask: 0x0000_ff00,
        });
        let mut allocations = Vec::new();

        let body =
            encode_sa_info_inner_observed(&parameters, false, None, |stage, pointer, capacity| {
                allocations.push((stage, pointer, capacity))
            })
            .unwrap();

        assert_eq!(allocations.len(), 2);
        assert_eq!(allocations[0].1, allocations[1].1);
        assert_eq!(allocations[0].2, allocations[1].2);
        assert!(allocations[0].2 >= body.len());
        assert!(route_attr_payload(&body, XFRMA_ALG_AEAD).is_some());
        assert_eq!(
            route_attr_payload(&body, XFRMA_REPLAY_ESN_VAL)
                .unwrap()
                .len(),
            XFRM_REPLAY_STATE_ESN_BASE_LEN
                + MAX_ESN_BITMAP_WORDS_PER_ATTR as usize * size_of::<u32>()
        );
        assert!(route_attr_payload(&body, XFRMA_MARK).is_some());
        assert!(route_attr_payload(&body, XFRMA_IF_ID).is_some());
        assert!(route_attr_payload(&body, XFRMA_SET_MARK).is_some());
        assert!(route_attr_payload(&body, XFRMA_SET_MARK_MASK).is_some());
        assert_sensitive_buffer(&body);
    }

    #[test]
    fn sa_plan_rejects_replay_attribute_overflow_before_allocating_bitmap() {
        const FIRST_OVERSIZED_ESN_BITMAP_WORDS: u32 = 16_377;

        let mut parameters = sa_parameters();
        parameters.replay_window = FIRST_OVERSIZED_ESN_BITMAP_WORDS * 32;

        let error = encode_sa_info(&parameters).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "netlink.attr",
                reason: "attribute length overflow",
            }
        ));
    }

    #[test]
    fn relocate_sa_codec_matches_upstream_uapi_layout() {
        let request = relocation_request();
        let body = encode_relocate_sa_request(&request).unwrap();

        assert_eq!(body.len(), 160);
        assert_eq!(&body[0..4], &[192, 0, 2, 20]);
        assert!(body[4..16].iter().all(|byte| *byte == 0));
        assert_eq!(&body[16..20], &0x1234_5678_u32.to_be_bytes());
        assert_eq!(&body[20..22], &AF_INET.to_ne_bytes());
        assert_eq!(body[22], IPPROTO_ESP);
        assert_eq!(body[23], 0);
        assert_eq!(&body[24..28], &[198, 51, 100, 20]);
        assert_eq!(&body[40..44], &[198, 51, 100, 10]);
        assert_eq!(&body[56..60], &0xaabb_ccdd_u32.to_ne_bytes());
        assert_eq!(&body[60..64], &0xffff_0000_u32.to_ne_bytes());
        assert_eq!(&body[64..68], &[10, 0, 0, 2]);
        assert_eq!(&body[80..84], &[10, 0, 0, 1]);
        assert_eq!(&body[104..106], &AF_INET.to_ne_bytes());
        assert_eq!(body[106], 32);
        assert_eq!(body[107], 32);
        assert_eq!(body[108], IPPROTO_ESP);
        assert_eq!(&body[120..124], &0x0102_0304_u32.to_ne_bytes());
        assert_eq!(&body[124..128], &0_u32.to_ne_bytes());
        assert_eq!(&body[128..130], &AF_INET.to_ne_bytes());
        assert_eq!(&body[130..132], &0_u16.to_ne_bytes());
        assert_eq!(&body[132..134], &28_u16.to_ne_bytes());
        assert_eq!(&body[134..136], &XFRMA_ENCAP.to_ne_bytes());
        assert_eq!(&body[136..138], &UDP_ENCAP_ESPINUDP.to_ne_bytes());
        assert_eq!(&body[138..140], &4500_u16.to_be_bytes());
        assert_eq!(&body[140..142], &62_000_u16.to_be_bytes());
        assert!(body[142..160].iter().all(|byte| *byte == 0));

        let message = encode_netlink_message(
            XFRM_MSG_MIGRATE_STATE,
            NLM_F_REQUEST | NLM_F_ACK,
            0x1122_3344,
            &body,
        )
        .unwrap();
        assert_eq!(message.len(), 176);
        assert_eq!(&message[0..4], &176_u32.to_ne_bytes());
        assert_eq!(&message[4..6], &0x29_u16.to_ne_bytes());
        assert_eq!(&message[6..8], &5_u16.to_ne_bytes());
        assert_eq!(&message[8..12], &0x1122_3344_u32.to_ne_bytes());
        assert_eq!(&message[16..], body.as_slice());
    }

    #[test]
    fn relocation_encapsulation_actions_match_upstream_uapi_semantics() {
        let mut request = relocation_request();

        request.encap = SaRelocationEncap::Preserve;
        let preserve_natt = encode_relocate_sa_request(&request).unwrap();
        assert_eq!(preserve_natt.len(), XFRM_USER_MIGRATE_STATE_LEN);
        assert!(
            route_attr_payload_from(&preserve_natt, XFRM_USER_MIGRATE_STATE_LEN, XFRMA_ENCAP)
                .is_none()
        );

        request.current.encap = None;
        let preserve_native = encode_relocate_sa_request(&request).unwrap();
        assert_eq!(preserve_native.len(), XFRM_USER_MIGRATE_STATE_LEN);

        request.encap = SaRelocationEncap::Set(UdpEncap::esp_in_udp(4500, 62_000));
        let add_natt = encode_relocate_sa_request(&request).unwrap();
        let add_payload =
            route_attr_payload_from(&add_natt, XFRM_USER_MIGRATE_STATE_LEN, XFRMA_ENCAP).unwrap();
        assert_eq!(&add_payload[0..2], &UDP_ENCAP_ESPINUDP.to_ne_bytes());
        assert_eq!(&add_payload[2..4], &4500_u16.to_be_bytes());
        assert_eq!(&add_payload[4..6], &62_000_u16.to_be_bytes());

        request.current.encap = Some(UdpEncap::esp_in_udp(4500, 4500));
        request.encap = SaRelocationEncap::Remove;
        let remove_natt = encode_relocate_sa_request(&request).unwrap();
        let remove_payload =
            route_attr_payload_from(&remove_natt, XFRM_USER_MIGRATE_STATE_LEN, XFRMA_ENCAP)
                .unwrap();
        assert_eq!(remove_payload, &[0; XFRM_ENCAP_TEMPLATE_LEN]);
    }

    #[test]
    fn relocation_snapshot_exposes_exact_attributes() {
        let parameters = relocation_parameters();
        let snapshot = parse_sa_relocation_snapshot(&encode_sa_info(&parameters).unwrap()).unwrap();

        assert_eq!(snapshot.identity.encap, parameters.encap);
        assert_eq!(snapshot.identity.mark, parameters.mark);
        assert_eq!(snapshot.identity.if_id, parameters.if_id);
        assert_eq!(snapshot.identity.output_mark, parameters.output_mark);
        assert_eq!(snapshot.identity.id, parameters.id);
    }

    #[test]
    fn esp_peer_observation_registration_is_derived_from_exact_getsa() {
        let parameters = relocation_parameters();
        let body = encode_sa_info(&parameters).unwrap();
        let registration =
            parse_esp_peer_observation_registration(&body, observation_key(&parameters)).unwrap();

        assert_eq!(registration.key.id, parameters.id);
        assert_eq!(registration.key.mark, parameters.mark);
        assert_eq!(registration.key.if_id, parameters.if_id);
        assert_eq!(registration.key.direction, XfrmDirection::In);
        assert_eq!(registration.current_outer_source, parameters.source_address);
        assert_eq!(
            registration.current_outer_source_port,
            parameters.encap.unwrap().source_port
        );
        assert!(registration.integrity_protected);
    }

    #[test]
    fn esp_peer_observation_registration_uses_raw_kernel_mark() {
        let parameters = relocation_parameters();
        let body = encode_sa_info(&parameters).unwrap();
        let mut requested = observation_key(&parameters);
        requested.mark = Some(XfrmMark {
            value: 0xaabb_1234,
            mask: 0xffff_0000,
        });

        let registration = parse_esp_peer_observation_registration(&body, requested).unwrap();
        assert_eq!(registration.key.mark, parameters.mark);

        requested.mark = Some(XfrmMark {
            value: 0xbbbb_1234,
            mask: 0xffff_0000,
        });
        assert!(matches!(
            parse_esp_peer_observation_registration(&body, requested),
            Err(XfrmError::StateMismatch {
                operation: "query_esp_peer_observation_registration"
            })
        ));
    }

    #[test]
    fn esp_peer_observation_registration_rejects_unsafe_sa_shapes() {
        let parameters = relocation_parameters();
        let requested = observation_key(&parameters);
        let clean = encode_sa_info(&parameters).unwrap();

        let mut offloaded = clean.clone();
        append_attr(&mut offloaded, XFRMA_OFFLOAD_DEV, &[0; 8]).unwrap();
        assert!(matches!(
            parse_esp_peer_observation_registration(&offloaded, requested),
            Err(XfrmError::UnsupportedFeature {
                feature: "esp_peer_observation_xfrm_offload"
            })
        ));

        let mut outbound = clean.clone();
        append_attr(&mut outbound, XFRMA_SA_DIR, &[XFRM_SA_DIR_OUT]).unwrap();
        assert!(parse_esp_peer_observation_registration(&outbound, requested).is_err());

        let mut noncanonical_unspecified_direction = clean.clone();
        append_attr(&mut noncanonical_unspecified_direction, XFRMA_SA_DIR, &[0]).unwrap();
        assert!(parse_esp_peer_observation_registration(
            &noncanonical_unspecified_direction,
            requested,
        )
        .is_err());

        let mut replay_disabled = clean.clone();
        replay_disabled[215] = 0;
        assert!(matches!(
            parse_esp_peer_observation_registration(&replay_disabled, requested),
            Err(XfrmError::UnsupportedFeature {
                feature: "esp_peer_observation_replay_disabled"
            })
        ));

        let mut crypt_only = clean;
        remove_route_attr(&mut crypt_only, XFRM_USER_SA_INFO_LEN, XFRMA_ALG_AUTH_TRUNC);
        assert!(matches!(
            parse_esp_peer_observation_registration(&crypt_only, requested),
            Err(XfrmError::UnsupportedFeature {
                feature: "esp_peer_observation_unauthenticated_sa"
            })
        ));

        let mut esn_parameters = parameters;
        esn_parameters.replay_window = 64;
        let mut replay_state = SaReplayState::fresh(64);
        replay_state.esn = true;
        esn_parameters.replay_state = Some(replay_state);
        let mut zero_active_esn_window = encode_sa_info(&esn_parameters).unwrap();
        // A nonzero legacy byte must not mask the selected ESN/BMP window.
        zero_active_esn_window[215] = 32;
        let replay = route_attr_payload_offset_from(
            &zero_active_esn_window,
            XFRM_USER_SA_INFO_LEN,
            XFRMA_REPLAY_ESN_VAL,
        )
        .unwrap();
        zero_active_esn_window[replay + 20..replay + 24].fill(0);
        assert!(matches!(
            parse_esp_peer_observation_registration(
                &zero_active_esn_window,
                observation_key(&esn_parameters),
            ),
            Err(XfrmError::UnsupportedFeature {
                feature: "esp_peer_observation_replay_disabled"
            })
        ));
    }

    #[test]
    fn outbound_binding_parsers_accept_exact_kernel_shape_and_dynamic_counters() {
        let request = outbound_binding_request();
        let expectation = validate_outbound_request(&request).unwrap();
        let mut sa_body = encode_sa_binding_readback(&request.sa.parameters);
        // GETSA lifetime-current/statistics/sequence fields are mutable and do
        // not weaken the immutable identity proof.
        sa_body[160..208].fill(0x5a);
        append_attr(&mut sa_body, XFRMA_PAD, &[]).unwrap();
        append_attr(&mut sa_body, XFRMA_LASTUSED, &123_u64.to_ne_bytes()).unwrap();
        let observed = parse_outbound_sa_binding_snapshot(
            &sa_body,
            &expectation,
            Some(&request.sa.parameters),
        )
        .unwrap();
        assert_eq!(observed.identity.id, request.sa.parameters.id);

        let mut policy_body = encode_policy_info(&request.policy.parameters).unwrap();
        // Lifetime-current and the kernel-assigned policy index are dynamic.
        policy_body[120..152].fill(0xa5);
        policy_body[156..160].copy_from_slice(&42_u32.to_ne_bytes());
        append_attr(
            &mut policy_body,
            XFRMA_POLICY_TYPE,
            &[XFRM_POLICY_TYPE_MAIN, 0, 0, 0, 0, 0],
        )
        .unwrap();
        let observed = parse_policy_state(&policy_body).unwrap();
        assert_eq!(observed.parameters, request.policy.parameters);
    }

    #[test]
    fn outbound_binding_sa_parser_rejects_unmodeled_or_noncanonical_semantics() {
        let request = outbound_binding_request();
        let parameters = request.sa.parameters.clone();
        let expectation = validate_outbound_request(&request).unwrap();
        let clean = encode_sa_binding_readback(&parameters);

        let mut unknown = clean.clone();
        append_attr(&mut unknown, 8, &[0; 4]).unwrap(); // XFRMA_SEC_CTX
        assert!(
            parse_outbound_sa_binding_snapshot(&unknown, &expectation, Some(&parameters)).is_err()
        );

        let mut unexpected_flag = clean.clone();
        unexpected_flag[216] |= 1; // XFRM_STATE_NOECN
        assert!(parse_outbound_sa_binding_snapshot(
            &unexpected_flag,
            &expectation,
            Some(&parameters)
        )
        .is_err());

        let mut reserved = clean.clone();
        reserved[217] = 1;
        assert!(
            parse_outbound_sa_binding_snapshot(&reserved, &expectation, Some(&parameters)).is_err()
        );

        let mut use_expiry = clean.clone();
        use_expiry[144] = 1;
        assert!(
            parse_outbound_sa_binding_snapshot(&use_expiry, &expectation, Some(&parameters))
                .is_err()
        );

        let mut inbound = clean.clone();
        let direction =
            route_attr_payload_offset_from(&inbound, XFRM_USER_SA_INFO_LEN, XFRMA_SA_DIR).unwrap();
        inbound[direction] = 1;
        assert!(
            parse_outbound_sa_binding_snapshot(&inbound, &expectation, Some(&parameters)).is_err()
        );

        let mut duplicate_direction = clean;
        append_attr(&mut duplicate_direction, XFRMA_SA_DIR, &[XFRM_SA_DIR_OUT]).unwrap();
        assert!(parse_outbound_sa_binding_snapshot(
            &duplicate_direction,
            &expectation,
            Some(&parameters),
        )
        .is_err());
    }

    #[test]
    fn outbound_binding_sa_parser_compares_kernel_keys_to_transient_intent() {
        let request = outbound_binding_request();
        let supplied = request.sa.parameters.clone();
        let expectation = validate_outbound_request(&request).unwrap();
        let kernel_a = encode_sa_binding_readback(&supplied);
        assert!(
            parse_outbound_sa_binding_snapshot(&kernel_a, &expectation, Some(&supplied)).is_ok()
        );

        // Installation requests contain AUTH_TRUNC only. A real GETSA also
        // returns the redundant legacy AUTH form; omitting either fails closed.
        let missing_legacy = encode_sa_info(&supplied).unwrap();
        assert!(
            parse_outbound_sa_binding_snapshot(&missing_legacy, &expectation, Some(&supplied))
                .is_err()
        );

        let mut kernel_b_parameters = supplied.clone();
        kernel_b_parameters.auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0x11; 32]);
        let kernel_b = encode_sa_binding_readback(&kernel_b_parameters);
        assert!(
            parse_outbound_sa_binding_snapshot(&kernel_b, &expectation, Some(&supplied)).is_err()
        );

        let mut ambiguous_zero = supplied.clone();
        ambiguous_zero.auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0; 32]);
        ambiguous_zero.crypt.as_mut().unwrap().1 = KeyMaterial::new(vec![0; 16]);
        let redacted_or_zero = encode_sa_binding_readback(&ambiguous_zero);
        assert!(matches!(
            parse_outbound_sa_binding_snapshot(
                &redacted_or_zero,
                &expectation,
                Some(&ambiguous_zero),
            ),
            Err(XfrmError::UnsupportedFeature {
                feature: XFRM_KEY_READBACK_REDACTED
            })
        ));

        let mut contradictory_auth = kernel_a;
        let legacy_key = route_attr_payload_offset_from(
            &contradictory_auth,
            XFRM_USER_SA_INFO_LEN,
            XFRMA_ALG_AUTH,
        )
        .unwrap()
            + XFRM_ALGO_HEADER_LEN;
        contradictory_auth[legacy_key] ^= 1;
        assert!(parse_outbound_sa_binding_snapshot(
            &contradictory_auth,
            &expectation,
            Some(&supplied),
        )
        .is_err());
        assert!(
            parse_outbound_sa_binding_snapshot(&contradictory_auth, &expectation, None).is_err(),
            "key-free receipt validation must still reject contradictory AUTH copies"
        );
    }

    #[test]
    fn outbound_binding_sa_parser_rejects_ambiguous_replay_attributes() {
        let request = outbound_binding_request();
        let parameters = request.sa.parameters.clone();
        let expectation = validate_outbound_request(&request).unwrap();
        let clean = encode_sa_binding_readback(&parameters);
        let legacy = encode_replay_state_legacy(&SaReplayState::fresh(32)).unwrap();

        let mut duplicate = clean.clone();
        append_attr(&mut duplicate, XFRMA_REPLAY_VAL, &legacy).unwrap();
        append_attr(&mut duplicate, XFRMA_REPLAY_VAL, &legacy).unwrap();
        assert!(
            parse_outbound_sa_binding_snapshot(&duplicate, &expectation, Some(&parameters))
                .is_err()
        );

        let mut contradictory = clean;
        append_attr(&mut contradictory, XFRMA_REPLAY_VAL, &legacy).unwrap();
        let mut esn_state = SaReplayState::fresh(64);
        esn_state.esn = true;
        let esn = encode_replay_state_esn(&esn_state).unwrap();
        append_attr(&mut contradictory, XFRMA_REPLAY_ESN_VAL, &esn).unwrap();
        assert!(parse_outbound_sa_binding_snapshot(
            &contradictory,
            &expectation,
            Some(&parameters),
        )
        .is_err());

        let mut esn_parameters = parameters;
        esn_parameters.replay_window = 64;
        let mut esn_request = outbound_binding_request();
        esn_request.sa.parameters = esn_parameters.clone();
        let esn_expectation = validate_outbound_request(&esn_request).unwrap();
        let mut missing_esn = encode_sa_binding_readback(&esn_parameters);
        remove_route_attr(
            &mut missing_esn,
            XFRM_USER_SA_INFO_LEN,
            XFRMA_REPLAY_ESN_VAL,
        );
        assert!(parse_outbound_sa_binding_snapshot(
            &missing_esn,
            &esn_expectation,
            Some(&esn_parameters),
        )
        .is_err());
    }

    #[test]
    fn outbound_binding_policy_parser_rejects_unknown_duplicate_and_sub_policy_attrs() {
        let parameters = outbound_binding_request().policy.parameters;
        let clean = encode_policy_info(&parameters).unwrap();

        let mut unknown = clean.clone();
        append_attr(&mut unknown, 8, &[0; 4]).unwrap(); // XFRMA_SEC_CTX
        assert!(parse_policy_state(&unknown).is_err());

        let mut sub_policy = clean.clone();
        append_attr(&mut sub_policy, XFRMA_POLICY_TYPE, &[1, 0, 0, 0, 0, 0]).unwrap();
        assert!(parse_policy_state(&sub_policy).is_err());

        let mut short = clean.clone();
        append_attr(&mut short, XFRMA_POLICY_TYPE, &[0; 4]).unwrap();
        assert!(parse_policy_state(&short).is_err());

        for offset in 1..6 {
            let mut noncanonical = clean.clone();
            let mut policy_type = [0; 6];
            policy_type[offset] = 1;
            append_attr(&mut noncanonical, XFRMA_POLICY_TYPE, &policy_type).unwrap();
            assert!(parse_policy_state(&noncanonical).is_err());
        }

        let mut duplicate = clean;
        append_attr(
            &mut duplicate,
            XFRMA_POLICY_TYPE,
            &[XFRM_POLICY_TYPE_MAIN, 0, 0, 0, 0, 0],
        )
        .unwrap();
        append_attr(
            &mut duplicate,
            XFRMA_POLICY_TYPE,
            &[XFRM_POLICY_TYPE_MAIN, 0, 0, 0, 0, 0],
        )
        .unwrap();
        assert!(parse_policy_state(&duplicate).is_err());
    }

    #[tokio::test]
    async fn outbound_binding_backend_reads_policy_then_sa_and_rejects_key_substitution() {
        let request = outbound_binding_request();
        let expectation = validate_outbound_request(&request).unwrap();
        let mut policy_body = encode_policy_info(&request.policy.parameters).unwrap();
        append_attr(
            &mut policy_body,
            XFRMA_POLICY_TYPE,
            &[XFRM_POLICY_TYPE_MAIN, 0, 0, 0, 0, 0],
        )
        .unwrap();
        let sa_body = encode_sa_binding_readback(&request.sa.parameters);
        let transport = ScriptedTransport::new(vec![
            Ok(Some(policy_body.to_vec())),
            Ok(Some(sa_body.to_vec())),
        ]);
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport);

        backend
            .validate_outbound_sa_binding(&expectation, &request.sa.parameters)
            .await
            .unwrap();
        let requests = capture.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_GETPOLICY);
        assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_GETSA);

        let mut kernel_b = request.sa.parameters.clone();
        kernel_b.auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0x11; 32]);
        let transport = ScriptedTransport::new(vec![
            Ok(Some(policy_body.to_vec())),
            Ok(Some(encode_sa_binding_readback(&kernel_b).to_vec())),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport);
        let error = backend
            .validate_outbound_sa_binding(&expectation, &request.sa.parameters)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "xfrm_outbound_sa_binding_current_sa_mismatch");

        let mut redacted = request.sa.parameters.clone();
        redacted.auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0; 32]);
        redacted.crypt.as_mut().unwrap().1 = KeyMaterial::new(vec![0; 16]);
        let transport = ScriptedTransport::new(vec![
            Ok(Some(policy_body.to_vec())),
            Ok(Some(encode_sa_binding_readback(&redacted).to_vec())),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport);
        let error = backend
            .validate_outbound_sa_binding(&expectation, &request.sa.parameters)
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            "xfrm_outbound_sa_binding_key_readback_unavailable"
        );
    }

    #[test]
    fn relocation_preserves_every_raw_selector_field() {
        let mut body = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        body[32..34].copy_from_slice(&443_u16.to_be_bytes());
        body[34..36].copy_from_slice(&0xfff0_u16.to_be_bytes());
        body[36..38].copy_from_slice(&4500_u16.to_be_bytes());
        body[38..40].copy_from_slice(&0xff00_u16.to_be_bytes());
        body[48..52].copy_from_slice(&41_i32.to_ne_bytes());
        body[52..56].copy_from_slice(&1001_u32.to_ne_bytes());
        let snapshot = parse_sa_relocation_snapshot(&body).unwrap();

        assert_eq!(snapshot.identity.selector.destination_port, 443);
        assert_eq!(snapshot.identity.selector.destination_port_mask, 0xfff0);
        assert_eq!(snapshot.identity.selector.source_port, 4500);
        assert_eq!(snapshot.identity.selector.source_port_mask, 0xff00);
        assert_eq!(snapshot.identity.selector.ifindex, 41);
        assert_eq!(snapshot.identity.selector.user_id, 1001);

        let mut request = relocation_request();
        request.current = snapshot.identity;
        let migrate = encode_relocate_sa_request(&request).unwrap();
        assert_eq!(&migrate[96..98], &443_u16.to_be_bytes());
        assert_eq!(&migrate[98..100], &0xfff0_u16.to_be_bytes());
        assert_eq!(&migrate[100..102], &4500_u16.to_be_bytes());
        assert_eq!(&migrate[102..104], &0xff00_u16.to_be_bytes());
        assert_eq!(&migrate[112..116], &41_i32.to_ne_bytes());
        assert_eq!(&migrate[116..120], &1001_u32.to_ne_bytes());
    }

    #[test]
    fn relocation_rejects_noncanonical_selector_and_encap_original_address() {
        let mut noncanonical_selector = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        noncanonical_selector[4] = 1;
        assert!(parse_sa_relocation_snapshot(&noncanonical_selector).is_err());

        let mut noncanonical_reserved = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        noncanonical_reserved[45] = 1;
        assert!(parse_sa_relocation_snapshot(&noncanonical_reserved).is_err());

        let mut nonzero_original_address =
            encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        let encap_offset = route_attr_payload_offset_from(
            &nonzero_original_address,
            XFRM_USER_SA_INFO_LEN,
            XFRMA_ENCAP,
        )
        .unwrap();
        nonzero_original_address[encap_offset + 8] = 1;
        assert!(matches!(
            parse_sa_relocation_snapshot(&nonzero_original_address),
            Err(XfrmError::UnsupportedFeature {
                feature: "sa_relocation_encap_original_address"
            })
        ));
    }

    #[test]
    fn relocation_codec_supports_ipv6_and_cross_family_outer_migration() {
        let mut request = relocation_request();
        let new_source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10];
        let new_destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20];
        request.new_source_address = IpAddress::Ipv6(new_source);
        request.new_destination = IpAddress::Ipv6(new_destination);

        let body = encode_relocate_sa_request(&request).unwrap();

        assert_eq!(&body[20..22], &AF_INET.to_ne_bytes());
        assert_eq!(&body[24..40], &new_destination);
        assert_eq!(&body[40..56], &new_source);
        assert_eq!(&body[128..130], &AF_INET6.to_ne_bytes());

        let old_source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 10];
        let old_destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 20];
        let mut parameters = relocation_parameters();
        parameters.source_address = IpAddress::Ipv6(old_source);
        parameters.id.destination = IpAddress::Ipv6(old_destination);
        let snapshot = parse_sa_relocation_snapshot(&encode_sa_info(&parameters).unwrap()).unwrap();
        let request = RelocateSaRequest {
            current: snapshot.identity,
            new_source_address: ipv4(198, 51, 100, 10),
            new_destination: ipv4(198, 51, 100, 20),
            encap: SaRelocationEncap::Preserve,
            direction: SaRelocationDirection::Inbound,
        };
        let body = encode_relocate_sa_request(&request).unwrap();
        assert_eq!(&body[0..16], &old_destination);
        assert_eq!(&body[20..22], &AF_INET6.to_ne_bytes());
        assert_eq!(&body[128..130], &AF_INET.to_ne_bytes());
    }

    #[test]
    fn relocation_validation_rejects_unsafe_shapes() {
        let valid = relocation_request();

        let mut request = valid.clone();
        request.current.id.spi = 0;
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.current.spi",
                ..
            })
        ));

        let mut request = valid.clone();
        request.current.id.protocol = 51;
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.current.protocol",
                ..
            })
        ));

        let mut request = valid.clone();
        request.current.mode = XfrmMode::Transport;
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.current.mode",
                ..
            })
        ));

        let mut request = valid.clone();
        request.current.selector.source = IpAddress::Ipv6([1; 16]);
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.current.selector.family",
                ..
            })
        ));

        let mut request = valid.clone();
        request.current.selector.source_prefix_len = 33;
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.current.selector.source_prefix_len",
                ..
            })
        ));

        let mut request = valid.clone();
        request.new_source_address = IpAddress::Ipv6([1; 16]);
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.new.family",
                ..
            })
        ));

        let mut request = valid.clone();
        request.new_destination = ipv4(0, 0, 0, 0);
        request.new_source_address = ipv4(0, 0, 0, 0);
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.address",
                ..
            })
        ));

        let mut request = valid.clone();
        request.current.mark = Some(XfrmMark { value: 7, mask: 0 });
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.current.mark",
                ..
            })
        ));

        let mut request = valid.clone();
        request.current.if_id = Some(0);
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.current.if_id",
                ..
            })
        ));

        let mut request = valid.clone();
        request.encap = SaRelocationEncap::Set(UdpEncap::esp_in_udp(4500, 0));
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.encap",
                ..
            })
        ));

        let mut request = valid.clone();
        request.current.encap = None;
        request.encap = SaRelocationEncap::Remove;
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.encap",
                ..
            })
        ));

        let mut request = valid.clone();
        request.encap = SaRelocationEncap::Set(UdpEncap {
            encap_type: 1,
            source_port: 4500,
            destination_port: 4500,
        });
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation.encap",
                ..
            })
        ));

        let mut request = valid.clone();
        request.new_source_address = request.current.source_address;
        request.new_destination = request.current.id.destination;
        request.encap = SaRelocationEncap::Preserve;
        assert!(matches!(
            validate_relocate_sa_request(&request),
            Err(XfrmError::InvalidConfig {
                field: "relocation",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn relocation_capability_probe_is_collision_free_and_cached() {
        let encoded = encode_sa_relocation_capability_probe().unwrap();
        assert_eq!(encoded.len(), XFRM_USER_MIGRATE_STATE_LEN);
        assert_eq!(read_u32_be(&encoded, 16).unwrap(), SA_RELOCATION_PROBE_SPI);
        assert_eq!(read_u16_ne(&encoded, 20).unwrap(), AF_INET);
        assert_eq!(read_u8(&encoded, 22).unwrap(), 0);
        assert_eq!(read_u16_ne(&encoded, 104).unwrap(), AF_INET);
        assert_eq!(read_u16_ne(&encoded, 128).unwrap(), AF_INET);

        let transport = ScriptedTransport::new(vec![Err(XfrmError::NotFound)]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());
        assert_eq!(
            backend.current_sa_relocation_capability(),
            XfrmCapability::UnknownUntilUse
        );

        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Available
        );
        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Available
        );

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_MIGRATE_STATE);
        assert_eq!(netlink_body(&requests[0]), encoded.as_slice());
    }

    #[tokio::test]
    async fn relocation_capability_probe_maps_documented_unsupported_errnos() {
        for errno in [LINUX_EINVAL, LINUX_ENOPROTOOPT] {
            let transport = ScriptedTransport::new(vec![Err(XfrmError::io(
                "netlink_ack",
                io::Error::from_raw_os_error(errno),
            ))]);
            let backend = LinuxXfrmBackend::with_transport(transport.clone());

            assert_eq!(
                backend.sa_relocation_capability().await.unwrap(),
                XfrmCapability::Missing
            );
            assert_eq!(
                backend.sa_relocation_capability().await.unwrap(),
                XfrmCapability::Missing
            );
            assert_eq!(transport.requests().len(), 1);
        }
    }

    #[tokio::test]
    async fn relocate_sa_ack_success_moved_target_and_old_absence_succeeds() {
        let old_body = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        let new_body = encode_sa_info(&relocated_parameters()).unwrap().to_vec();
        let transport = ScriptedTransport::new(vec![
            Ok(Some(old_body)),
            Err(XfrmError::NotFound),
            Ok(None),
            Ok(Some(new_body)),
            Err(XfrmError::NotFound),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());

        backend.relocate_sa(relocation_request()).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 5);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_GETSA);
        assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_GETSA);
        assert_eq!(netlink_message_type(&requests[2]), XFRM_MSG_MIGRATE_STATE);
        assert_eq!(netlink_message_type(&requests[3]), XFRM_MSG_GETSA);
        assert_eq!(netlink_message_type(&requests[4]), XFRM_MSG_GETSA);
        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Available
        );
    }

    #[tokio::test]
    async fn relocate_sa_ack_success_with_old_tuple_present_is_indeterminate() {
        let old_body = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        let new_body = encode_sa_info(&relocated_parameters()).unwrap().to_vec();
        let transport = ScriptedTransport::new(vec![
            Ok(Some(old_body.clone())),
            Err(XfrmError::NotFound),
            Ok(None),
            Ok(Some(new_body)),
            Ok(Some(old_body)),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());

        let error = backend.relocate_sa(relocation_request()).await.unwrap_err();

        assert!(matches!(
            error,
            XfrmError::StateIndeterminate {
                operation: "relocate_sa_reconcile"
            }
        ));
        assert_eq!(transport.requests().len(), 5);
        assert_eq!(
            backend.current_sa_relocation_capability(),
            XfrmCapability::UnknownUntilUse
        );
    }

    #[tokio::test]
    async fn relocate_sa_ack_success_with_unprovable_old_absence_is_indeterminate() {
        let old_body = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        let new_body = encode_sa_info(&relocated_parameters()).unwrap().to_vec();
        let old_query_outcomes = [
            Err(XfrmError::io(
                "netlink_ack",
                io::Error::from_raw_os_error(5),
            )),
            Ok(Some(vec![0; XFRM_USER_SA_INFO_LEN - 1])),
        ];

        for old_query_outcome in old_query_outcomes {
            let transport = ScriptedTransport::new(vec![
                Ok(Some(old_body.clone())),
                Err(XfrmError::NotFound),
                Ok(None),
                Ok(Some(new_body.clone())),
                old_query_outcome,
            ]);
            let backend = LinuxXfrmBackend::with_transport(transport.clone());

            let error = backend.relocate_sa(relocation_request()).await.unwrap_err();

            assert!(matches!(
                error,
                XfrmError::StateIndeterminate {
                    operation: "relocate_sa_reconcile"
                }
            ));
            assert_eq!(transport.requests().len(), 5);
            assert_eq!(
                backend.current_sa_relocation_capability(),
                XfrmCapability::UnknownUntilUse
            );
        }
    }

    #[tokio::test]
    async fn relocate_sa_preserves_native_esp_without_emitting_encap() {
        let mut old_parameters = relocation_parameters();
        old_parameters.encap = None;
        let old_body = encode_sa_info(&old_parameters).unwrap().to_vec();
        let old_snapshot = parse_sa_relocation_snapshot(&old_body).unwrap();
        let request = RelocateSaRequest {
            current: old_snapshot.identity,
            new_source_address: ipv4(198, 51, 100, 30),
            new_destination: ipv4(198, 51, 100, 40),
            encap: SaRelocationEncap::Preserve,
            direction: SaRelocationDirection::Inbound,
        };
        let mut new_parameters = old_parameters;
        new_parameters.id.destination = request.new_destination;
        new_parameters.source_address = request.new_source_address;
        let new_body = encode_sa_info(&new_parameters).unwrap().to_vec();
        let transport = ScriptedTransport::new(vec![
            Ok(Some(old_body)),
            Err(XfrmError::NotFound),
            Ok(None),
            Ok(Some(new_body)),
            Err(XfrmError::NotFound),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());

        backend.relocate_sa(request).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 5);
        let migrate = netlink_body(&requests[2]);
        assert_eq!(migrate.len(), XFRM_USER_MIGRATE_STATE_LEN);
        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Available
        );
    }

    #[tokio::test]
    async fn relocate_sa_ack_success_same_identity_encap_only_needs_one_readback() {
        let old_parameters = relocation_parameters();
        let old_body = encode_sa_info(&old_parameters).unwrap().to_vec();
        let old_snapshot = parse_sa_relocation_snapshot(&old_body).unwrap();
        let request = RelocateSaRequest {
            current: old_snapshot.identity,
            new_source_address: old_parameters.source_address,
            new_destination: old_parameters.id.destination,
            encap: SaRelocationEncap::Set(UdpEncap::esp_in_udp(4500, 62_000)),
            direction: SaRelocationDirection::Inbound,
        };
        let mut new_parameters = old_parameters;
        new_parameters.encap = Some(UdpEncap::esp_in_udp(4500, 62_000));
        let new_body = encode_sa_info(&new_parameters).unwrap().to_vec();
        let transport =
            ScriptedTransport::new(vec![Ok(Some(old_body)), Ok(None), Ok(Some(new_body))]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());

        backend.relocate_sa(request).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_GETSA);
        assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_MIGRATE_STATE);
        assert_eq!(netlink_message_type(&requests[2]), XFRM_MSG_GETSA);
        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Available
        );
    }

    #[tokio::test]
    async fn relocate_sa_rejects_stale_current_snapshot_before_mutation() {
        let old_body = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        let transport = ScriptedTransport::new(vec![Ok(Some(old_body))]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());
        let mut request = relocation_request();
        request.current.request_id = XfrmRequestId::new(99);

        let error = backend.relocate_sa(request).await.unwrap_err();

        assert!(matches!(
            error,
            XfrmError::StateMismatch {
                operation: "relocate_sa_preflight"
            }
        ));
        assert_eq!(transport.requests().len(), 1);
    }

    #[tokio::test]
    async fn supported_kernel_relocation_einval_remains_a_real_operation_failure() {
        let old_body = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        let transport = ScriptedTransport::new(vec![
            Err(XfrmError::NotFound),
            Ok(Some(old_body.clone())),
            Err(XfrmError::NotFound),
            Err(XfrmError::io(
                "netlink_ack",
                io::Error::from_raw_os_error(LINUX_EINVAL),
            )),
            Err(XfrmError::NotFound),
            Ok(Some(old_body)),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());
        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Available
        );

        let error = backend.relocate_sa(relocation_request()).await.unwrap_err();

        assert_eq!(error.raw_os_error(), Some(LINUX_EINVAL));
        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Available
        );
        assert_eq!(transport.requests().len(), 6);
        assert_eq!(
            netlink_message_type(&transport.requests()[0]),
            XFRM_MSG_MIGRATE_STATE
        );
    }

    #[tokio::test]
    async fn relocate_sa_lost_ack_requires_target_match_and_old_absence() {
        let old_body = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        let new_body = encode_sa_info(&relocated_parameters()).unwrap().to_vec();
        let transport = ScriptedTransport::new(vec![
            Ok(Some(old_body.clone())),
            Err(XfrmError::NotFound),
            Err(XfrmError::io(
                "netlink_ack",
                io::Error::from_raw_os_error(5),
            )),
            Ok(Some(new_body)),
            Ok(Some(old_body)),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());

        let error = backend.relocate_sa(relocation_request()).await.unwrap_err();

        assert!(matches!(
            error,
            XfrmError::StateIndeterminate {
                operation: "relocate_sa_reconcile"
            }
        ));
        assert_eq!(transport.requests().len(), 5);
        assert_eq!(
            backend.current_sa_relocation_capability(),
            XfrmCapability::UnknownUntilUse
        );
    }

    #[tokio::test]
    async fn relocate_sa_lost_ack_reconciles_when_target_matches_and_old_is_absent() {
        let old_body = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        let new_body = encode_sa_info(&relocated_parameters()).unwrap().to_vec();
        let transport = ScriptedTransport::new(vec![
            Ok(Some(old_body)),
            Err(XfrmError::NotFound),
            Err(XfrmError::io(
                "netlink_ack",
                io::Error::from_raw_os_error(5),
            )),
            Ok(Some(new_body)),
            Err(XfrmError::NotFound),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport.clone());

        backend.relocate_sa(relocation_request()).await.unwrap();

        assert_eq!(transport.requests().len(), 5);
        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Available
        );
    }

    #[tokio::test]
    async fn relocate_sa_maps_kernel_missing_capability_after_intact_readback() {
        let old_body = encode_sa_info(&relocation_parameters()).unwrap().to_vec();
        let transport = ScriptedTransport::new(vec![
            Ok(Some(old_body.clone())),
            Err(XfrmError::NotFound),
            Err(XfrmError::io(
                "netlink_ack",
                io::Error::from_raw_os_error(LINUX_ENOPROTOOPT),
            )),
            Err(XfrmError::NotFound),
            Ok(Some(old_body)),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport);

        let error = backend.relocate_sa(relocation_request()).await.unwrap_err();

        assert!(matches!(
            error,
            XfrmError::UnsupportedFeature {
                feature: "sa_relocation"
            }
        ));
        assert_eq!(
            backend.sa_relocation_capability().await.unwrap(),
            XfrmCapability::Missing
        );
    }

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
    fn absent_output_mark_and_dscp_preserve_exact_legacy_sa_bytes() {
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
    fn zero_value_and_mask_output_mark_is_invalid() {
        let mut parameters = sa_parameters();
        parameters.output_mark = Some(XfrmMark { value: 0, mask: 0 });

        assert!(matches!(
            encode_sa_info_with_dscp(&parameters, None),
            Err(XfrmError::InvalidConfig {
                field: "sa.output_mark",
                ..
            })
        ));
    }

    #[test]
    fn kernel_readback_without_output_mark_attrs_is_not_exact_zero_pair() {
        // Linux canonicalizes an smark whose value and mask are both zero by
        // omitting both SET_MARK attributes from GETSA. Preserve that absence
        // as `None`; treating it as an exact zero pair would make mandatory
        // mutation readback claim a value the kernel cannot represent.
        let kernel_getsa_body = encode_sa_info(&sa_parameters()).unwrap();
        assert!(route_attr_payload(&kernel_getsa_body, XFRMA_SET_MARK).is_none());
        assert!(route_attr_payload(&kernel_getsa_body, XFRMA_SET_MARK_MASK).is_none());

        let state = parse_sa_state(&kernel_getsa_body, None).unwrap();
        assert_eq!(state.output_mark, None);
        assert_ne!(state.output_mark, Some(XfrmMark { value: 0, mask: 0 }));
    }

    #[test]
    fn generic_output_mark_encodes_and_parses_exact_nonzero_u32_boundaries() {
        for output_mark in [
            XfrmMark { value: 1, mask: 0 },
            XfrmMark { value: 0, mask: 1 },
            XfrmMark {
                value: 0x0001_0000,
                mask: 0x00ff_0000,
            },
            XfrmMark {
                value: u32::MAX,
                mask: u32::MAX,
            },
        ] {
            let mut parameters = sa_parameters();
            parameters.output_mark = Some(output_mark);

            let body = encode_sa_info_with_dscp(&parameters, None).unwrap();
            assert_eq!(
                route_attr_payload(&body, XFRMA_SET_MARK),
                Some(output_mark.value.to_ne_bytes().as_slice())
            );
            assert_eq!(
                route_attr_payload(&body, XFRMA_SET_MARK_MASK),
                Some(output_mark.mask.to_ne_bytes().as_slice())
            );
            let state = parse_sa_state(&body, None).unwrap();
            assert_eq!(state.output_mark, Some(output_mark));
            assert_eq!(state.egress_dscp, None);
        }
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
    fn fixed_outer_dscp_rejects_unsupported_or_colliding_output_contracts() {
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

        marked.output_mark = Some(XfrmMark {
            value: profile.presence_bit(),
            mask: profile.mask,
        });
        assert!(matches!(
            encode_sa_info_with_dscp(&marked, Some(profile)).unwrap_err(),
            XfrmError::InvalidConfig {
                field: "sa.output_mark",
                ..
            }
        ));
    }

    #[test]
    fn configured_dscp_companion_only_constrains_sas_that_request_dscp() {
        let backend = LinuxXfrmBackend::with_transport_and_dscp_runtime(
            CapturingTransport::default(),
            dscp_config(),
            FakeDscpRuntime::default(),
        )
        .unwrap();
        let mut parameters = sa_parameters();
        for output_mark in [
            XfrmMark {
                value: 0,
                mask: u32::MAX,
            },
            XfrmMark {
                value: u32::MAX,
                mask: u32::MAX,
            },
        ] {
            parameters.output_mark = Some(output_mark);
            assert_eq!(backend.prepare_dscp(&parameters).unwrap(), None);
        }

        parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        for output_mark in [
            XfrmMark {
                value: 0,
                mask: u32::MAX,
            },
            XfrmMark {
                value: u32::MAX,
                mask: u32::MAX,
            },
        ] {
            parameters.output_mark = Some(output_mark);
            assert!(matches!(
                backend.prepare_dscp(&parameters),
                Err(XfrmError::InvalidConfig {
                    field: "sa.output_mark",
                    ..
                })
            ));
        }
    }

    #[test]
    fn lookup_mark_is_independent_and_disjoint_output_mark_composes_with_dscp() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let mut parameters = sa_parameters();
        let lookup_mark = XfrmMark {
            value: profile.presence_bit(),
            mask: profile.mask,
        };
        let output_mark = XfrmMark {
            value: 0x0001_0000,
            mask: 0x00ff_0000,
        };
        parameters.mark = Some(lookup_mark);
        parameters.output_mark = Some(output_mark);
        parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());

        let body = encode_sa_info_with_dscp(&parameters, Some(profile)).unwrap();
        assert_eq!(
            route_attr_payload(&body, XFRMA_MARK),
            Some(encode_mark(lookup_mark).as_slice())
        );
        let expected = XfrmMark {
            value: output_mark.value | profile.encode_token(46).unwrap(),
            mask: output_mark.mask | profile.mask,
        };
        assert_eq!(
            route_attr_payload(&body, XFRMA_SET_MARK),
            Some(expected.value.to_ne_bytes().as_slice())
        );
        assert_eq!(
            route_attr_payload(&body, XFRMA_SET_MARK_MASK),
            Some(expected.mask.to_ne_bytes().as_slice())
        );
        let state = parse_sa_state(&body, Some(profile)).unwrap();
        assert_eq!(state.output_mark, Some(expected));
        assert_eq!(state.egress_dscp, None);
    }

    #[test]
    fn fixed_outer_dscp_query_round_trips_and_preserves_ambiguous_generic_state() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let mut parameters = sa_parameters();
        parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let body = encode_sa_info_with_dscp(&parameters, Some(profile)).unwrap();

        let profiled = parse_sa_state(&body, Some(profile)).unwrap();
        assert_eq!(profiled.egress_dscp, parameters.egress_dscp);
        assert_eq!(
            profiled.output_mark,
            Some(XfrmMark {
                value: profile.encode_token(46).unwrap(),
                mask: profile.mask,
            })
        );
        let generic = parse_sa_state(&body, None).unwrap();
        assert_eq!(generic.output_mark, profiled.output_mark);
        assert_eq!(generic.egress_dscp, None);

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

        let mut generic_without_presence = encode_sa_info(&sa_parameters()).unwrap();
        append_attr(
            &mut generic_without_presence,
            XFRMA_SET_MARK,
            &(1_u32 << profile.shift).to_ne_bytes(),
        )
        .unwrap();
        append_attr(
            &mut generic_without_presence,
            XFRMA_SET_MARK_MASK,
            &profile.mask.to_ne_bytes(),
        )
        .unwrap();
        let state = parse_sa_state(&generic_without_presence, Some(profile)).unwrap();
        assert_eq!(
            state.output_mark,
            Some(XfrmMark {
                value: 1_u32 << profile.shift,
                mask: profile.mask,
            })
        );
        assert_eq!(state.egress_dscp, None);

        let mut disjoint_generic = encode_sa_info(&sa_parameters()).unwrap();
        append_attr(
            &mut disjoint_generic,
            XFRMA_SET_MARK,
            &0x42_u32.to_ne_bytes(),
        )
        .unwrap();
        append_attr(
            &mut disjoint_generic,
            XFRMA_SET_MARK_MASK,
            &0x7f_u32.to_ne_bytes(),
        )
        .unwrap();
        let state = parse_sa_state(&disjoint_generic, Some(profile)).unwrap();
        assert_eq!(
            state.output_mark,
            Some(XfrmMark {
                value: 0x42,
                mask: 0x7f,
            })
        );
        assert_eq!(state.egress_dscp, None);

        let mut partial_overlap = encode_sa_info(&sa_parameters()).unwrap();
        append_attr(
            &mut partial_overlap,
            XFRMA_SET_MARK,
            &profile.presence_bit().to_ne_bytes(),
        )
        .unwrap();
        append_attr(
            &mut partial_overlap,
            XFRMA_SET_MARK_MASK,
            &profile.presence_bit().to_ne_bytes(),
        )
        .unwrap();
        let state = parse_sa_state(&partial_overlap, Some(profile)).unwrap();
        assert_eq!(
            state.output_mark,
            Some(XfrmMark {
                value: profile.presence_bit(),
                mask: profile.presence_bit(),
            })
        );
        assert_eq!(state.egress_dscp, None);
    }

    #[test]
    fn output_mark_parser_rejects_invalid_lengths_and_duplicates() {
        let mut short_value = encode_sa_info(&sa_parameters()).unwrap();
        append_attr(&mut short_value, XFRMA_SET_MARK, &[1, 2, 3]).unwrap();
        append_attr(
            &mut short_value,
            XFRMA_SET_MARK_MASK,
            &u32::MAX.to_ne_bytes(),
        )
        .unwrap();
        assert_eq!(
            parse_sa_state(&short_value, None).unwrap_err().io_kind(),
            Some(io::ErrorKind::InvalidData)
        );

        let mut duplicate_value = encode_sa_info(&sa_parameters()).unwrap();
        for value in [1_u32, 2] {
            append_attr(&mut duplicate_value, XFRMA_SET_MARK, &value.to_ne_bytes()).unwrap();
        }
        append_attr(
            &mut duplicate_value,
            XFRMA_SET_MARK_MASK,
            &u32::MAX.to_ne_bytes(),
        )
        .unwrap();
        assert_eq!(
            parse_sa_state(&duplicate_value, None)
                .unwrap_err()
                .io_kind(),
            Some(io::ErrorKind::InvalidData)
        );

        let mut duplicate_mask = encode_sa_info(&sa_parameters()).unwrap();
        append_attr(&mut duplicate_mask, XFRMA_SET_MARK, &1_u32.to_ne_bytes()).unwrap();
        for mask in [1_u32, u32::MAX] {
            append_attr(
                &mut duplicate_mask,
                XFRMA_SET_MARK_MASK,
                &mask.to_ne_bytes(),
            )
            .unwrap();
        }
        assert_eq!(
            parse_sa_state(&duplicate_mask, None).unwrap_err().io_kind(),
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
    fn encodes_authenticated_only_sa_with_linux_null_cipher_attribute() {
        let mut params = sa_parameters();
        params.crypt = Some((Algorithm::null(), KeyMaterial::new(Vec::new())));

        let body = encode_sa_info(&params).unwrap();
        assert_sensitive_buffer(&body);
        let auth = route_attr_payload(&body, XFRMA_ALG_AUTH_TRUNC).expect("auth-trunc attr");

        assert_eq!(auth.len(), XFRM_ALGO_AUTH_HEADER_LEN + 32);
        assert_eq!(
            &auth[..XFRM_ALG_NAME_LEN],
            &encode_algorithm_name(XFRM_AUTH_HMAC_SHA256).unwrap()
        );
        assert_eq!(
            u32::from_ne_bytes([
                auth[XFRM_ALG_NAME_LEN],
                auth[XFRM_ALG_NAME_LEN + 1],
                auth[XFRM_ALG_NAME_LEN + 2],
                auth[XFRM_ALG_NAME_LEN + 3],
            ]),
            32 * 8
        );
        let crypt = route_attr_payload(&body, XFRMA_ALG_CRYPT).expect("NULL crypt attr");
        assert_eq!(crypt.len(), XFRM_ALGO_HEADER_LEN);
        assert_eq!(
            &crypt[..XFRM_ALG_NAME_LEN],
            &encode_algorithm_name(XFRM_ENCR_NULL).unwrap()
        );
        assert_eq!(
            u32::from_ne_bytes([
                crypt[XFRM_ALG_NAME_LEN],
                crypt[XFRM_ALG_NAME_LEN + 1],
                crypt[XFRM_ALG_NAME_LEN + 2],
                crypt[XFRM_ALG_NAME_LEN + 3],
            ]),
            0
        );
        assert!(route_attr_payload(&body, XFRMA_ALG_AEAD).is_none());
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
    fn rejects_esp_auth_without_explicit_linux_null_cipher() {
        let mut params = sa_parameters();
        params.crypt = None;

        let error = encode_sa_info(&params).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "crypt",
                reason: "authenticated-only ESP requires the explicit Linux NULL cipher"
            }
        ));
    }

    #[test]
    fn rejects_linux_null_cipher_without_authentication() {
        let mut params = sa_parameters();
        params.auth = None;
        params.crypt = Some((Algorithm::null(), KeyMaterial::new(Vec::new())));

        let error = encode_sa_info(&params).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "auth",
                reason: "NULL encryption requires a separate authentication algorithm"
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

        assert_eq!(body[215], 0);
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
    fn encodes_newae_replay_update_with_exact_identity_mark_and_esn_state() {
        let mut params = sa_parameters();
        params.replay_window = 64;
        params.mark = Some(XfrmMark {
            value: 0x1234_0000,
            mask: 0xffff_0000,
        });
        let mut replay = SaReplayState::fresh(64);
        replay.outbound_sequence = 17;
        replay.outbound_sequence_hi = 1;

        let body = encode_sa_replay_update(&params, &replay).unwrap();
        assert_eq!(&body[16..20], &params.id.spi.to_be_bytes());
        assert_eq!(
            u16::from_ne_bytes(body[20..22].try_into().unwrap()),
            AF_INET
        );
        assert_eq!(body[22], IPPROTO_ESP);
        assert_eq!(body[23], 0);
        assert_eq!(
            u32::from_ne_bytes(body[40..44].try_into().unwrap()),
            XFRM_AE_RVAL
        );
        assert_eq!(
            u32::from_ne_bytes(body[44..48].try_into().unwrap()),
            params.request_id.map_or(0, XfrmRequestId::get)
        );
        let replay_payload =
            route_attr_payload_from(&body, XFRM_AEVENT_ID_LEN, XFRMA_REPLAY_ESN_VAL).unwrap();
        assert_eq!(
            u32::from_ne_bytes(replay_payload[4..8].try_into().unwrap()),
            17
        );
        assert_eq!(
            u32::from_ne_bytes(replay_payload[12..16].try_into().unwrap()),
            1
        );
        assert_eq!(
            route_attr_payload_from(&body, XFRM_AEVENT_ID_LEN, XFRMA_MARK).unwrap(),
            &encode_mark(params.mark.unwrap())
        );
        assert!(route_attr_payload_from(&body, XFRM_AEVENT_ID_LEN, XFRMA_REPLAY_VAL).is_none());
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

        assert_eq!(encode_sa_flags(&params), XFRM_STATE_ESN);
        assert_eq!(encode_fixed_replay_window(&params), 0);

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
    async fn generic_output_mark_is_read_back_without_dscp_runtime_for_sa_mutations() {
        let mut parameters = sa_parameters();
        let installed = XfrmMark {
            value: 0x0001_0000,
            mask: 0x00ff_0000,
        };
        parameters.output_mark = Some(installed);
        let install_response = encode_sa_info(&parameters).unwrap().to_vec();
        let install_transport = CapturingTransport::with_response(install_response);
        let install_backend = LinuxXfrmBackend::with_transport(install_transport.clone());
        install_backend
            .install_sa(InstallSaRequest {
                parameters: parameters.clone(),
            })
            .await
            .unwrap();
        let install_requests = install_transport.requests();
        assert_eq!(install_requests.len(), 2);
        assert_eq!(netlink_message_type(&install_requests[0]), XFRM_MSG_NEWSA);
        assert_eq!(netlink_message_type(&install_requests[1]), XFRM_MSG_GETSA);
        let install_body = netlink_body(&install_requests[0]);
        assert_eq!(
            route_attr_payload(install_body, XFRMA_SET_MARK),
            Some(installed.value.to_ne_bytes().as_slice())
        );
        assert_eq!(
            route_attr_payload(install_body, XFRMA_SET_MARK_MASK),
            Some(installed.mask.to_ne_bytes().as_slice())
        );

        let rekeyed = XfrmMark {
            value: 0x0002_0000,
            mask: 0x00ff_0000,
        };
        parameters.output_mark = Some(rekeyed);
        let rekey_response = encode_sa_info(&parameters).unwrap().to_vec();
        let rekey_transport = CapturingTransport::with_response(rekey_response);
        let rekey_backend = LinuxXfrmBackend::with_transport(rekey_transport.clone());
        rekey_backend
            .rekey_sa(RekeySaRequest { parameters })
            .await
            .unwrap();
        let rekey_requests = rekey_transport.requests();
        assert_eq!(rekey_requests.len(), 2);
        assert_eq!(netlink_message_type(&rekey_requests[0]), XFRM_MSG_UPDSA);
        assert_eq!(netlink_message_type(&rekey_requests[1]), XFRM_MSG_GETSA);
        let rekey_body = netlink_body(&rekey_requests[0]);
        assert_eq!(
            route_attr_payload(rekey_body, XFRMA_SET_MARK),
            Some(rekeyed.value.to_ne_bytes().as_slice())
        );
        assert_eq!(
            route_attr_payload(rekey_body, XFRMA_SET_MARK_MASK),
            Some(rekeyed.mask.to_ne_bytes().as_slice())
        );
    }

    #[tokio::test]
    async fn full_width_generic_marks_survive_a_configured_dscp_companion() {
        for output_mark in [
            XfrmMark {
                value: 0,
                mask: u32::MAX,
            },
            XfrmMark {
                value: u32::MAX,
                mask: u32::MAX,
            },
        ] {
            let mut parameters = sa_parameters();
            parameters.output_mark = Some(output_mark);
            let response = encode_sa_info(&parameters).unwrap().to_vec();
            let transport = CapturingTransport::with_response(response);
            let runtime = FakeDscpRuntime::default();
            let backend = LinuxXfrmBackend::with_transport_and_dscp_runtime(
                transport.clone(),
                dscp_config(),
                runtime.clone(),
            )
            .unwrap();

            backend
                .install_sa(InstallSaRequest {
                    parameters: parameters.clone(),
                })
                .await
                .unwrap();

            let requests = transport.requests();
            assert_eq!(requests.len(), 2);
            assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_NEWSA);
            assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_GETSA);
            assert_eq!(
                route_attr_payload(netlink_body(&requests[0]), XFRMA_SET_MARK),
                Some(output_mark.value.to_ne_bytes().as_slice())
            );
            assert_eq!(
                route_attr_payload(netlink_body(&requests[0]), XFRMA_SET_MARK_MASK),
                Some(output_mark.mask.to_ne_bytes().as_slice())
            );
            assert_eq!(runtime.ensure_calls(), 1);

            let state = backend
                .query_sa(QuerySaRequest {
                    destination: parameters.id.destination,
                    protocol: parameters.id.protocol,
                    spi: parameters.id.spi,
                    mark: parameters.mark,
                })
                .await
                .unwrap();
            assert_eq!(state.output_mark, Some(output_mark));
            assert_eq!(state.egress_dscp, None);
            assert_eq!(
                backend.probe().await.unwrap().egress_dscp_marking,
                XfrmCapability::Unknown
            );

            backend
                .rekey_sa(RekeySaRequest { parameters })
                .await
                .unwrap();
            let requests = transport.requests();
            assert_eq!(requests.len(), 5);
            assert_eq!(netlink_message_type(&requests[3]), XFRM_MSG_UPDSA);
            assert_eq!(netlink_message_type(&requests[4]), XFRM_MSG_GETSA);
            assert_eq!(runtime.ensure_calls(), 1);
        }
    }

    #[tokio::test]
    async fn disjoint_generic_and_dscp_mutation_uses_exact_raw_readback() {
        let profile = MarkProfile::new(25, 0xfe00_0000).unwrap();
        let generic = XfrmMark {
            value: 0x0001_0000,
            mask: 0x00ff_0000,
        };
        let mut parameters = sa_parameters();
        parameters.output_mark = Some(generic);
        parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let expected = XfrmMark {
            value: generic.value | profile.encode_token(46).unwrap(),
            mask: generic.mask | profile.mask,
        };
        let response = encode_sa_info_with_dscp(&parameters, Some(profile))
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
            .install_sa(InstallSaRequest { parameters })
            .await
            .unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            route_attr_payload(netlink_body(&requests[0]), XFRMA_SET_MARK),
            Some(expected.value.to_ne_bytes().as_slice())
        );
        assert_eq!(
            route_attr_payload(netlink_body(&requests[0]), XFRMA_SET_MARK_MASK),
            Some(expected.mask.to_ne_bytes().as_slice())
        );
        assert_eq!(runtime.ensure_calls(), 2);
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Available
        );
    }

    #[tokio::test]
    async fn generic_output_mark_ack_without_exact_readback_is_indeterminate() {
        let transport = CapturingTransport::default();
        let backend = LinuxXfrmBackend::with_transport(transport.clone());
        let mut parameters = sa_parameters();
        parameters.output_mark = Some(XfrmMark {
            value: 0x0001_0000,
            mask: 0x00ff_0000,
        });

        assert!(matches!(
            backend.install_sa(InstallSaRequest { parameters }).await,
            Err(XfrmError::StateIndeterminate {
                operation: "install_sa_output_mark_readback"
            })
        ));
        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(netlink_message_type(&requests[0]), XFRM_MSG_NEWSA);
        assert_eq!(netlink_message_type(&requests[1]), XFRM_MSG_GETSA);
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

        let mut body = Vec::new();
        push_i32_ne(&mut body, -LINUX_ENOPROTOOPT);
        let message = encode_netlink_message(NLMSG_ERROR, 0, 11, &body).unwrap();

        let error = parse_netlink_response(&message, 11).unwrap_err();

        assert_eq!(error.raw_os_error(), Some(LINUX_ENOPROTOOPT));
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
    fn null_cipher_rejects_nonempty_key_material_without_leaking_it() {
        let secret = vec![0x7a; 16];
        let error = encode_algorithm(XFRM_ENCR_NULL, &secret).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "crypt.key_material",
                ..
            }
        ));
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(!debug.contains("7a"));
        assert!(!display.contains("7a"));
    }

    #[test]
    fn non_null_cipher_still_rejects_empty_key_material() {
        let error = encode_algorithm(XFRM_ENCR_CBC_AES, &[]).unwrap_err();

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "key_material",
                ..
            }
        ));
    }

    #[test]
    fn algorithm_encoders_return_zeroizing_buffers() {
        let null = encode_algorithm(XFRM_ENCR_NULL, &[]).unwrap();
        let crypt = encode_algorithm(XFRM_ENCR_CBC_AES, &[0xcd; 16]).unwrap();
        let auth = encode_auth_algorithm(XFRM_AUTH_HMAC_SHA256, &[0xab; 32], 96).unwrap();
        let aead = encode_aead_algorithm(XFRM_AEAD_RFC4106_GCM_AES, &[0xef; 36], 128).unwrap();

        assert_sensitive_buffer(&null);
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

    #[test]
    fn namespace_actor_discards_source_namespace_capability_proofs() {
        let backend = LinuxXfrmBackend::with_transport(CapturingTransport::default());
        backend
            .inner
            .dscp_xfrm_attributes_verified
            .store(true, Ordering::Release);
        backend.record_sa_relocation_capability(XfrmCapability::Available);

        let actor = backend.for_namespace_actor(NetworkNamespaceBinding::capture().unwrap());

        assert!(!actor
            .inner
            .dscp_xfrm_attributes_verified
            .load(Ordering::Acquire));
        assert_eq!(
            actor.current_sa_relocation_capability(),
            XfrmCapability::UnknownUntilUse
        );
    }

    fn futures_probe(backend: &LinuxXfrmBackend) -> XfrmProbe {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async { backend.probe().await.unwrap() })
    }
}
