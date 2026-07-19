//! Safe Linux route-steering backend over rtnetlink.

use std::fmt;
use std::io::{self, Read};
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use opc_linux_route_sys::{
    align_to_netlink, open_route_netlink_socket, receive_message, send_message, AF_INET, AF_INET6,
    AF_UNSPEC, FRA_DST, FRA_FWMARK, FRA_FWMASK, FRA_PAD, FRA_PRIORITY, FRA_PROTOCOL, FRA_SRC,
    FRA_SUPPRESS_IFGROUP, FRA_SUPPRESS_PREFIXLEN, FRA_TABLE, FR_ACT_TO_TBL,
    ICMPV6_ROUTER_PREF_MEDIUM, NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_EXCL, NLM_F_MULTI, NLM_F_REQUEST,
    RTA_CACHEINFO, RTA_DST, RTA_OIF, RTA_PREF, RTA_PRIORITY, RTA_TABLE, RTM_DELROUTE, RTM_DELRULE,
    RTM_GETROUTE, RTM_GETRULE, RTM_NEWROUTE, RTM_NEWRULE, RTN_UNICAST, RTPROT_STATIC,
    RT_SCOPE_UNIVERSE, RT_TABLE_COMPAT, RT_TABLE_UNSPEC,
};

use crate::backend::{
    route_readback_after_owned_rollback, route_readback_failure_class,
    route_readback_to_convergence, rule_readback_after_owned_rollback, rule_readback_failure_class,
    rule_readback_to_convergence, RouteSteeringBackend,
};
use crate::error::{RouteSteeringError, RouteSteeringFailureClass};
use crate::model::{
    FirewallMark, IpPrefix, ReadbackIndeterminateReason, RouteConflict, RouteConvergenceOutcome,
    RouteMismatch, RouteReadback, RouteRequest, RouteRuleConvergenceOutcome, RouteRuleRollback,
    RouteSteeringBackendKind, RouteSteeringCapabilities, RouteSteeringProbe, RuleConflict,
    RuleConvergenceOutcome, RuleMismatch, RuleReadback, RuleRequest,
};
use crate::validation::{
    canonical_route_request, validate_owned_rule_request, validate_route_request,
    validate_rule_request,
};

const NETLINK_HEADER_LEN: usize = 16;
const ROUTE_ATTRIBUTE_HEADER_LEN: usize = 4;
const ROUTE_MESSAGE_LEN: usize = 12;
const FIB_RULE_HEADER_LEN: usize = 12;
const ROUTE_CACHEINFO_LEN: usize = 32;
const CAP_NET_ADMIN: u32 = 12;
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const EINVAL: i32 = 22;
const EPROTONOSUPPORT: i32 = 93;
const EOPNOTSUPP: i32 = 95;
const EAFNOSUPPORT: i32 = 97;
const NLA_TYPE_MASK: u16 = 0x3fff;
const MAX_RECEIVE_BUFFER_LEN: usize = 1024 * 1024;
const MAX_KERNEL_RELEASE_LEN: usize = 256;

/// Nonzero rtnetlink origin protocol reserved for one OpenPacketCore
/// convergence authority.
///
/// Routes and rules created by conflict-safe convergence carry this value in
/// route `rtm_protocol` and rule `FRA_PROTOCOL`. The legacy `install_*` methods
/// retain `RTPROT_STATIC`/untagged wire behavior. A Linux namespace must have
/// one coordinated owner of this protocol value; separate backend instances
/// and external writers require orchestration-level serialization.
pub const LINUX_ROUTE_STEERING_PROTOCOL: u8 = 242;

const RULE_PROTOCOL_CAPABILITY_UNCONFIRMED: u8 = 0;
const RULE_PROTOCOL_CAPABILITY_CONFIRMED: u8 = 1;
const RULE_PROTOCOL_CAPABILITY_UNSUPPORTED_REJECTED: u8 = 2;
const RULE_PROTOCOL_CAPABILITY_UNSUPPORTED_DISCARDED: u8 = 3;

/// Evidence for Linux `FRA_PROTOCOL` support used by conflict-safe rules.
///
/// Linux introduced this rule attribute in upstream 4.17. Kernel release text
/// can establish that a plain upstream kernel is too old, but an older vendor
/// or custom kernel may contain a backport and is therefore reported as
/// [`Self::Unknown`]. Only readback of the ownership tag proves support.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum LinuxRuleProtocolCapability {
    /// A resident rule was read back with the requested ownership protocol.
    /// Generic later create failures do not downgrade this positive evidence.
    Confirmed,
    /// The upstream kernel version includes `FRA_PROTOCOL`, but the current
    /// network namespace has not yet supplied positive readback evidence.
    ExpectedByKernelVersion,
    /// Capability cannot be inferred safely, including possible vendor
    /// backports on a pre-4.17 release.
    #[default]
    Unknown,
    /// A plain upstream pre-4.17 kernel is known not to implement the attribute.
    UnsupportedByKernelVersion,
    /// Before positive readback, a validated IPv4 ownership-tagged create was
    /// rejected with a kernel error used for unsupported attributes.
    UnsupportedByKernelRejection,
    /// A successful create was read back without the requested attribute.
    /// The detecting call attempts owned rollback and reports a rollback error
    /// unless absence is proved; subsequent convergence remains blocked.
    UnsupportedByReadback,
}

impl LinuxRuleProtocolCapability {
    const fn permits_verified_attempt(self) -> bool {
        !matches!(
            self,
            Self::UnsupportedByKernelVersion
                | Self::UnsupportedByKernelRejection
                | Self::UnsupportedByReadback
        )
    }
}

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

/// Hard bounds for one Linux route/rule resident-state readback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxRouteReadbackLimits {
    /// Maximum datagrams accepted for one multipart readback.
    pub max_datagrams: u16,
    /// Maximum netlink objects accepted for one readback.
    pub max_messages: u16,
    /// Maximum aggregate reply bytes accepted for one readback.
    pub max_bytes: usize,
}

impl Default for LinuxRouteReadbackLimits {
    fn default() -> Self {
        Self {
            max_datagrams: 64,
            max_messages: 4096,
            max_bytes: 1024 * 1024,
        }
    }
}

/// Production Linux route/rule steering backend.
///
/// Clones share one operation lock. Separate instances or external writers in
/// the same network namespace must be coordinated as one authority for
/// [`LINUX_ROUTE_STEERING_PROTOCOL`].
#[derive(Clone)]
pub struct LinuxRouteSteeringBackend {
    inner: Arc<LinuxRouteSteeringBackendInner>,
}

struct LinuxRouteSteeringBackendInner {
    transport: Arc<dyn LinuxRouteTransport>,
    next_sequence: AtomicU32,
    operation_lock: Mutex<()>,
    config: LinuxRouteSteeringBackendConfig,
    readback_limits: LinuxRouteReadbackLimits,
    rule_protocol_capability: AtomicU8,
}

impl fmt::Debug for LinuxRouteSteeringBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxRouteSteeringBackend")
            .field("config", &self.inner.config)
            .field("readback_limits", &self.inner.readback_limits)
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
        Self::with_config_and_readback_limits(config, LinuxRouteReadbackLimits::default())
    }

    /// Create a backend with custom transport behavior and readback bounds.
    #[must_use]
    pub fn with_config_and_readback_limits(
        config: LinuxRouteSteeringBackendConfig,
        readback_limits: LinuxRouteReadbackLimits,
    ) -> Self {
        Self {
            inner: Arc::new(LinuxRouteSteeringBackendInner {
                transport: Arc::new(NetlinkRouteTransport),
                next_sequence: AtomicU32::new(1),
                operation_lock: Mutex::new(()),
                config,
                readback_limits,
                rule_protocol_capability: AtomicU8::new(RULE_PROTOCOL_CAPABILITY_UNCONFIRMED),
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
                operation_lock: Mutex::new(()),
                config: LinuxRouteSteeringBackendConfig {
                    receive_attempts: 1,
                    receive_buffer_len: 4096,
                    retry_delay: Duration::ZERO,
                },
                readback_limits: LinuxRouteReadbackLimits::default(),
                rule_protocol_capability: AtomicU8::new(RULE_PROTOCOL_CAPABILITY_UNCONFIRMED),
            }),
        }
    }

    /// Return current evidence for Linux rule ownership protocol support.
    ///
    /// This method never mutates kernel state. An `ExpectedByKernelVersion` or
    /// `Unknown` result is followed by per-request post-create verification;
    /// it is not treated as proof that the kernel retained the attribute.
    #[must_use]
    pub fn rule_protocol_capability(&self) -> LinuxRuleProtocolCapability {
        match self.inner.rule_protocol_capability.load(Ordering::Acquire) {
            RULE_PROTOCOL_CAPABILITY_CONFIRMED => LinuxRuleProtocolCapability::Confirmed,
            RULE_PROTOCOL_CAPABILITY_UNSUPPORTED_REJECTED => {
                LinuxRuleProtocolCapability::UnsupportedByKernelRejection
            }
            RULE_PROTOCOL_CAPABILITY_UNSUPPORTED_DISCARDED => {
                LinuxRuleProtocolCapability::UnsupportedByReadback
            }
            _ => self.inner.transport.rule_protocol_capability(),
        }
    }

    fn require_rule_protocol_capability(&self) -> Result<(), RouteSteeringError> {
        if self.rule_protocol_capability().permits_verified_attempt() {
            Ok(())
        } else {
            Err(RouteSteeringError::indeterminate(
                ReadbackIndeterminateReason::OwnershipMarkerUnsupported,
            ))
        }
    }

    fn confirm_rule_protocol_capability(&self) {
        self.inner
            .rule_protocol_capability
            .store(RULE_PROTOCOL_CAPABILITY_CONFIRMED, Ordering::Release);
    }

    fn reject_rule_protocol_capability_from_readback(&self) {
        self.inner.rule_protocol_capability.store(
            RULE_PROTOCOL_CAPABILITY_UNSUPPORTED_DISCARDED,
            Ordering::Release,
        );
    }

    fn reject_rule_protocol_capability_from_kernel(&self) {
        // A generic create failure cannot invalidate hard positive readback
        // evidence. Publish negative kernel-rejection evidence only while the
        // runtime slot is still unconfirmed; a concurrent or prior Confirmed
        // observation wins permanently over this ambiguous failure class.
        let _ = self.inner.rule_protocol_capability.compare_exchange(
            RULE_PROTOCOL_CAPABILITY_UNCONFIRMED,
            RULE_PROTOCOL_CAPABILITY_UNSUPPORTED_REJECTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
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

    fn dump(
        &self,
        operation: &'static str,
        message_type: u16,
        expected_response_type: u16,
        body: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, RouteSteeringError> {
        validate_readback_config(self.inner.config, self.inner.readback_limits)?;
        let sequence = self.next_sequence();
        let request =
            encode_netlink_message(message_type, NLM_F_REQUEST | NLM_F_DUMP, sequence, &body)?;
        self.inner.transport.dump(
            operation,
            &request,
            sequence,
            expected_response_type,
            self.inner.config,
            self.inner.readback_limits,
        )
    }

    async fn run_ack(
        &self,
        operation: &'static str,
        message_type: u16,
        flags: u16,
        body: Vec<u8>,
    ) -> Result<(), RouteSteeringError> {
        self.run_locked(operation, move |backend| {
            let _ = backend.transact(operation, message_type, flags, body)?;
            Ok(())
        })
        .await
    }

    async fn run_locked<T, F>(
        &self,
        operation: &'static str,
        action: F,
    ) -> Result<T, RouteSteeringError>
    where
        T: Send + 'static,
        F: FnOnce(&Self) -> Result<T, RouteSteeringError> + Send + 'static,
    {
        let backend = self.clone();
        tokio::task::spawn_blocking(move || {
            let _operation_guard = backend
                .inner
                .operation_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            action(&backend)
        })
        .await
        .map_err(|_| blocking_task_error(operation))?
    }

    async fn run_read_route(
        &self,
        request: RouteRequest,
    ) -> Result<RouteReadback, RouteSteeringError> {
        self.run_locked("read_route", move |backend| {
            backend.read_route_sync(&request)
        })
        .await
    }

    async fn run_read_rule(
        &self,
        request: RuleRequest,
    ) -> Result<RuleReadback, RouteSteeringError> {
        self.run_locked("read_rule", move |backend| backend.read_rule_sync(&request))
            .await
    }

    async fn run_remove_converged_route(
        &self,
        request: RouteRequest,
    ) -> Result<(), RouteSteeringError> {
        self.run_locked("remove_converged_route", move |backend| {
            backend.remove_converged_route_sync(&request)
        })
        .await
    }

    async fn run_remove_converged_rule(
        &self,
        request: RuleRequest,
    ) -> Result<(), RouteSteeringError> {
        self.run_locked("remove_converged_rule", move |backend| {
            backend.remove_converged_rule_sync(&request)
        })
        .await
    }

    async fn run_converge_route(
        &self,
        request: RouteRequest,
    ) -> Result<RouteConvergenceOutcome, RouteSteeringError> {
        self.run_locked("converge_route", move |backend| {
            backend.converge_route_sync(&request)
        })
        .await
    }

    async fn run_converge_rule(
        &self,
        request: RuleRequest,
    ) -> Result<RuleConvergenceOutcome, RouteSteeringError> {
        self.run_locked("converge_rule", move |backend| {
            backend.converge_rule_sync(&request)
        })
        .await
    }

    async fn run_converge_pair(
        &self,
        route: RouteRequest,
        rule: RuleRequest,
    ) -> Result<RouteRuleConvergenceOutcome, RouteSteeringError> {
        self.run_locked("converge_route_and_rule", move |backend| {
            backend.converge_pair_sync(&route, &rule)
        })
        .await
    }

    fn read_route_sync(&self, request: &RouteRequest) -> Result<RouteReadback, RouteSteeringError> {
        validate_route_request(request)?;
        let bodies = self.dump(
            "read_route",
            RTM_GETROUTE,
            RTM_NEWROUTE,
            encode_route_dump_request(request),
        );
        match bodies {
            Ok(bodies) => match classify_route_readback(request, &bodies) {
                Ok(readback) => Ok(readback),
                Err(error) => readback_error_to_route(error),
            },
            Err(error) => readback_error_to_route(error),
        }
    }

    fn read_rule_sync(&self, request: &RuleRequest) -> Result<RuleReadback, RouteSteeringError> {
        self.read_rule_sync_with_protocol_evidence(request)
            .map(|(readback, _)| readback)
    }

    fn read_rule_sync_with_protocol_evidence(
        &self,
        request: &RuleRequest,
    ) -> Result<(RuleReadback, RuleProtocolReadbackEvidence), RouteSteeringError> {
        validate_rule_request(request)?;
        let bodies = self.dump(
            "read_rule",
            RTM_GETRULE,
            RTM_NEWRULE,
            encode_rule_dump_request(request)?,
        );
        match bodies {
            Ok(bodies) => match classify_rule_readback_with_protocol_evidence(request, &bodies) {
                Ok(classification) => Ok(classification),
                Err(error) => readback_error_to_rule(error)
                    .map(|readback| (readback, RuleProtocolReadbackEvidence::None)),
            },
            Err(error) => readback_error_to_rule(error)
                .map(|readback| (readback, RuleProtocolReadbackEvidence::None)),
        }
    }

    fn install_route_sync(&self, request: &RouteRequest) -> Result<(), RouteSteeringError> {
        let body = encode_route_request(request)?;
        let _ = self.transact(
            "install_route",
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )?;
        Ok(())
    }

    fn install_rule_sync(&self, request: &RuleRequest) -> Result<(), RouteSteeringError> {
        let body = encode_rule_request(request)?;
        let _ = self.transact(
            "install_rule",
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )?;
        Ok(())
    }

    fn remove_converged_route_sync(
        &self,
        request: &RouteRequest,
    ) -> Result<(), RouteSteeringError> {
        require_exact_route_for_removal(self.read_route_sync(request)?)?;
        let body = encode_route_request(request)?;
        let _ = self.transact(
            "remove_converged_route",
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )?;
        verify_route_removed(self.read_route_sync(request)?)
    }

    fn remove_converged_rule_sync(&self, request: &RuleRequest) -> Result<(), RouteSteeringError> {
        validate_owned_rule_request(request)?;
        self.require_rule_protocol_capability()?;
        let (readback, protocol_evidence) = self.read_rule_sync_with_protocol_evidence(request)?;
        require_exact_rule_for_removal(readback)?;
        if protocol_evidence == RuleProtocolReadbackEvidence::Confirmed {
            self.confirm_rule_protocol_capability();
        }
        let body = encode_rule_request(request)?;
        let _ = self.transact(
            "remove_converged_rule",
            RTM_DELRULE,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )?;
        verify_rule_removed(self.read_rule_sync(request)?)
    }

    /// Roll back only the rule whose exclusive create succeeded in the current
    /// serialized attempt. This intentionally skips ownership readback: an old
    /// or custom kernel may have ACKed the create while dropping
    /// `FRA_PROTOCOL`. The delete repeats every requested field and uses an
    /// untagged request only when readback proved the kernel discarded the
    /// marker; bounded readback must then prove the broad key absent.
    fn rollback_rule_after_owned_install_sync(
        &self,
        request: &RuleRequest,
        marker_was_discarded: bool,
    ) -> Result<(), RouteSteeringError> {
        let body = if marker_was_discarded {
            // A kernel which discarded FRA_PROTOCOL on create cannot be
            // trusted to match that attribute on delete. Strict owned-request
            // validation guarantees the remaining selector fields are not
            // Linux delete wildcards, and the pre-read plus exclusive ACK
            // identify this rule as owned by the current serialized attempt.
            encode_legacy_rule_request(request)?
        } else {
            encode_rule_request(request)?
        };
        let _ = self.transact(
            "rollback_converged_rule",
            RTM_DELRULE,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )?;
        verify_rule_removed(self.read_rule_sync(request)?)
    }

    fn converge_route_sync(
        &self,
        request: &RouteRequest,
    ) -> Result<RouteConvergenceOutcome, RouteSteeringError> {
        match self.read_route_sync(request)? {
            RouteReadback::Absent => {}
            RouteReadback::ExactPresent => {
                return Ok(RouteConvergenceOutcome::ExactAlreadyPresent);
            }
            RouteReadback::Conflict(conflict) => {
                return Ok(RouteConvergenceOutcome::Conflict(conflict));
            }
            RouteReadback::Indeterminate(reason) => {
                return Ok(RouteConvergenceOutcome::Indeterminate(reason));
            }
        }
        match self.install_route_sync(request) {
            Ok(()) => match self.read_route_sync(request) {
                Ok(RouteReadback::ExactPresent) => Ok(RouteConvergenceOutcome::Installed),
                Ok(readback) => {
                    let primary = route_readback_failure_class(&readback);
                    match self.remove_converged_route_sync(request) {
                        Ok(()) => Ok(route_readback_after_owned_rollback(readback)),
                        Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                            primary,
                            rollback: rollback.class(),
                        }),
                    }
                }
                Err(primary) => match self.remove_converged_route_sync(request) {
                    Ok(()) => Err(primary),
                    Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                        primary: primary.class(),
                        rollback: rollback.class(),
                    }),
                },
            },
            Err(RouteSteeringError::AlreadyExists) => Ok(route_readback_to_convergence(
                self.read_route_sync(request)?,
            )),
            Err(error) => Err(error),
        }
    }

    fn converge_rule_sync(
        &self,
        request: &RuleRequest,
    ) -> Result<RuleConvergenceOutcome, RouteSteeringError> {
        validate_owned_rule_request(request)?;
        if let Err(error) = self.require_rule_protocol_capability() {
            return match error {
                RouteSteeringError::ReadbackIndeterminate { reason } => {
                    Ok(RuleConvergenceOutcome::Indeterminate(reason))
                }
                other => Err(other),
            };
        }
        let (pre_readback, pre_protocol_evidence) =
            self.read_rule_sync_with_protocol_evidence(request)?;
        match pre_readback {
            RuleReadback::Absent => {}
            RuleReadback::ExactPresent => {
                if pre_protocol_evidence == RuleProtocolReadbackEvidence::Confirmed {
                    self.confirm_rule_protocol_capability();
                }
                return Ok(RuleConvergenceOutcome::ExactAlreadyPresent);
            }
            RuleReadback::Conflict(conflict) => {
                return Ok(RuleConvergenceOutcome::Conflict(conflict));
            }
            RuleReadback::Indeterminate(reason) => {
                return Ok(RuleConvergenceOutcome::Indeterminate(reason));
            }
        }
        match self.install_rule_sync(request) {
            Ok(()) => match self.read_rule_sync_with_protocol_evidence(request) {
                Ok((RuleReadback::ExactPresent, protocol_evidence)) => {
                    if protocol_evidence == RuleProtocolReadbackEvidence::Confirmed {
                        self.confirm_rule_protocol_capability();
                    }
                    Ok(RuleConvergenceOutcome::Installed)
                }
                Ok((readback, protocol_evidence)) => {
                    let marker_was_discarded = protocol_evidence
                        == RuleProtocolReadbackEvidence::MissingOnOnlySemanticMatch;
                    if marker_was_discarded {
                        self.reject_rule_protocol_capability_from_readback();
                    }
                    let primary = rule_readback_failure_class(&readback);
                    match self.rollback_rule_after_owned_install_sync(request, marker_was_discarded)
                    {
                        Ok(()) => Ok(rule_readback_after_owned_rollback(readback)),
                        Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                            primary,
                            rollback: rollback.class(),
                        }),
                    }
                }
                Err(primary) => match self.rollback_rule_after_owned_install_sync(request, false) {
                    Ok(()) => Err(primary),
                    Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                        primary: primary.class(),
                        rollback: rollback.class(),
                    }),
                },
            },
            Err(RouteSteeringError::AlreadyExists) => {
                let (readback, protocol_evidence) =
                    self.read_rule_sync_with_protocol_evidence(request)?;
                if protocol_evidence == RuleProtocolReadbackEvidence::Confirmed {
                    self.confirm_rule_protocol_capability();
                }
                Ok(rule_readback_to_convergence(readback))
            }
            Err(error) if rule_protocol_create_rejected(&error) => {
                // IPv4 is universally present on supported Linux builds, so a
                // validated tagged IPv4 rule rejected here is usable global
                // evidence about FRA_PROTOCOL only before positive tagged
                // readback. An IPv6-family rejection may instead mean IPv6
                // itself is unavailable. In either case, hard Confirmed
                // evidence is monotonic and the original operational error is
                // preserved rather than relabeled as marker failure.
                if rule_family(request)? != AF_INET
                    || self.rule_protocol_capability() == LinuxRuleProtocolCapability::Confirmed
                {
                    return Err(error);
                }
                self.reject_rule_protocol_capability_from_kernel();
                if self.rule_protocol_capability() == LinuxRuleProtocolCapability::Confirmed {
                    Err(error)
                } else {
                    Ok(RuleConvergenceOutcome::Indeterminate(
                        ReadbackIndeterminateReason::OwnershipMarkerUnsupported,
                    ))
                }
            }
            Err(error) => Err(error),
        }
    }

    fn converge_pair_sync(
        &self,
        route: &RouteRequest,
        rule: &RuleRequest,
    ) -> Result<RouteRuleConvergenceOutcome, RouteSteeringError> {
        validate_route_request(route)?;
        validate_owned_rule_request(rule)?;
        if !self.rule_protocol_capability().permits_verified_attempt() {
            return Ok(RouteRuleConvergenceOutcome {
                route: RouteConvergenceOutcome::NotAttempted,
                rule: RuleConvergenceOutcome::Indeterminate(
                    ReadbackIndeterminateReason::OwnershipMarkerUnsupported,
                ),
                rollback: RouteRuleRollback::NotNeeded,
            });
        }
        let route_outcome = self.converge_route_sync(route)?;
        if !matches!(
            route_outcome,
            RouteConvergenceOutcome::Installed | RouteConvergenceOutcome::ExactAlreadyPresent
        ) {
            let rollback = if route_outcome_has_owned_rollback(&route_outcome) {
                RouteRuleRollback::RemovedOwnedRoute
            } else {
                RouteRuleRollback::NotNeeded
            };
            return Ok(RouteRuleConvergenceOutcome {
                route: route_outcome,
                rule: RuleConvergenceOutcome::NotAttempted,
                rollback,
            });
        }

        let route_owned = matches!(route_outcome, RouteConvergenceOutcome::Installed);
        match self.converge_rule_sync(rule) {
            Ok(rule_outcome)
                if matches!(
                    rule_outcome,
                    RuleConvergenceOutcome::Installed | RuleConvergenceOutcome::ExactAlreadyPresent
                ) =>
            {
                Ok(RouteRuleConvergenceOutcome {
                    route: route_outcome,
                    rule: rule_outcome,
                    rollback: RouteRuleRollback::NotNeeded,
                })
            }
            Ok(rule_outcome) if route_owned => match self.remove_converged_route_sync(route) {
                Ok(()) => Ok(RouteRuleConvergenceOutcome {
                    route: RouteConvergenceOutcome::InstalledThenRolledBack,
                    rollback: if rule_outcome_has_owned_rollback(&rule_outcome) {
                        RouteRuleRollback::RemovedOwnedRouteAndRule
                    } else {
                        RouteRuleRollback::RemovedOwnedRoute
                    },
                    rule: rule_outcome,
                }),
                Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                    primary: convergence_failure_class(&rule_outcome),
                    rollback: rollback.class(),
                }),
            },
            Ok(rule_outcome) => Ok(RouteRuleConvergenceOutcome {
                route: route_outcome,
                rollback: if rule_outcome_has_owned_rollback(&rule_outcome) {
                    RouteRuleRollback::RemovedOwnedRule
                } else {
                    RouteRuleRollback::NotNeeded
                },
                rule: rule_outcome,
            }),
            Err(primary) if route_owned => match self.remove_converged_route_sync(route) {
                Ok(()) => Err(primary),
                Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                    primary: primary.class(),
                    rollback: rollback.class(),
                }),
            },
            Err(primary) => Err(primary),
        }
    }
}

#[async_trait]
impl RouteSteeringBackend for LinuxRouteSteeringBackend {
    async fn install_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError> {
        let body = encode_legacy_route_request(&request)?;
        self.run_ack(
            "install_route",
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )
        .await
    }

    async fn remove_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError> {
        let body = encode_legacy_route_request(&request)?;
        self.run_ack(
            "remove_route",
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            body,
        )
        .await
    }

    async fn install_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        let body = encode_legacy_rule_request(&request)?;
        self.run_ack(
            "install_rule",
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            body,
        )
        .await
    }

    async fn remove_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        let body = encode_legacy_rule_request(&request)?;
        self.run_ack("remove_rule", RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, body)
            .await
    }

    async fn remove_converged_route(
        &self,
        request: RouteRequest,
    ) -> Result<(), RouteSteeringError> {
        self.run_remove_converged_route(request).await
    }

    async fn remove_converged_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        self.run_remove_converged_rule(request).await
    }

    async fn read_route(
        &self,
        request: &RouteRequest,
    ) -> Result<RouteReadback, RouteSteeringError> {
        self.run_read_route(request.clone()).await
    }

    async fn read_rule(&self, request: &RuleRequest) -> Result<RuleReadback, RouteSteeringError> {
        self.run_read_rule(request.clone()).await
    }

    async fn converge_route(
        &self,
        request: RouteRequest,
    ) -> Result<RouteConvergenceOutcome, RouteSteeringError> {
        self.run_converge_route(request).await
    }

    async fn converge_rule(
        &self,
        request: RuleRequest,
    ) -> Result<RuleConvergenceOutcome, RouteSteeringError> {
        self.run_converge_rule(request).await
    }

    async fn converge_route_and_rule(
        &self,
        route: RouteRequest,
        rule: RuleRequest,
    ) -> Result<RouteRuleConvergenceOutcome, RouteSteeringError> {
        self.run_converge_pair(route, rule).await
    }

    async fn probe(&self) -> Result<RouteSteeringProbe, RouteSteeringError> {
        Ok(self.inner.transport.probe(self.inner.config))
    }

    async fn capabilities(&self) -> RouteSteeringCapabilities {
        let rule_convergence = self.rule_protocol_capability().permits_verified_attempt();
        RouteSteeringCapabilities {
            legacy_mutation: true,
            conflict_safe_route_convergence: true,
            conflict_safe_rule_convergence: rule_convergence,
            paired_convergence: rule_convergence,
        }
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

    fn dump(
        &self,
        _operation: &'static str,
        _request: &[u8],
        _expected_sequence: u32,
        _expected_message_type: u16,
        _config: LinuxRouteSteeringBackendConfig,
        _limits: LinuxRouteReadbackLimits,
    ) -> Result<Vec<Vec<u8>>, RouteSteeringError> {
        Err(RouteSteeringError::indeterminate(
            ReadbackIndeterminateReason::Unsupported,
        ))
    }

    fn probe(&self, config: LinuxRouteSteeringBackendConfig) -> RouteSteeringProbe;

    fn rule_protocol_capability(&self) -> LinuxRuleProtocolCapability {
        LinuxRuleProtocolCapability::Unknown
    }
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

    fn dump(
        &self,
        operation: &'static str,
        request: &[u8],
        expected_sequence: u32,
        expected_message_type: u16,
        config: LinuxRouteSteeringBackendConfig,
        limits: LinuxRouteReadbackLimits,
    ) -> Result<Vec<Vec<u8>>, RouteSteeringError> {
        validate_readback_config(config, limits)?;
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
        let mut messages = Vec::new();
        let mut datagrams = 0_u16;
        let mut total_bytes = 0_usize;
        let mut empty_attempts = 0_u16;
        while empty_attempts < config.receive_attempts {
            match receive_message(&socket, &mut buffer) {
                Ok(0) => empty_attempts = empty_attempts.saturating_add(1),
                Ok(len) => {
                    empty_attempts = 0;
                    account_dump_datagram(&mut datagrams, &mut total_bytes, len, limits)?;
                    let done = parse_dump_datagram(
                        &buffer[..len],
                        expected_sequence,
                        expected_message_type,
                        limits.max_messages,
                        &mut messages,
                    )?;
                    if done {
                        return Ok(messages);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    empty_attempts = empty_attempts.saturating_add(1);
                }
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    return Err(RouteSteeringError::indeterminate(
                        ReadbackIndeterminateReason::MalformedReply,
                    ));
                }
                Err(error) => return Err(RouteSteeringError::io("netlink_receive", error)),
            }
            if !config.retry_delay.is_zero() {
                std::thread::sleep(config.retry_delay);
            }
        }

        Err(RouteSteeringError::indeterminate(
            ReadbackIndeterminateReason::IncompleteReply,
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

    fn rule_protocol_capability(&self) -> LinuxRuleProtocolCapability {
        linux_rule_protocol_capability_from_osrelease()
    }
}

fn map_open_error(operation: &'static str, error: io::Error) -> RouteSteeringError {
    if error.kind() == io::ErrorKind::Unsupported {
        RouteSteeringError::UnsupportedPlatform
    } else {
        RouteSteeringError::io(operation, error)
    }
}

fn blocking_task_error(operation: &'static str) -> RouteSteeringError {
    RouteSteeringError::io(
        operation,
        io::Error::new(io::ErrorKind::Interrupted, "route blocking task failed"),
    )
}

fn validate_readback_config(
    config: LinuxRouteSteeringBackendConfig,
    limits: LinuxRouteReadbackLimits,
) -> Result<(), RouteSteeringError> {
    if config.receive_attempts == 0 {
        return Err(RouteSteeringError::invalid_config(
            "linux.receive_attempts",
            "receive attempts must be nonzero",
        ));
    }
    if !(NETLINK_HEADER_LEN..=MAX_RECEIVE_BUFFER_LEN).contains(&config.receive_buffer_len) {
        return Err(RouteSteeringError::invalid_config(
            "linux.receive_buffer_len",
            "receive buffer is outside supported bounds",
        ));
    }
    if limits.max_datagrams == 0 {
        return Err(RouteSteeringError::invalid_config(
            "linux.max_readback_datagrams",
            "readback datagram limit must be nonzero",
        ));
    }
    if limits.max_messages == 0 {
        return Err(RouteSteeringError::invalid_config(
            "linux.max_readback_messages",
            "readback message limit must be nonzero",
        ));
    }
    if limits.max_bytes < config.receive_buffer_len {
        return Err(RouteSteeringError::invalid_config(
            "linux.max_readback_bytes",
            "readback byte limit must cover one receive buffer",
        ));
    }
    Ok(())
}

fn account_dump_datagram(
    datagrams: &mut u16,
    total_bytes: &mut usize,
    received_bytes: usize,
    limits: LinuxRouteReadbackLimits,
) -> Result<(), RouteSteeringError> {
    *datagrams = datagrams.checked_add(1).ok_or_else(|| {
        RouteSteeringError::indeterminate(ReadbackIndeterminateReason::LimitExceeded)
    })?;
    *total_bytes = total_bytes.checked_add(received_bytes).ok_or_else(|| {
        RouteSteeringError::indeterminate(ReadbackIndeterminateReason::LimitExceeded)
    })?;
    if *datagrams > limits.max_datagrams || *total_bytes > limits.max_bytes {
        return Err(RouteSteeringError::indeterminate(
            ReadbackIndeterminateReason::LimitExceeded,
        ));
    }
    Ok(())
}

fn readback_reason(error: &RouteSteeringError) -> Option<ReadbackIndeterminateReason> {
    match error {
        RouteSteeringError::UnsupportedPlatform => Some(ReadbackIndeterminateReason::Unsupported),
        RouteSteeringError::ReadbackIndeterminate { reason } => Some(*reason),
        RouteSteeringError::Io { kind, .. } => Some(match kind {
            io::ErrorKind::InvalidData => ReadbackIndeterminateReason::MalformedReply,
            io::ErrorKind::TimedOut => ReadbackIndeterminateReason::IncompleteReply,
            io::ErrorKind::Unsupported => ReadbackIndeterminateReason::Unsupported,
            _ => ReadbackIndeterminateReason::BackendUnavailable,
        }),
        _ => None,
    }
}

fn readback_error_to_route(error: RouteSteeringError) -> Result<RouteReadback, RouteSteeringError> {
    match readback_reason(&error) {
        Some(reason) => Ok(RouteReadback::Indeterminate(reason)),
        None => Err(error),
    }
}

fn readback_error_to_rule(error: RouteSteeringError) -> Result<RuleReadback, RouteSteeringError> {
    match readback_reason(&error) {
        Some(reason) => Ok(RuleReadback::Indeterminate(reason)),
        None => Err(error),
    }
}

fn require_exact_route_for_removal(readback: RouteReadback) -> Result<(), RouteSteeringError> {
    match readback {
        RouteReadback::ExactPresent => Ok(()),
        RouteReadback::Absent => Err(RouteSteeringError::NotFound),
        RouteReadback::Conflict(_) => Err(RouteSteeringError::AlreadyExists),
        RouteReadback::Indeterminate(reason) => Err(RouteSteeringError::indeterminate(reason)),
    }
}

fn require_exact_rule_for_removal(readback: RuleReadback) -> Result<(), RouteSteeringError> {
    match readback {
        RuleReadback::ExactPresent => Ok(()),
        RuleReadback::Absent => Err(RouteSteeringError::NotFound),
        RuleReadback::Conflict(_) => Err(RouteSteeringError::AlreadyExists),
        RuleReadback::Indeterminate(reason) => Err(RouteSteeringError::indeterminate(reason)),
    }
}

fn verify_route_removed(readback: RouteReadback) -> Result<(), RouteSteeringError> {
    match readback {
        RouteReadback::Absent => Ok(()),
        _ => Err(RouteSteeringError::indeterminate(
            ReadbackIndeterminateReason::ConcurrentModification,
        )),
    }
}

fn verify_rule_removed(readback: RuleReadback) -> Result<(), RouteSteeringError> {
    match readback {
        RuleReadback::Absent => Ok(()),
        _ => Err(RouteSteeringError::indeterminate(
            ReadbackIndeterminateReason::ConcurrentModification,
        )),
    }
}

fn convergence_failure_class(outcome: &RuleConvergenceOutcome) -> RouteSteeringFailureClass {
    match outcome {
        RuleConvergenceOutcome::Conflict(_)
        | RuleConvergenceOutcome::ConflictAfterOwnedRollback(_) => {
            RouteSteeringFailureClass::AlreadyExists
        }
        RuleConvergenceOutcome::Indeterminate(_)
        | RuleConvergenceOutcome::IndeterminateAfterOwnedRollback(_)
        | RuleConvergenceOutcome::NotAttempted => RouteSteeringFailureClass::ReadbackIndeterminate,
        RuleConvergenceOutcome::Installed | RuleConvergenceOutcome::ExactAlreadyPresent => {
            RouteSteeringFailureClass::Io
        }
    }
}

fn route_outcome_has_owned_rollback(outcome: &RouteConvergenceOutcome) -> bool {
    matches!(
        outcome,
        RouteConvergenceOutcome::ConflictAfterOwnedRollback(_)
            | RouteConvergenceOutcome::IndeterminateAfterOwnedRollback(_)
            | RouteConvergenceOutcome::InstalledThenRolledBack
    )
}

fn rule_outcome_has_owned_rollback(outcome: &RuleConvergenceOutcome) -> bool {
    matches!(
        outcome,
        RuleConvergenceOutcome::ConflictAfterOwnedRollback(_)
            | RuleConvergenceOutcome::IndeterminateAfterOwnedRollback(_)
    )
}

fn encode_route_dump_request(request: &RouteRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(ROUTE_MESSAGE_LEN);
    push_u8(&mut out, encode_family(request.destination.address));
    out.resize(ROUTE_MESSAGE_LEN, 0);
    out
}

fn encode_rule_dump_request(request: &RuleRequest) -> Result<Vec<u8>, RouteSteeringError> {
    let mut out = Vec::with_capacity(FIB_RULE_HEADER_LEN);
    push_u8(&mut out, rule_family(request)?);
    out.resize(FIB_RULE_HEADER_LEN, 0);
    Ok(out)
}

fn encode_route_request(request: &RouteRequest) -> Result<Vec<u8>, RouteSteeringError> {
    let request = canonical_route_request(request);
    encode_route_request_with_protocol(&request, LINUX_ROUTE_STEERING_PROTOCOL, request.priority)
}

fn encode_legacy_route_request(request: &RouteRequest) -> Result<Vec<u8>, RouteSteeringError> {
    encode_route_request_with_protocol(request, RTPROT_STATIC, request.priority)
}

fn encode_route_request_with_protocol(
    request: &RouteRequest,
    protocol: u8,
    priority: Option<u32>,
) -> Result<Vec<u8>, RouteSteeringError> {
    validate_route_request(request)?;
    let mut out = Vec::with_capacity(ROUTE_MESSAGE_LEN + 64);
    push_u8(&mut out, encode_family(request.destination.address));
    push_u8(&mut out, request.destination.prefix_len);
    push_u8(&mut out, 0);
    push_u8(&mut out, 0);
    push_u8(&mut out, table_header_value(request.table)?);
    push_u8(&mut out, protocol);
    push_u8(&mut out, RT_SCOPE_UNIVERSE);
    push_u8(&mut out, RTN_UNICAST);
    push_u32_ne(&mut out, 0);
    debug_assert_eq!(out.len(), ROUTE_MESSAGE_LEN);
    append_ip_attr(&mut out, RTA_DST, request.destination.address)?;
    append_attr_u32_ne(&mut out, RTA_OIF, request.oif_ifindex)?;
    if let Some(priority) = priority {
        append_attr_u32_ne(&mut out, RTA_PRIORITY, priority)?;
    }
    if request.table > u32::from(u8::MAX) {
        append_attr_u32_ne(&mut out, RTA_TABLE, request.table)?;
    }
    Ok(out)
}

fn encode_rule_request(request: &RuleRequest) -> Result<Vec<u8>, RouteSteeringError> {
    validate_owned_rule_request(request)?;
    encode_rule_request_with_protocol(request, Some(LINUX_ROUTE_STEERING_PROTOCOL))
}

fn encode_legacy_rule_request(request: &RuleRequest) -> Result<Vec<u8>, RouteSteeringError> {
    encode_rule_request_with_protocol(request, None)
}

fn encode_rule_request_with_protocol(
    request: &RuleRequest,
    protocol: Option<u8>,
) -> Result<Vec<u8>, RouteSteeringError> {
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
    if let Some(protocol) = protocol {
        append_attr(&mut out, FRA_PROTOCOL, &[protocol])?;
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

fn parse_dump_datagram(
    response: &[u8],
    expected_sequence: u32,
    expected_message_type: u16,
    max_messages: u16,
    messages: &mut Vec<Vec<u8>>,
) -> Result<bool, RouteSteeringError> {
    let mut offset = 0_usize;
    let mut done = false;
    while offset < response.len() {
        if response.len() - offset < NETLINK_HEADER_LEN {
            return Err(malformed_readback());
        }
        let length =
            usize::try_from(read_u32_ne(response, offset)?).map_err(|_| malformed_readback())?;
        let end = offset.checked_add(length).ok_or_else(malformed_readback)?;
        if length < NETLINK_HEADER_LEN || end > response.len() {
            return Err(malformed_readback());
        }
        let message_type = read_u16_ne(response, offset + 4)?;
        let flags = read_u16_ne(response, offset + 6)?;
        let sequence = read_u32_ne(response, offset + 8)?;
        if sequence != expected_sequence {
            return Err(malformed_readback());
        }
        if done && message_type != NLMSG_NOOP {
            return Err(malformed_readback());
        }
        let body = &response[offset + NETLINK_HEADER_LEN..end];
        if flags & NLM_F_DUMP_INTR != 0 {
            return Err(RouteSteeringError::indeterminate(
                ReadbackIndeterminateReason::IncompleteReply,
            ));
        }
        match message_type {
            NLMSG_ERROR => parse_netlink_error(body)?,
            NLMSG_DONE => {
                if flags & NLM_F_MULTI == 0 {
                    return Err(malformed_readback());
                }
                parse_dump_done(body)?;
                done = true;
            }
            NLMSG_OVERRUN => {
                return Err(RouteSteeringError::indeterminate(
                    ReadbackIndeterminateReason::IncompleteReply,
                ));
            }
            NLMSG_NOOP => {}
            message_type if message_type == expected_message_type => {
                if flags & NLM_F_MULTI == 0 || done {
                    return Err(malformed_readback());
                }
                let next_count = messages.len().checked_add(1).ok_or_else(|| {
                    RouteSteeringError::indeterminate(ReadbackIndeterminateReason::LimitExceeded)
                })?;
                if next_count > usize::from(max_messages) {
                    return Err(RouteSteeringError::indeterminate(
                        ReadbackIndeterminateReason::LimitExceeded,
                    ));
                }
                messages.push(body.to_vec());
            }
            _ => return Err(malformed_readback()),
        }

        let aligned = align_to_netlink(length).ok_or_else(malformed_readback)?;
        let aligned_end = offset.checked_add(aligned).ok_or_else(malformed_readback)?;
        if aligned_end > response.len() {
            return Err(malformed_readback());
        }
        if response[end..aligned_end].iter().any(|byte| *byte != 0) {
            return Err(malformed_readback());
        }
        offset = aligned_end;
    }
    Ok(done)
}

fn parse_dump_done(body: &[u8]) -> Result<(), RouteSteeringError> {
    if body.is_empty() {
        return Ok(());
    }
    if body.len() < 4 {
        return Err(malformed_readback());
    }
    parse_netlink_error(body)
}

#[derive(Debug)]
struct ParsedRouteCandidate {
    destination: IpPrefix,
    resident: Option<RouteRequest>,
    fixed_semantics_exact: bool,
    has_unrepresented_attributes: bool,
}

#[derive(Debug)]
struct ParsedRuleCandidate {
    family: u8,
    priority: Option<u32>,
    resident: Option<RuleRequest>,
    fixed_kernel_semantics_exact: bool,
    protocol: Option<u8>,
    has_unrepresented_attributes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleProtocolReadbackEvidence {
    None,
    Confirmed,
    MissingOnOnlySemanticMatch,
}

fn classify_route_readback(
    request: &RouteRequest,
    bodies: &[Vec<u8>],
) -> Result<RouteReadback, RouteSteeringError> {
    let request = canonical_route_request(request);
    let mut candidate_count = 0_u16;
    let mut resident: Option<RouteRequest> = None;
    let mut aggregate = RouteMismatch::default();
    let mut every_candidate_exact = true;
    for body in bodies {
        let Some(candidate) = parse_route_candidate(body)? else {
            continue;
        };
        if candidate.destination != request.destination {
            continue;
        }
        candidate_count = candidate_count.checked_add(1).ok_or_else(|| {
            RouteSteeringError::indeterminate(ReadbackIndeterminateReason::LimitExceeded)
        })?;
        if candidate.has_unrepresented_attributes || candidate.resident.is_none() {
            return Ok(RouteReadback::Indeterminate(
                ReadbackIndeterminateReason::UnrepresentableObject,
            ));
        }
        let current = match candidate.resident {
            Some(current) => current,
            None => {
                return Ok(RouteReadback::Indeterminate(
                    ReadbackIndeterminateReason::UnrepresentableObject,
                ));
            }
        };
        let mismatch = RouteMismatch {
            output_interface: current.oif_ifindex != request.oif_ifindex,
            table: current.table != request.table,
            priority: current.priority != request.priority,
            kernel_semantics: !candidate.fixed_semantics_exact,
        };
        let exact = current == request && candidate.fixed_semantics_exact;
        every_candidate_exact &= exact;
        aggregate.output_interface |= mismatch.output_interface;
        aggregate.table |= mismatch.table;
        aggregate.priority |= mismatch.priority;
        aggregate.kernel_semantics |= mismatch.kernel_semantics;
        if resident.as_ref().is_none_or(|prior| current < *prior) {
            resident = Some(current);
        }
    }

    match (candidate_count, resident) {
        (0, _) => Ok(RouteReadback::Absent),
        (1, Some(_)) if every_candidate_exact => Ok(RouteReadback::ExactPresent),
        (_, Some(resident)) => Ok(RouteReadback::Conflict(RouteConflict::new(
            resident,
            nonzero_candidate_count(candidate_count)?,
            aggregate,
        ))),
        _ => Ok(RouteReadback::Indeterminate(
            ReadbackIndeterminateReason::UnrepresentableObject,
        )),
    }
}

#[cfg(test)]
fn classify_rule_readback(
    request: &RuleRequest,
    bodies: &[Vec<u8>],
) -> Result<RuleReadback, RouteSteeringError> {
    classify_rule_readback_with_protocol_evidence(request, bodies).map(|(readback, _)| readback)
}

fn classify_rule_readback_with_protocol_evidence(
    request: &RuleRequest,
    bodies: &[Vec<u8>],
) -> Result<(RuleReadback, RuleProtocolReadbackEvidence), RouteSteeringError> {
    let expected_family = rule_family(request)?;
    let mut candidate_count = 0_u16;
    let mut resident: Option<RuleRequest> = None;
    let mut aggregate = RuleMismatch::default();
    let mut every_candidate_exact = true;
    let mut protocol_evidence = RuleProtocolReadbackEvidence::None;
    for body in bodies {
        let Some(candidate) = parse_rule_candidate(body)? else {
            continue;
        };
        if candidate.family != expected_family || candidate.priority != Some(request.priority) {
            continue;
        }
        candidate_count = candidate_count.checked_add(1).ok_or_else(|| {
            RouteSteeringError::indeterminate(ReadbackIndeterminateReason::LimitExceeded)
        })?;
        if candidate.has_unrepresented_attributes || candidate.resident.is_none() {
            return Ok((
                RuleReadback::Indeterminate(ReadbackIndeterminateReason::UnrepresentableObject),
                RuleProtocolReadbackEvidence::None,
            ));
        }
        let current = match candidate.resident {
            Some(current) => current,
            None => {
                return Ok((
                    RuleReadback::Indeterminate(ReadbackIndeterminateReason::UnrepresentableObject),
                    RuleProtocolReadbackEvidence::None,
                ));
            }
        };
        if candidate_count == 1 && current == *request && candidate.fixed_kernel_semantics_exact {
            protocol_evidence = match candidate.protocol {
                Some(LINUX_ROUTE_STEERING_PROTOCOL) => RuleProtocolReadbackEvidence::Confirmed,
                None => RuleProtocolReadbackEvidence::MissingOnOnlySemanticMatch,
                Some(_) => RuleProtocolReadbackEvidence::None,
            };
        } else {
            protocol_evidence = RuleProtocolReadbackEvidence::None;
        }
        let mismatch = RuleMismatch {
            source: current.source != request.source,
            destination: current.destination != request.destination,
            firewall_mark: current.fwmark != request.fwmark,
            table: current.table != request.table,
            kernel_semantics: !candidate.fixed_kernel_semantics_exact
                || candidate.protocol != Some(LINUX_ROUTE_STEERING_PROTOCOL),
        };
        let exact = current == *request
            && candidate.fixed_kernel_semantics_exact
            && candidate.protocol == Some(LINUX_ROUTE_STEERING_PROTOCOL);
        every_candidate_exact &= exact;
        aggregate.source |= mismatch.source;
        aggregate.destination |= mismatch.destination;
        aggregate.firewall_mark |= mismatch.firewall_mark;
        aggregate.table |= mismatch.table;
        aggregate.kernel_semantics |= mismatch.kernel_semantics;
        if resident.as_ref().is_none_or(|prior| current < *prior) {
            resident = Some(current);
        }
    }

    match (candidate_count, resident) {
        (0, _) => Ok((RuleReadback::Absent, RuleProtocolReadbackEvidence::None)),
        (1, Some(_)) if every_candidate_exact => {
            Ok((RuleReadback::ExactPresent, protocol_evidence))
        }
        (_, Some(resident)) => Ok((
            RuleReadback::Conflict(RuleConflict::new(
                resident,
                nonzero_candidate_count(candidate_count)?,
                aggregate,
            )),
            protocol_evidence,
        )),
        _ => Ok((
            RuleReadback::Indeterminate(ReadbackIndeterminateReason::UnrepresentableObject),
            RuleProtocolReadbackEvidence::None,
        )),
    }
}

fn nonzero_candidate_count(candidate_count: u16) -> Result<NonZeroU16, RouteSteeringError> {
    NonZeroU16::new(candidate_count).ok_or_else(|| {
        RouteSteeringError::indeterminate(ReadbackIndeterminateReason::ConcurrentModification)
    })
}

fn parse_route_candidate(body: &[u8]) -> Result<Option<ParsedRouteCandidate>, RouteSteeringError> {
    if body.len() < ROUTE_MESSAGE_LEN {
        return Err(malformed_readback());
    }
    let family = body[0];
    if !matches!(family, AF_INET | AF_INET6) {
        parse_attributes(body, ROUTE_MESSAGE_LEN, |_, _, _| Ok(()))?;
        return Ok(None);
    }
    let destination_prefix_len = body[1];
    let prefix_limit = if family == AF_INET { 32 } else { 128 };
    if destination_prefix_len > prefix_limit {
        return Err(malformed_readback());
    }
    let header_table = u32::from(body[4]);
    let fixed_semantics_exact = body[2] == 0
        && body[3] == 0
        && body[5] == LINUX_ROUTE_STEERING_PROTOCOL
        && body[6] == RT_SCOPE_UNIVERSE
        && body[7] == RTN_UNICAST
        && read_u32_ne(body, 8)? == 0;

    let mut destination = None;
    let mut oif = None;
    let mut priority = None;
    let mut table_attr = None;
    let mut preference = None;
    let mut cacheinfo_semantic_state = None;
    let mut unrepresented = false;
    parse_attributes(body, ROUTE_MESSAGE_LEN, |attr_type, raw_type, payload| {
        let flagged = attr_type != raw_type;
        match attr_type {
            RTA_DST => set_once_ip(&mut destination, family, payload, flagged),
            RTA_OIF => set_once_u32(&mut oif, payload, flagged),
            RTA_PRIORITY => set_once_u32(&mut priority, payload, flagged),
            RTA_TABLE => set_once_u32(&mut table_attr, payload, flagged),
            RTA_PREF => set_once_u8(&mut preference, payload, flagged),
            RTA_CACHEINFO => {
                set_once_route_cacheinfo(&mut cacheinfo_semantic_state, payload, flagged)
            }
            _ => {
                unrepresented = true;
                Ok(())
            }
        }
    })?;
    if let Some(table_attr) = table_attr {
        if header_table != u32::from(RT_TABLE_UNSPEC)
            && header_table != u32::from(RT_TABLE_COMPAT)
            && header_table != table_attr
        {
            return Err(malformed_readback());
        }
    }
    if destination_prefix_len != 0 && destination.is_none() {
        return Err(malformed_readback());
    }
    if family == AF_INET6 && priority.is_none() {
        return Err(malformed_readback());
    }
    if preference.is_some_and(|value| value != ICMPV6_ROUTER_PREF_MEDIUM) {
        unrepresented = true;
    }
    if cacheinfo_semantic_state == Some(true) {
        unrepresented = true;
    }
    let table = table_attr.unwrap_or(header_table);
    let address = destination.unwrap_or_else(|| unspecified_address(family));
    let destination = IpPrefix::new(address, destination_prefix_len);
    let resident = oif.filter(|_| table != 0).map(|oif_ifindex| {
        canonical_route_request(&RouteRequest {
            destination,
            oif_ifindex,
            table,
            priority,
        })
    });
    Ok(Some(ParsedRouteCandidate {
        destination,
        resident,
        fixed_semantics_exact,
        has_unrepresented_attributes: unrepresented,
    }))
}

fn parse_rule_candidate(body: &[u8]) -> Result<Option<ParsedRuleCandidate>, RouteSteeringError> {
    if body.len() < FIB_RULE_HEADER_LEN {
        return Err(malformed_readback());
    }
    let family = body[0];
    if !matches!(family, AF_UNSPEC | AF_INET | AF_INET6) {
        parse_attributes(body, FIB_RULE_HEADER_LEN, |_, _, _| Ok(()))?;
        return Ok(None);
    }
    let destination_prefix_len = body[1];
    let source_prefix_len = body[2];
    let prefix_limit = if family == AF_INET6 { 128 } else { 32 };
    if destination_prefix_len > prefix_limit || source_prefix_len > prefix_limit {
        return Err(malformed_readback());
    }
    let header_table = u32::from(body[4]);
    let header_semantics_exact = body[3] == 0
        && body[5] == 0
        && body[6] == 0
        && body[7] == FR_ACT_TO_TBL
        && read_u32_ne(body, 8)? == 0;
    let mut destination_address = None;
    let mut source_address = None;
    let mut mark = None;
    let mut mask = None;
    let mut priority = None;
    let mut table_attr = None;
    let mut suppress_ifgroup = None;
    let mut suppress_prefix_len = None;
    let mut protocol = None;
    let mut padding_seen = false;
    let mut unrepresented = false;
    parse_attributes(body, FIB_RULE_HEADER_LEN, |attr_type, raw_type, payload| {
        let flagged = attr_type != raw_type;
        match attr_type {
            FRA_DST => set_once_ip(&mut destination_address, family, payload, flagged),
            FRA_SRC => set_once_ip(&mut source_address, family, payload, flagged),
            FRA_FWMARK => set_once_u32(&mut mark, payload, flagged),
            FRA_FWMASK => set_once_u32(&mut mask, payload, flagged),
            FRA_PRIORITY => set_once_u32(&mut priority, payload, flagged),
            FRA_TABLE => set_once_u32(&mut table_attr, payload, flagged),
            FRA_SUPPRESS_IFGROUP => set_once_u32(&mut suppress_ifgroup, payload, flagged),
            FRA_SUPPRESS_PREFIXLEN => set_once_u32(&mut suppress_prefix_len, payload, flagged),
            FRA_PROTOCOL => set_once_u8(&mut protocol, payload, flagged),
            FRA_PAD => set_once_padding(&mut padding_seen, payload, flagged),
            _ => {
                unrepresented = true;
                Ok(())
            }
        }
    })?;
    if let Some(table_attr) = table_attr {
        if header_table != u32::from(RT_TABLE_UNSPEC)
            && header_table != u32::from(RT_TABLE_COMPAT)
            && header_table != table_attr
        {
            return Err(malformed_readback());
        }
    }
    if suppress_ifgroup.is_some_and(|value| value != u32::MAX)
        || suppress_prefix_len.is_some_and(|value| value != u32::MAX)
    {
        unrepresented = true;
    }
    if destination_prefix_len != 0 && destination_address.is_none() {
        return Err(malformed_readback());
    }
    if source_prefix_len != 0 && source_address.is_none() {
        return Err(malformed_readback());
    }
    let destination =
        destination_address.map(|address| IpPrefix::new(address, destination_prefix_len));
    let source = source_address.map(|address| IpPrefix::new(address, source_prefix_len));
    let fwmark = mark.or_else(|| mask.map(|_| 0)).map(|value| FirewallMark {
        value,
        mask: mask.unwrap_or(u32::MAX),
    });
    let table = table_attr.unwrap_or(header_table);
    let resident = if table != 0 && (source.is_some() || destination.is_some() || fwmark.is_some())
    {
        Some(RuleRequest {
            source,
            destination,
            fwmark,
            table,
            priority: priority.unwrap_or(0),
        })
    } else {
        None
    };
    Ok(Some(ParsedRuleCandidate {
        family,
        priority,
        resident,
        fixed_kernel_semantics_exact: header_semantics_exact,
        protocol,
        has_unrepresented_attributes: unrepresented,
    }))
}

fn parse_attributes<F>(
    body: &[u8],
    mut offset: usize,
    mut visitor: F,
) -> Result<(), RouteSteeringError>
where
    F: FnMut(u16, u16, &[u8]) -> Result<(), RouteSteeringError>,
{
    while offset < body.len() {
        if body.len() - offset < ROUTE_ATTRIBUTE_HEADER_LEN {
            return Err(malformed_readback());
        }
        let length = usize::from(read_u16_ne(body, offset)?);
        let raw_type = read_u16_ne(body, offset + 2)?;
        let end = offset.checked_add(length).ok_or_else(malformed_readback)?;
        if length < ROUTE_ATTRIBUTE_HEADER_LEN || end > body.len() {
            return Err(malformed_readback());
        }
        visitor(
            raw_type & NLA_TYPE_MASK,
            raw_type,
            &body[offset + ROUTE_ATTRIBUTE_HEADER_LEN..end],
        )?;
        let aligned = align_to_netlink(length).ok_or_else(malformed_readback)?;
        let aligned_end = offset.checked_add(aligned).ok_or_else(malformed_readback)?;
        if aligned_end > body.len() || body[end..aligned_end].iter().any(|byte| *byte != 0) {
            return Err(malformed_readback());
        }
        offset = aligned_end;
    }
    Ok(())
}

fn set_once_u32(
    slot: &mut Option<u32>,
    payload: &[u8],
    flagged: bool,
) -> Result<(), RouteSteeringError> {
    if flagged || slot.is_some() || payload.len() != 4 {
        return Err(malformed_readback());
    }
    *slot = Some(u32::from_ne_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]));
    Ok(())
}

fn set_once_u8(
    slot: &mut Option<u8>,
    payload: &[u8],
    flagged: bool,
) -> Result<(), RouteSteeringError> {
    if flagged || slot.is_some() || payload.len() != 1 {
        return Err(malformed_readback());
    }
    *slot = Some(payload[0]);
    Ok(())
}

fn set_once_padding(
    seen: &mut bool,
    payload: &[u8],
    flagged: bool,
) -> Result<(), RouteSteeringError> {
    if flagged || *seen || payload.iter().any(|byte| *byte != 0) {
        return Err(malformed_readback());
    }
    *seen = true;
    Ok(())
}

fn set_once_route_cacheinfo(
    semantic_state: &mut Option<bool>,
    payload: &[u8],
    flagged: bool,
) -> Result<(), RouteSteeringError> {
    if flagged || semantic_state.is_some() || payload.len() != ROUTE_CACHEINFO_LEN {
        return Err(malformed_readback());
    }
    let expires = read_i32_ne(payload, 8).map_err(|_| malformed_readback())?;
    let error = read_i32_ne(payload, 12).map_err(|_| malformed_readback())?;
    *semantic_state = Some(expires != 0 || error != 0);
    Ok(())
}

fn set_once_ip(
    slot: &mut Option<IpAddr>,
    family: u8,
    payload: &[u8],
    flagged: bool,
) -> Result<(), RouteSteeringError> {
    if flagged || slot.is_some() {
        return Err(malformed_readback());
    }
    let address = match family {
        AF_INET if payload.len() == 4 => IpAddr::V4(std::net::Ipv4Addr::new(
            payload[0], payload[1], payload[2], payload[3],
        )),
        AF_INET6 if payload.len() == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(payload);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => return Err(malformed_readback()),
    };
    *slot = Some(address);
    Ok(())
}

fn unspecified_address(family: u8) -> IpAddr {
    if family == AF_INET6 {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    }
}

fn malformed_readback() -> RouteSteeringError {
    RouteSteeringError::indeterminate(ReadbackIndeterminateReason::MalformedReply)
}

fn rule_protocol_create_rejected(error: &RouteSteeringError) -> bool {
    matches!(error, RouteSteeringError::UnsupportedPlatform) || error.raw_os_error() == Some(EINVAL)
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
    if matches!(errno, EPROTONOSUPPORT | EOPNOTSUPP | EAFNOSUPPORT) {
        return Err(RouteSteeringError::UnsupportedPlatform);
    }
    let io_error = io::Error::from_raw_os_error(errno);
    match io_error.kind() {
        io::ErrorKind::AlreadyExists => Err(RouteSteeringError::AlreadyExists),
        io::ErrorKind::NotFound => Err(RouteSteeringError::NotFound),
        _ => Err(RouteSteeringError::io("netlink_ack", io_error)),
    }
}

fn rule_family(request: &RuleRequest) -> Result<u8, RouteSteeringError> {
    if let Some(source) = request.source {
        return Ok(encode_family(source.address));
    }
    if let Some(destination) = request.destination {
        return Ok(encode_family(destination.address));
    }
    // `fib_rules` rejects AF_UNSPEC for a mark-only create. Preserve the
    // existing request shape by applying the same IPv4 default as `ip rule`.
    Ok(AF_INET)
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

fn linux_rule_protocol_capability_from_osrelease() -> LinuxRuleProtocolCapability {
    let file = match std::fs::File::open("/proc/sys/kernel/osrelease") {
        Ok(file) => file,
        Err(_) => return LinuxRuleProtocolCapability::Unknown,
    };
    let mut bytes = Vec::with_capacity(64);
    let limit = match u64::try_from(MAX_KERNEL_RELEASE_LEN) {
        Ok(limit) => limit.saturating_add(1),
        Err(_) => return LinuxRuleProtocolCapability::Unknown,
    };
    if file.take(limit).read_to_end(&mut bytes).is_err() || bytes.len() > MAX_KERNEL_RELEASE_LEN {
        return LinuxRuleProtocolCapability::Unknown;
    }
    let Ok(release) = std::str::from_utf8(&bytes) else {
        return LinuxRuleProtocolCapability::Unknown;
    };
    classify_linux_rule_protocol_release(release)
}

fn classify_linux_rule_protocol_release(release: &str) -> LinuxRuleProtocolCapability {
    let release = release.trim();
    let mut components = release.split('.');
    let Some(major) = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return LinuxRuleProtocolCapability::Unknown;
    };
    let Some(minor_text) = components.next() else {
        return LinuxRuleProtocolCapability::Unknown;
    };
    let minor_digits = minor_text.bytes().take_while(u8::is_ascii_digit).count();
    let Some(minor) = minor_text
        .get(..minor_digits)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return LinuxRuleProtocolCapability::Unknown;
    };

    if major > 4 || (major == 4 && minor >= 17) {
        return LinuxRuleProtocolCapability::ExpectedByKernelVersion;
    }

    // A suffix identifies a vendor/custom build which may have backported the
    // attribute. Version text alone cannot safely call that kernel unsupported.
    if release
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        LinuxRuleProtocolCapability::UnsupportedByKernelVersion
    } else {
        LinuxRuleProtocolCapability::Unknown
    }
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

fn read_i32_ne(bytes: &[u8], offset: usize) -> Result<i32, RouteSteeringError> {
    let end = offset.checked_add(4).ok_or_else(|| {
        RouteSteeringError::io("netlink_receive", invalid_data("offset overflow"))
    })?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        RouteSteeringError::io("netlink_receive", invalid_data("short netlink field"))
    })?;
    Ok(i32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::{mpsc, Arc, Mutex};

    use super::*;

    #[derive(Debug, Default, Clone)]
    struct CapturingTransport {
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        response: Option<Vec<u8>>,
        transaction_error: Option<RouteSteeringError>,
        dump_bodies: Option<Vec<Vec<u8>>>,
        dump_error: Option<RouteSteeringError>,
        probe: RouteSteeringProbe,
        rule_protocol_capability: LinuxRuleProtocolCapability,
    }

    impl CapturingTransport {
        fn requests(&self) -> Vec<Vec<u8>> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn with_dump_bodies(dump_bodies: Vec<Vec<u8>>) -> Self {
            Self {
                dump_bodies: Some(dump_bodies),
                ..Self::default()
            }
        }

        fn with_dump_error(error: RouteSteeringError) -> Self {
            Self {
                dump_error: Some(error),
                ..Self::default()
            }
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
            if let Some(error) = &self.transaction_error {
                return Err(error.clone());
            }
            Ok(self.response.clone())
        }

        fn dump(
            &self,
            _operation: &'static str,
            request: &[u8],
            _expected_sequence: u32,
            _expected_message_type: u16,
            _config: LinuxRouteSteeringBackendConfig,
            _limits: LinuxRouteReadbackLimits,
        ) -> Result<Vec<Vec<u8>>, RouteSteeringError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request.to_vec());
            if let Some(error) = &self.dump_error {
                return Err(error.clone());
            }
            self.dump_bodies.clone().ok_or_else(|| {
                RouteSteeringError::indeterminate(ReadbackIndeterminateReason::Unsupported)
            })
        }

        fn probe(&self, _config: LinuxRouteSteeringBackendConfig) -> RouteSteeringProbe {
            self.probe
        }

        fn rule_protocol_capability(&self) -> LinuxRuleProtocolCapability {
            self.rule_protocol_capability
        }
    }

    #[derive(Debug)]
    enum ScriptedResponse {
        Transaction(Result<Option<Vec<u8>>, RouteSteeringError>),
        Dump(Result<Vec<Vec<u8>>, RouteSteeringError>),
    }

    #[derive(Debug, Clone)]
    struct ScriptedTransport {
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        responses: Arc<Mutex<VecDeque<ScriptedResponse>>>,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<ScriptedResponse>) -> Self {
            Self {
                requests: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(responses.into())),
            }
        }

        fn requests(&self) -> Vec<Vec<u8>> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn next(&self) -> Result<ScriptedResponse, RouteSteeringError> {
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .ok_or_else(malformed_readback)
        }
    }

    impl LinuxRouteTransport for ScriptedTransport {
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
            match self.next()? {
                ScriptedResponse::Transaction(result) => result,
                ScriptedResponse::Dump(_) => Err(malformed_readback()),
            }
        }

        fn dump(
            &self,
            _operation: &'static str,
            request: &[u8],
            _expected_sequence: u32,
            _expected_message_type: u16,
            _config: LinuxRouteSteeringBackendConfig,
            _limits: LinuxRouteReadbackLimits,
        ) -> Result<Vec<Vec<u8>>, RouteSteeringError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request.to_vec());
            match self.next()? {
                ScriptedResponse::Dump(result) => result,
                ScriptedResponse::Transaction(_) => Err(malformed_readback()),
            }
        }

        fn probe(&self, _config: LinuxRouteSteeringBackendConfig) -> RouteSteeringProbe {
            RouteSteeringProbe::default()
        }
    }

    #[derive(Debug, Clone)]
    struct CancellationTransport {
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        rule_started: mpsc::Sender<()>,
        release_rule: Arc<Mutex<mpsc::Receiver<()>>>,
        route_present: Arc<AtomicBool>,
    }

    impl CancellationTransport {
        fn requests(&self) -> Vec<Vec<u8>> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl LinuxRouteTransport for CancellationTransport {
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
            let message_type = read_u16_ne(request, 4)?;
            if message_type == RTM_NEWRULE {
                self.rule_started.send(()).map_err(|_| {
                    RouteSteeringError::io(
                        "test_rule_started",
                        io::Error::new(io::ErrorKind::BrokenPipe, "test receiver closed"),
                    )
                })?;
                self.release_rule
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .recv()
                    .map_err(|_| {
                        RouteSteeringError::io(
                            "test_rule_release",
                            io::Error::new(io::ErrorKind::BrokenPipe, "test sender closed"),
                        )
                    })?;
                return Err(RouteSteeringError::io(
                    "install_rule",
                    io::Error::new(io::ErrorKind::PermissionDenied, "synthetic failure"),
                ));
            }
            if message_type == RTM_NEWROUTE {
                self.route_present.store(true, AtomicOrdering::Release);
            } else if message_type == RTM_DELROUTE {
                self.route_present.store(false, AtomicOrdering::Release);
            }
            Ok(None)
        }

        fn dump(
            &self,
            _operation: &'static str,
            request: &[u8],
            _expected_sequence: u32,
            expected_message_type: u16,
            _config: LinuxRouteSteeringBackendConfig,
            _limits: LinuxRouteReadbackLimits,
        ) -> Result<Vec<Vec<u8>>, RouteSteeringError> {
            self.requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(request.to_vec());
            match expected_message_type {
                RTM_NEWROUTE => {
                    if self.route_present.load(AtomicOrdering::Acquire) {
                        Ok(vec![encode_route_request(&route())?])
                    } else {
                        Ok(Vec::new())
                    }
                }
                RTM_NEWRULE => Ok(Vec::new()),
                _ => Err(malformed_readback()),
            }
        }

        fn probe(&self, _config: LinuxRouteSteeringBackendConfig) -> RouteSteeringProbe {
            RouteSteeringProbe::default()
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

    fn noncanonical_routes() -> [(RouteRequest, IpPrefix); 2] {
        [
            (
                RouteRequest {
                    destination: prefix([192, 0, 2, 129], 24),
                    oif_ifindex: 42,
                    table: 1000,
                    priority: Some(10),
                },
                prefix([192, 0, 2, 0], 24),
            ),
            (
                RouteRequest {
                    destination: IpPrefix::new(
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 3, 4, 5, 6)),
                        64,
                    ),
                    oif_ifindex: 42,
                    table: 1000,
                    priority: Some(10),
                },
                IpPrefix::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 0, 0, 0, 0)),
                    64,
                ),
            ),
        ]
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

    fn ipv6_rule() -> RuleRequest {
        RuleRequest {
            source: Some(IpPrefix::new(
                IpAddr::V6("2001:db8:1::".parse().unwrap()),
                64,
            )),
            destination: Some(IpPrefix::new(
                IpAddr::V6("2001:db8:2::".parse().unwrap()),
                64,
            )),
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

    fn set_attr_u8(body: &mut [u8], mut offset: usize, attr_type: u16, value: u8) {
        while offset + ROUTE_ATTRIBUTE_HEADER_LEN <= body.len() {
            let len = usize::from(u16::from_ne_bytes([body[offset], body[offset + 1]]));
            let found_type = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]);
            assert!(len >= ROUTE_ATTRIBUTE_HEADER_LEN && offset + len <= body.len());
            if found_type == attr_type {
                assert_eq!(len, ROUTE_ATTRIBUTE_HEADER_LEN + 1);
                body[offset + ROUTE_ATTRIBUTE_HEADER_LEN] = value;
                return;
            }
            offset += align_to_netlink(len).unwrap();
        }
        panic!("attribute not found");
    }

    fn remove_attr(body: &mut Vec<u8>, mut offset: usize, attr_type: u16) {
        while offset + ROUTE_ATTRIBUTE_HEADER_LEN <= body.len() {
            let len = usize::from(u16::from_ne_bytes([body[offset], body[offset + 1]]));
            let found_type = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]);
            assert!(len >= ROUTE_ATTRIBUTE_HEADER_LEN && offset + len <= body.len());
            let aligned = align_to_netlink(len).unwrap();
            if found_type == attr_type {
                body.drain(offset..offset + aligned);
                return;
            }
            offset += aligned;
        }
        panic!("attribute not found");
    }

    #[test]
    fn encodes_route_with_table_oif_metric_and_destination() {
        let body = encode_route_request(&route()).unwrap();

        assert_eq!(body[0], AF_INET);
        assert_eq!(body[1], 24);
        assert_eq!(body[4], RT_TABLE_UNSPEC);
        assert_eq!(body[5], LINUX_ROUTE_STEERING_PROTOCOL);
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
        assert_eq!(
            attr_payload(&body, FIB_RULE_HEADER_LEN, FRA_PROTOCOL),
            Some(&[LINUX_ROUTE_STEERING_PROTOCOL][..])
        );
        assert_eq!(attr_u32(&body, FIB_RULE_HEADER_LEN, FRA_PRIORITY), 100);
        assert_eq!(attr_u32(&body, FIB_RULE_HEADER_LEN, FRA_TABLE), 1000);

        let mark_only = RuleRequest {
            source: None,
            destination: None,
            fwmark: rule().fwmark,
            table: rule().table,
            priority: rule().priority,
        };
        assert_eq!(encode_rule_request(&mark_only).unwrap()[0], AF_INET);
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
        assert_eq!(attr_u32(&body, ROUTE_MESSAGE_LEN, RTA_PRIORITY), 1024);
    }

    #[test]
    fn route_priority_encoding_matches_family_specific_kernel_canonicalization() {
        for priority in [None, Some(0)] {
            let mut ipv4 = route();
            ipv4.priority = priority;
            let body = encode_route_request(&ipv4).unwrap();
            assert!(attr_payload(&body, ROUTE_MESSAGE_LEN, RTA_PRIORITY).is_none());

            let ipv6 = RouteRequest {
                destination: IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
                oif_ifindex: 7,
                table: 100,
                priority,
            };
            let body = encode_route_request(&ipv6).unwrap();
            assert_eq!(attr_u32(&body, ROUTE_MESSAGE_LEN, RTA_PRIORITY), 1024);
        }

        let mut ipv4 = route();
        ipv4.priority = Some(77);
        assert_eq!(
            attr_u32(
                &encode_route_request(&ipv4).unwrap(),
                ROUTE_MESSAGE_LEN,
                RTA_PRIORITY
            ),
            77
        );
    }

    #[test]
    fn owned_route_encoding_and_readback_use_effective_network_destination() {
        for (request, canonical_destination) in noncanonical_routes() {
            let body = encode_route_request(&request).unwrap();
            let expected = match canonical_destination.address {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            };
            assert_eq!(
                attr_payload(&body, ROUTE_MESSAGE_LEN, RTA_DST),
                Some(expected.as_slice())
            );
            assert_eq!(
                classify_route_readback(&request, std::slice::from_ref(&body)).unwrap(),
                RouteReadback::ExactPresent
            );
        }
    }

    #[tokio::test]
    async fn noncanonical_owned_routes_converge_and_remove_without_rollback() {
        for (request, canonical_destination) in noncanonical_routes() {
            let resident = encode_route_request(&request).unwrap();
            let transport = ScriptedTransport::new(vec![
                ScriptedResponse::Dump(Ok(Vec::new())),
                ScriptedResponse::Transaction(Ok(None)),
                ScriptedResponse::Dump(Ok(vec![resident.clone()])),
                ScriptedResponse::Dump(Ok(vec![resident])),
                ScriptedResponse::Transaction(Ok(None)),
                ScriptedResponse::Dump(Ok(Vec::new())),
            ]);
            let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());

            assert_eq!(
                backend.converge_route(request.clone()).await.unwrap(),
                RouteConvergenceOutcome::Installed
            );
            backend.remove_converged_route(request).await.unwrap();

            let messages = transport.requests();
            let message_types = messages
                .iter()
                .map(|message| u16::from_ne_bytes([message[4], message[5]]))
                .collect::<Vec<_>>();
            assert_eq!(
                message_types,
                vec![
                    RTM_GETROUTE,
                    RTM_NEWROUTE,
                    RTM_GETROUTE,
                    RTM_GETROUTE,
                    RTM_DELROUTE,
                    RTM_GETROUTE,
                ]
            );
            let expected = match canonical_destination.address {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            };
            for message in messages.iter().filter(|message| {
                matches!(
                    u16::from_ne_bytes([message[4], message[5]]),
                    RTM_NEWROUTE | RTM_DELROUTE
                )
            }) {
                assert_eq!(
                    attr_payload(netlink_body(message), ROUTE_MESSAGE_LEN, RTA_DST),
                    Some(expected.as_slice())
                );
            }
        }
    }

    #[tokio::test]
    async fn legacy_route_mutations_preserve_caller_priority_encoding() {
        let cases = [
            RouteRequest {
                destination: prefix([192, 0, 2, 0], 24),
                oif_ifindex: 7,
                table: 100,
                priority: Some(0),
            },
            RouteRequest {
                destination: IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
                oif_ifindex: 7,
                table: 100,
                priority: None,
            },
            RouteRequest {
                destination: IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
                oif_ifindex: 7,
                table: 100,
                priority: Some(0),
            },
        ];

        for request in cases {
            let expected_priority = request.priority;
            let transport = CapturingTransport::default();
            let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
            backend.install_route(request.clone()).await.unwrap();
            backend.remove_route(request).await.unwrap();

            let messages = transport.requests();
            assert_eq!(messages.len(), 2);
            for (message, expected_type) in messages.iter().zip([RTM_NEWROUTE, RTM_DELROUTE]) {
                assert_eq!(u16::from_ne_bytes([message[4], message[5]]), expected_type);
                let body = netlink_body(message);
                assert_eq!(body[5], RTPROT_STATIC);
                match expected_priority {
                    Some(priority) => {
                        assert_eq!(attr_u32(body, ROUTE_MESSAGE_LEN, RTA_PRIORITY), priority);
                    }
                    None => assert!(attr_payload(body, ROUTE_MESSAGE_LEN, RTA_PRIORITY).is_none()),
                }
            }
        }
    }

    #[tokio::test]
    async fn legacy_route_mutations_preserve_caller_destination_encoding() {
        for (request, _) in noncanonical_routes() {
            let expected = match request.destination.address {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            };
            let transport = CapturingTransport::default();
            let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
            backend.install_route(request.clone()).await.unwrap();
            backend.remove_route(request).await.unwrap();

            let messages = transport.requests();
            assert_eq!(messages.len(), 2);
            for (message, expected_type) in messages.iter().zip([RTM_NEWROUTE, RTM_DELROUTE]) {
                assert_eq!(u16::from_ne_bytes([message[4], message[5]]), expected_type);
                let body = netlink_body(message);
                assert_eq!(body[5], RTPROT_STATIC);
                assert_eq!(
                    attr_payload(body, ROUTE_MESSAGE_LEN, RTA_DST),
                    Some(expected.as_slice())
                );
            }
        }
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

        let mut zero_mark = rule();
        zero_mark.fwmark = Some(FirewallMark {
            value: 0,
            mask: u32::MAX,
        });
        assert!(matches!(
            encode_rule_request(&zero_mark),
            Err(RouteSteeringError::InvalidConfig {
                field: "rule.fwmark.value",
                ..
            })
        ));

        for (source, destination, field) in [
            (Some(prefix([0, 0, 0, 0], 0)), None, "rule.source"),
            (None, Some(prefix([0, 0, 0, 0], 0)), "rule.destination"),
        ] {
            let mut zero_selector = rule();
            zero_selector.source = source;
            zero_selector.destination = destination;
            assert!(matches!(
                encode_rule_request(&zero_selector),
                Err(RouteSteeringError::InvalidConfig {
                    field: actual,
                    ..
                }) if actual == field
            ));
        }
    }

    #[test]
    fn legacy_rule_encoding_preserves_zero_mark_and_ipv4_ipv6_default_selectors() {
        for (source, expected_family, expected_address) in [
            (
                IpPrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                AF_INET,
                Ipv4Addr::UNSPECIFIED.octets().to_vec(),
            ),
            (
                IpPrefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                AF_INET6,
                Ipv6Addr::UNSPECIFIED.octets().to_vec(),
            ),
        ] {
            let request = RuleRequest {
                source: Some(source),
                destination: None,
                fwmark: Some(FirewallMark {
                    value: 0,
                    mask: 0xff,
                }),
                table: 1000,
                priority: 100,
            };
            let body = encode_legacy_rule_request(&request).unwrap();
            assert_eq!(body[0], expected_family);
            assert_eq!(body[2], 0);
            assert_eq!(
                attr_payload(&body, FIB_RULE_HEADER_LEN, FRA_SRC),
                Some(expected_address.as_slice())
            );
            assert_eq!(attr_u32(&body, FIB_RULE_HEADER_LEN, FRA_FWMARK), 0);
            assert_eq!(attr_u32(&body, FIB_RULE_HEADER_LEN, FRA_FWMASK), 0xff);
            assert!(attr_payload(&body, FIB_RULE_HEADER_LEN, FRA_PROTOCOL).is_none());

            let conflict = match classify_rule_readback(&request, &[body]).unwrap() {
                RuleReadback::Conflict(conflict) => conflict,
                other => panic!("unexpected legacy readback: {other:?}"),
            };
            assert_eq!(conflict.resident(), &request);
            assert_eq!(
                conflict.mismatch(),
                RuleMismatch {
                    kernel_semantics: true,
                    ..RuleMismatch::default()
                }
            );
        }

        let default_route = RouteRequest {
            destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            oif_ifindex: 42,
            table: 1000,
            priority: None,
        };
        let body = encode_legacy_route_request(&default_route).unwrap();
        assert_eq!(body[1], 0);
        assert_eq!(body[5], RTPROT_STATIC);
    }

    #[tokio::test]
    async fn owned_rule_wildcards_fail_before_netlink_mutation() {
        for request in [
            RuleRequest {
                source: Some(IpPrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
                destination: None,
                fwmark: Some(FirewallMark {
                    value: 1,
                    mask: 0xff,
                }),
                table: 1000,
                priority: 100,
            },
            RuleRequest {
                source: Some(prefix([192, 0, 2, 0], 24)),
                destination: None,
                fwmark: Some(FirewallMark {
                    value: 0,
                    mask: 0xff,
                }),
                table: 1000,
                priority: 100,
            },
        ] {
            let transport = CapturingTransport::default();
            let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
            assert!(matches!(
                backend.converge_rule(request.clone()).await,
                Err(RouteSteeringError::InvalidConfig { .. })
            ));
            assert!(matches!(
                backend.remove_converged_rule(request).await,
                Err(RouteSteeringError::InvalidConfig { .. })
            ));
            assert!(transport.requests().is_empty());
        }
    }

    #[tokio::test]
    async fn pre_upgrade_static_route_is_foreign_and_never_adopted_by_convergence() {
        let legacy = encode_legacy_route_request(&route()).unwrap();
        let transport = CapturingTransport::with_dump_bodies(vec![legacy]);
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());

        let conflict = match backend.read_route(&route()).await.unwrap() {
            RouteReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected static-route readback: {other:?}"),
        };
        assert!(conflict.mismatch().kernel_semantics);
        assert!(matches!(
            backend.converge_route(route()).await.unwrap(),
            RouteConvergenceOutcome::Conflict(_)
        ));
        assert!(matches!(
            backend.remove_converged_route(route()).await,
            Err(RouteSteeringError::AlreadyExists)
        ));
        assert!(transport
            .requests()
            .iter()
            .all(|request| { u16::from_ne_bytes([request[4], request[5]]) == RTM_GETROUTE }));

        let legacy_cleanup_transport = CapturingTransport::default();
        let backend = LinuxRouteSteeringBackend::with_transport(legacy_cleanup_transport.clone());
        backend.remove_route(route()).await.unwrap();
        let requests = legacy_cleanup_transport.requests();
        assert_eq!(
            u16::from_ne_bytes([requests[0][4], requests[0][5]]),
            RTM_DELROUTE
        );
        assert_eq!(netlink_body(&requests[0])[5], RTPROT_STATIC);
    }

    #[test]
    fn kernel_release_capability_is_versioned_without_guessing_backports() {
        assert_eq!(
            classify_linux_rule_protocol_release("4.16.18"),
            LinuxRuleProtocolCapability::UnsupportedByKernelVersion
        );
        assert_eq!(
            classify_linux_rule_protocol_release("4.16.18-vendor.1"),
            LinuxRuleProtocolCapability::Unknown
        );
        assert_eq!(
            classify_linux_rule_protocol_release("4.17.0"),
            LinuxRuleProtocolCapability::ExpectedByKernelVersion
        );
        assert_eq!(
            classify_linux_rule_protocol_release("6.8.12-custom"),
            LinuxRuleProtocolCapability::ExpectedByKernelVersion
        );
        assert_eq!(
            classify_linux_rule_protocol_release("not-a-version"),
            LinuxRuleProtocolCapability::Unknown
        );
    }

    #[tokio::test]
    async fn known_unsupported_rule_protocol_fails_before_any_mutation() {
        let transport = CapturingTransport {
            rule_protocol_capability: LinuxRuleProtocolCapability::UnsupportedByKernelVersion,
            ..CapturingTransport::default()
        };
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
        assert_eq!(
            backend.converge_rule(rule()).await.unwrap(),
            RuleConvergenceOutcome::Indeterminate(
                ReadbackIndeterminateReason::OwnershipMarkerUnsupported
            )
        );
        let pair = backend
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap();
        assert_eq!(pair.route, RouteConvergenceOutcome::NotAttempted);
        assert_eq!(
            pair.rule,
            RuleConvergenceOutcome::Indeterminate(
                ReadbackIndeterminateReason::OwnershipMarkerUnsupported
            )
        );
        assert!(transport.requests().is_empty());
        let capabilities = backend.capabilities().await;
        assert!(capabilities.legacy_mutation);
        assert!(capabilities.conflict_safe_route_convergence);
        assert!(!capabilities.conflict_safe_rule_convergence);
        assert!(!capabilities.paired_convergence);
    }

    #[tokio::test]
    async fn legacy_probe_readiness_is_independent_from_rule_convergence_capability() {
        let probe = RouteSteeringProbe {
            kind: RouteSteeringBackendKind::LinuxKernel,
            platform_supported: true,
            kernel_reachable: true,
            net_admin_capable: true,
            mutation_ready: true,
            details: Some("linux route netlink mutation ready"),
        };
        let transport = CapturingTransport {
            probe,
            rule_protocol_capability: LinuxRuleProtocolCapability::UnsupportedByKernelVersion,
            ..CapturingTransport::default()
        };
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());

        assert_eq!(backend.probe().await.unwrap(), probe);
        let capabilities = backend.capabilities().await;
        assert!(capabilities.legacy_mutation);
        assert!(capabilities.conflict_safe_route_convergence);
        assert!(!capabilities.conflict_safe_rule_convergence);
        assert!(!capabilities.paired_convergence);
        assert!(transport.requests().is_empty());
    }

    #[tokio::test]
    async fn kernel_rejection_becomes_cached_typed_rule_protocol_evidence() {
        for rejection in [
            RouteSteeringError::io("netlink_ack", io::Error::from_raw_os_error(EINVAL)),
            RouteSteeringError::UnsupportedPlatform,
        ] {
            let transport = ScriptedTransport::new(vec![
                ScriptedResponse::Dump(Ok(Vec::new())),
                ScriptedResponse::Transaction(Err(rejection)),
            ]);
            let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
            assert_eq!(
                backend.converge_rule(rule()).await.unwrap(),
                RuleConvergenceOutcome::Indeterminate(
                    ReadbackIndeterminateReason::OwnershipMarkerUnsupported
                )
            );
            assert_eq!(
                backend.rule_protocol_capability(),
                LinuxRuleProtocolCapability::UnsupportedByKernelRejection
            );
            assert_eq!(
                transport
                    .requests()
                    .iter()
                    .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                    .collect::<Vec<_>>(),
                vec![RTM_GETRULE, RTM_NEWRULE]
            );
            let request_count = transport.requests().len();
            assert_eq!(
                backend.converge_rule(rule()).await.unwrap(),
                RuleConvergenceOutcome::Indeterminate(
                    ReadbackIndeterminateReason::OwnershipMarkerUnsupported
                )
            );
            assert_eq!(transport.requests().len(), request_count);
        }
    }

    #[tokio::test]
    async fn confirmed_rule_protocol_evidence_survives_generic_ipv4_create_failures() {
        for rejection in [
            RouteSteeringError::io("netlink_ack", io::Error::from_raw_os_error(EINVAL)),
            RouteSteeringError::UnsupportedPlatform,
        ] {
            let expected_class = rejection.class();
            let expected_raw_os_error = rejection.raw_os_error();
            let mut failed = rule();
            failed.priority += 1;
            let mut retried = rule();
            retried.priority += 2;
            let transport = ScriptedTransport::new(vec![
                ScriptedResponse::Dump(Ok(vec![encode_rule_request(&rule()).unwrap()])),
                ScriptedResponse::Dump(Ok(Vec::new())),
                ScriptedResponse::Transaction(Err(rejection.clone())),
                ScriptedResponse::Dump(Ok(Vec::new())),
                ScriptedResponse::Transaction(Err(rejection)),
            ]);
            let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());

            assert_eq!(
                backend.converge_rule(rule()).await.unwrap(),
                RuleConvergenceOutcome::ExactAlreadyPresent
            );
            assert_eq!(
                backend.rule_protocol_capability(),
                LinuxRuleProtocolCapability::Confirmed
            );

            let error = backend.converge_rule(failed).await.unwrap_err();
            assert_eq!(error.class(), expected_class);
            assert_eq!(error.raw_os_error(), expected_raw_os_error);
            assert_eq!(
                backend.rule_protocol_capability(),
                LinuxRuleProtocolCapability::Confirmed
            );

            let retry_error = backend.converge_rule(retried).await.unwrap_err();
            assert_eq!(retry_error.class(), expected_class);
            assert_eq!(retry_error.raw_os_error(), expected_raw_os_error);
            assert_eq!(
                backend.rule_protocol_capability(),
                LinuxRuleProtocolCapability::Confirmed
            );
            assert_eq!(
                transport
                    .requests()
                    .iter()
                    .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                    .collect::<Vec<_>>(),
                vec![
                    RTM_GETRULE,
                    RTM_GETRULE,
                    RTM_NEWRULE,
                    RTM_GETRULE,
                    RTM_NEWRULE,
                ]
            );
        }
    }

    #[tokio::test]
    async fn non_ipv4_create_failures_preserve_error_and_do_not_poison_capability() {
        for rejection in [
            RouteSteeringError::io("netlink_ack", io::Error::from_raw_os_error(EAFNOSUPPORT)),
            RouteSteeringError::UnsupportedPlatform,
        ] {
            let expected_class = rejection.class();
            let expected_raw_os_error = rejection.raw_os_error();
            let transport = ScriptedTransport::new(vec![
                ScriptedResponse::Dump(Ok(Vec::new())),
                ScriptedResponse::Transaction(Err(rejection.clone())),
                ScriptedResponse::Dump(Ok(Vec::new())),
                ScriptedResponse::Transaction(Err(rejection)),
            ]);
            let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());

            for _ in 0..2 {
                let error = backend.converge_rule(ipv6_rule()).await.unwrap_err();
                assert_eq!(error.class(), expected_class);
                assert_eq!(error.raw_os_error(), expected_raw_os_error);
                assert_eq!(
                    backend.rule_protocol_capability(),
                    LinuxRuleProtocolCapability::Unknown
                );
            }
            assert_eq!(
                transport
                    .requests()
                    .iter()
                    .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                    .collect::<Vec<_>>(),
                vec![RTM_GETRULE, RTM_NEWRULE, RTM_GETRULE, RTM_NEWRULE]
            );
        }
    }

    #[tokio::test]
    async fn silently_ignored_rule_protocol_is_rolled_back_and_cached_unsupported() {
        let mut untagged = encode_rule_request(&rule()).unwrap();
        remove_attr(&mut untagged, FIB_RULE_HEADER_LEN, FRA_PROTOCOL);
        let transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(vec![untagged])),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(Vec::new())),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
        assert!(matches!(
            backend.converge_rule(rule()).await.unwrap(),
            RuleConvergenceOutcome::ConflictAfterOwnedRollback(_)
        ));
        assert_eq!(
            backend.rule_protocol_capability(),
            LinuxRuleProtocolCapability::UnsupportedByReadback
        );
        assert_eq!(
            transport
                .requests()
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![
                RTM_GETRULE,
                RTM_NEWRULE,
                RTM_GETRULE,
                RTM_DELRULE,
                RTM_GETRULE
            ]
        );
        let requests = transport.requests();
        assert!(attr_payload(
            netlink_body(&requests[3]),
            FIB_RULE_HEADER_LEN,
            FRA_PROTOCOL
        )
        .is_none());

        let request_count = transport.requests().len();
        assert_eq!(
            backend.converge_rule(rule()).await.unwrap(),
            RuleConvergenceOutcome::Indeterminate(
                ReadbackIndeterminateReason::OwnershipMarkerUnsupported
            )
        );
        assert_eq!(transport.requests().len(), request_count);
    }

    #[tokio::test]
    async fn indeterminate_post_create_readback_still_rolls_back_attempt_owned_rule() {
        let transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Err(RouteSteeringError::indeterminate(
                ReadbackIndeterminateReason::IncompleteReply,
            ))),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(Vec::new())),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
        assert_eq!(
            backend.converge_rule(rule()).await.unwrap(),
            RuleConvergenceOutcome::IndeterminateAfterOwnedRollback(
                ReadbackIndeterminateReason::IncompleteReply
            )
        );
        assert!(transport
            .requests()
            .iter()
            .any(|request| u16::from_ne_bytes([request[4], request[5]]) == RTM_DELRULE));
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
        assert!(matches!(
            parse_netlink_response(&netlink_error(10, EOPNOTSUPP), 10).unwrap_err(),
            RouteSteeringError::UnsupportedPlatform
        ));
        assert!(matches!(
            parse_netlink_response(&netlink_error(11, EAFNOSUPPORT), 11).unwrap_err(),
            RouteSteeringError::UnsupportedPlatform
        ));
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
        assert_eq!(netlink_body(&requests[0])[5], RTPROT_STATIC);
        assert!(attr_payload(
            netlink_body(&requests[1]),
            FIB_RULE_HEADER_LEN,
            FRA_PROTOCOL
        )
        .is_none());
    }

    #[tokio::test]
    async fn linux_backend_sends_remove_messages() {
        let transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(vec![encode_route_request(&route()).unwrap()])),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Dump(Ok(vec![encode_rule_request(&rule()).unwrap()])),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(Vec::new())),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());

        backend.remove_converged_route(route()).await.unwrap();
        backend.remove_converged_rule(rule()).await.unwrap();

        let requests = transport.requests();
        assert_eq!(
            requests
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![
                RTM_GETROUTE,
                RTM_DELROUTE,
                RTM_GETROUTE,
                RTM_GETRULE,
                RTM_DELRULE,
                RTM_GETRULE,
            ]
        );
    }

    #[tokio::test]
    async fn exact_removal_refuses_multiplicity_and_foreign_ownership() {
        let mut other_route = route();
        other_route.priority = Some(11);
        let route_transport = CapturingTransport::with_dump_bodies(vec![
            encode_route_request(&route()).unwrap(),
            encode_route_request(&other_route).unwrap(),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(route_transport.clone());
        assert!(matches!(
            backend.remove_converged_route(route()).await,
            Err(RouteSteeringError::AlreadyExists)
        ));
        assert_eq!(
            route_transport
                .requests()
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![RTM_GETROUTE]
        );

        let mut foreign_rule = encode_rule_request(&rule()).unwrap();
        set_attr_u8(&mut foreign_rule, FIB_RULE_HEADER_LEN, FRA_PROTOCOL, 99);
        let rule_transport = CapturingTransport::with_dump_bodies(vec![foreign_rule]);
        let backend = LinuxRouteSteeringBackend::with_transport(rule_transport.clone());
        assert!(matches!(
            backend.remove_converged_rule(rule()).await,
            Err(RouteSteeringError::AlreadyExists)
        ));
        assert_eq!(
            rule_transport
                .requests()
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![RTM_GETRULE]
        );
    }

    #[tokio::test]
    async fn external_post_delete_state_is_reported_as_indeterminate_residual() {
        let mut foreign = encode_route_request(&route()).unwrap();
        foreign[5] = 99;
        let transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(vec![encode_route_request(&route()).unwrap()])),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(vec![foreign])),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
        assert!(matches!(
            backend.remove_converged_route(route()).await,
            Err(RouteSteeringError::ReadbackIndeterminate {
                reason: ReadbackIndeterminateReason::ConcurrentModification,
            })
        ));
        assert_eq!(
            transport
                .requests()
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![RTM_GETROUTE, RTM_DELROUTE, RTM_GETROUTE]
        );
    }

    #[tokio::test]
    async fn post_install_multiplicity_uses_only_attempt_owned_rollback() {
        let mut other_route = route();
        other_route.priority = Some(11);
        let route_candidates = vec![
            encode_route_request(&route()).unwrap(),
            encode_route_request(&other_route).unwrap(),
        ];
        let route_transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(route_candidates.clone())),
            ScriptedResponse::Dump(Ok(route_candidates)),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(route_transport.clone());
        assert!(matches!(
            backend.converge_route(route()).await,
            Err(RouteSteeringError::RollbackFailed {
                primary: RouteSteeringFailureClass::AlreadyExists,
                rollback: RouteSteeringFailureClass::AlreadyExists,
            })
        ));
        assert!(!route_transport
            .requests()
            .iter()
            .any(|request| { u16::from_ne_bytes([request[4], request[5]]) == RTM_DELROUTE }));

        let mut other_rule = rule();
        other_rule.table += 1;
        let rule_candidates = vec![
            encode_rule_request(&rule()).unwrap(),
            encode_rule_request(&other_rule).unwrap(),
        ];
        let rule_transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(rule_candidates.clone())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(Vec::new())),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(rule_transport.clone());
        assert!(matches!(
            backend.converge_rule(rule()).await.unwrap(),
            RuleConvergenceOutcome::ConflictAfterOwnedRollback(_)
        ));
        assert!(rule_transport
            .requests()
            .iter()
            .any(|request| { u16::from_ne_bytes([request[4], request[5]]) == RTM_DELRULE }));
    }

    #[test]
    fn route_and_rule_readback_compare_every_modeled_field() {
        assert_eq!(
            classify_route_readback(&route(), &[encode_route_request(&route()).unwrap()]).unwrap(),
            RouteReadback::ExactPresent
        );
        let mut kernel_rule = encode_rule_request(&rule()).unwrap();
        append_attr_u32_ne(&mut kernel_rule, FRA_SUPPRESS_PREFIXLEN, u32::MAX).unwrap();
        assert_eq!(
            classify_rule_readback(&rule(), &[kernel_rule]).unwrap(),
            RuleReadback::ExactPresent
        );

        let mut foreign_rule = encode_rule_request(&rule()).unwrap();
        set_attr_u8(&mut foreign_rule, FIB_RULE_HEADER_LEN, FRA_PROTOCOL, 99);
        assert!(matches!(
            classify_rule_readback(&rule(), &[foreign_rule]).unwrap(),
            RuleReadback::Conflict(_)
        ));

        let mut legacy_rule = encode_rule_request(&rule()).unwrap();
        remove_attr(&mut legacy_rule, FIB_RULE_HEADER_LEN, FRA_PROTOCOL);
        let legacy_conflict = match classify_rule_readback(&rule(), &[legacy_rule]).unwrap() {
            RuleReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected legacy rule readback: {other:?}"),
        };
        assert!(legacy_conflict.mismatch().kernel_semantics);

        let mut conflicting_route = route();
        conflicting_route.oif_ifindex = 99;
        conflicting_route.table = 2000;
        conflicting_route.priority = None;
        let conflict = match classify_route_readback(
            &route(),
            &[encode_route_request(&conflicting_route).unwrap()],
        )
        .unwrap()
        {
            RouteReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected route readback: {other:?}"),
        };
        assert_eq!(
            conflict.mismatch(),
            RouteMismatch {
                output_interface: true,
                table: true,
                priority: true,
                kernel_semantics: false,
            }
        );

        let mut conflicting_rule = rule();
        conflicting_rule.source = None;
        conflicting_rule.destination = Some(prefix([203, 0, 113, 0], 24));
        conflicting_rule.fwmark = None;
        conflicting_rule.table = 2000;
        let conflict = match classify_rule_readback(
            &rule(),
            &[encode_rule_request(&conflicting_rule).unwrap()],
        )
        .unwrap()
        {
            RuleReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected rule readback: {other:?}"),
        };
        assert_eq!(
            conflict.mismatch(),
            RuleMismatch {
                source: true,
                destination: true,
                firewall_mark: true,
                table: true,
                kernel_semantics: false,
            }
        );
    }

    #[test]
    fn readback_preserves_foreign_zero_mark_and_rejects_multiplicity_as_exact() {
        let mut zero_mark = encode_rule_request(&rule()).unwrap();
        remove_attr(&mut zero_mark, FIB_RULE_HEADER_LEN, FRA_FWMARK);
        set_attr_u8(&mut zero_mark, FIB_RULE_HEADER_LEN, FRA_PROTOCOL, 99);
        let parsed = parse_rule_candidate(&zero_mark)
            .unwrap()
            .and_then(|candidate| candidate.resident)
            .unwrap();
        assert_eq!(
            parsed.fwmark,
            Some(FirewallMark {
                value: 0,
                mask: 0xff,
            })
        );
        let conflict = match classify_rule_readback(&rule(), &[zero_mark]).unwrap() {
            RuleReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected readback: {other:?}"),
        };
        assert!(conflict.mismatch().firewall_mark);
        assert!(conflict.mismatch().kernel_semantics);

        let mut conflicting_route = route();
        conflicting_route.priority = Some(11);
        let route_conflict = match classify_route_readback(
            &route(),
            &[
                encode_route_request(&route()).unwrap(),
                encode_route_request(&conflicting_route).unwrap(),
            ],
        )
        .unwrap()
        {
            RouteReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected readback: {other:?}"),
        };
        assert_eq!(route_conflict.candidate_count().get(), 2);
        assert!(!route_conflict.mismatch().kernel_semantics);

        let mut conflicting_rule = rule();
        conflicting_rule.table += 1;
        let rule_conflict = match classify_rule_readback(
            &rule(),
            &[
                encode_rule_request(&rule()).unwrap(),
                encode_rule_request(&conflicting_rule).unwrap(),
            ],
        )
        .unwrap()
        {
            RuleReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected readback: {other:?}"),
        };
        assert_eq!(rule_conflict.candidate_count().get(), 2);
        assert!(!rule_conflict.mismatch().kernel_semantics);
    }

    #[test]
    fn route_readback_uses_family_specific_effective_priorities() {
        let mut ipv4_none = route();
        ipv4_none.priority = None;
        let mut ipv4_zero = ipv4_none.clone();
        ipv4_zero.priority = Some(0);
        assert_eq!(
            classify_route_readback(&ipv4_none, &[encode_route_request(&ipv4_zero).unwrap()])
                .unwrap(),
            RouteReadback::ExactPresent
        );

        let ipv6_none = RouteRequest {
            destination: IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
            oif_ifindex: 7,
            table: 100,
            priority: None,
        };
        let mut ipv6_zero = ipv6_none.clone();
        ipv6_zero.priority = Some(0);
        let kernel = encode_route_request(&ipv6_none).unwrap();
        assert_eq!(
            classify_route_readback(&ipv6_none, std::slice::from_ref(&kernel)).unwrap(),
            RouteReadback::ExactPresent
        );
        assert_eq!(
            classify_route_readback(&ipv6_zero, &[kernel]).unwrap(),
            RouteReadback::ExactPresent
        );
    }

    #[tokio::test]
    async fn linux_readback_encodes_bounded_dump_requests() {
        let transport =
            CapturingTransport::with_dump_bodies(vec![encode_route_request(&route()).unwrap()]);
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
        assert_eq!(
            backend.read_route(&route()).await.unwrap(),
            RouteReadback::ExactPresent
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            u16::from_ne_bytes([requests[0][4], requests[0][5]]),
            RTM_GETROUTE
        );
        assert_eq!(
            u16::from_ne_bytes([requests[0][6], requests[0][7]]),
            NLM_F_REQUEST | NLM_F_DUMP
        );
        assert_eq!(netlink_body(&requests[0])[0], AF_INET);

        let transport =
            CapturingTransport::with_dump_bodies(vec![encode_rule_request(&rule()).unwrap()]);
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
        assert_eq!(
            backend.read_rule(&rule()).await.unwrap(),
            RuleReadback::ExactPresent
        );
        assert_eq!(
            u16::from_ne_bytes([transport.requests()[0][4], transport.requests()[0][5]]),
            RTM_GETRULE
        );
    }

    #[test]
    fn multipart_dump_parser_requires_complete_strict_bounded_replies() {
        let sequence = 77;
        let first = encode_netlink_message(
            RTM_NEWROUTE,
            NLM_F_MULTI,
            sequence,
            &encode_route_request(&route()).unwrap(),
        )
        .unwrap();
        let mut second_route = route();
        second_route.table = 2000;
        let second = encode_netlink_message(
            RTM_NEWROUTE,
            NLM_F_MULTI,
            sequence,
            &encode_route_request(&second_route).unwrap(),
        )
        .unwrap();
        let done = encode_netlink_message(NLMSG_DONE, NLM_F_MULTI, sequence, &[]).unwrap();
        let mut messages = Vec::new();
        assert!(!parse_dump_datagram(&first, sequence, RTM_NEWROUTE, 2, &mut messages).unwrap());
        let mut final_datagram = second.clone();
        final_datagram.extend_from_slice(&done);
        assert!(
            parse_dump_datagram(&final_datagram, sequence, RTM_NEWROUTE, 2, &mut messages).unwrap()
        );
        assert_eq!(messages.len(), 2);

        let mut limited = Vec::new();
        parse_dump_datagram(&first, sequence, RTM_NEWROUTE, 1, &mut limited).unwrap();
        assert!(matches!(
            parse_dump_datagram(&second, sequence, RTM_NEWROUTE, 1, &mut limited),
            Err(RouteSteeringError::ReadbackIndeterminate {
                reason: ReadbackIndeterminateReason::LimitExceeded
            })
        ));

        let mut truncated = first;
        truncated.pop();
        assert!(matches!(
            parse_dump_datagram(&truncated, sequence, RTM_NEWROUTE, 2, &mut Vec::new()),
            Err(RouteSteeringError::ReadbackIndeterminate {
                reason: ReadbackIndeterminateReason::MalformedReply
            })
        ));

        let without_multi = encode_netlink_message(
            RTM_NEWROUTE,
            0,
            sequence,
            &encode_route_request(&route()).unwrap(),
        )
        .unwrap();
        assert!(
            parse_dump_datagram(&without_multi, sequence, RTM_NEWROUTE, 2, &mut Vec::new())
                .is_err()
        );

        let interrupted =
            encode_netlink_message(NLMSG_DONE, NLM_F_MULTI | NLM_F_DUMP_INTR, sequence, &[])
                .unwrap();
        assert!(matches!(
            parse_dump_datagram(&interrupted, sequence, RTM_NEWROUTE, 2, &mut Vec::new()),
            Err(RouteSteeringError::ReadbackIndeterminate {
                reason: ReadbackIndeterminateReason::IncompleteReply
            })
        ));

        let overrun = encode_netlink_message(NLMSG_OVERRUN, NLM_F_MULTI, sequence, &[]).unwrap();
        assert!(matches!(
            parse_dump_datagram(&overrun, sequence, RTM_NEWROUTE, 2, &mut Vec::new()),
            Err(RouteSteeringError::ReadbackIndeterminate {
                reason: ReadbackIndeterminateReason::IncompleteReply
            })
        ));
    }

    #[test]
    fn readback_datagram_and_byte_bounds_fail_closed() {
        let limits = LinuxRouteReadbackLimits {
            max_datagrams: 1,
            max_messages: 2,
            max_bytes: 64,
        };
        let mut datagrams = 0;
        let mut bytes = 0;
        account_dump_datagram(&mut datagrams, &mut bytes, 32, limits).unwrap();
        assert!(matches!(
            account_dump_datagram(&mut datagrams, &mut bytes, 1, limits),
            Err(RouteSteeringError::ReadbackIndeterminate {
                reason: ReadbackIndeterminateReason::LimitExceeded
            })
        ));

        let limits = LinuxRouteReadbackLimits {
            max_datagrams: 2,
            max_messages: 2,
            max_bytes: 64,
        };
        let mut datagrams = 0;
        let mut bytes = 0;
        assert!(matches!(
            account_dump_datagram(&mut datagrams, &mut bytes, 65, limits),
            Err(RouteSteeringError::ReadbackIndeterminate {
                reason: ReadbackIndeterminateReason::LimitExceeded
            })
        ));

        let invalid = LinuxRouteSteeringBackendConfig {
            receive_buffer_len: MAX_RECEIVE_BUFFER_LEN + 1,
            ..LinuxRouteSteeringBackendConfig::default()
        };
        let limits = LinuxRouteReadbackLimits {
            max_bytes: MAX_RECEIVE_BUFFER_LEN + 1,
            ..LinuxRouteReadbackLimits::default()
        };
        assert!(matches!(
            validate_readback_config(invalid, limits),
            Err(RouteSteeringError::InvalidConfig {
                field: "linux.receive_buffer_len",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn malformed_and_unsupported_readback_fail_closed_as_typed_indeterminate() {
        let mut malformed = encode_route_request(&route()).unwrap();
        append_attr(&mut malformed, RTA_OIF, &[1, 2]).unwrap();
        let backend =
            LinuxRouteSteeringBackend::with_transport(CapturingTransport::with_dump_bodies(vec![
                malformed,
            ]));
        assert_eq!(
            backend.read_route(&route()).await.unwrap(),
            RouteReadback::Indeterminate(ReadbackIndeterminateReason::MalformedReply)
        );

        let backend = LinuxRouteSteeringBackend::with_transport(
            CapturingTransport::with_dump_error(RouteSteeringError::UnsupportedPlatform),
        );
        assert_eq!(
            backend.read_route(&route()).await.unwrap(),
            RouteReadback::Indeterminate(ReadbackIndeterminateReason::Unsupported)
        );

        let backend =
            LinuxRouteSteeringBackend::with_transport(CapturingTransport::with_dump_error(
                RouteSteeringError::indeterminate(ReadbackIndeterminateReason::IncompleteReply),
            ));
        assert_eq!(
            backend.read_rule(&rule()).await.unwrap(),
            RuleReadback::Indeterminate(ReadbackIndeterminateReason::IncompleteReply)
        );

        let mut missing_destination = encode_route_request(&route()).unwrap();
        missing_destination.truncate(ROUTE_MESSAGE_LEN);
        let backend =
            LinuxRouteSteeringBackend::with_transport(CapturingTransport::with_dump_bodies(vec![
                missing_destination,
            ]));
        assert_eq!(
            backend.read_route(&route()).await.unwrap(),
            RouteReadback::Indeterminate(ReadbackIndeterminateReason::MalformedReply)
        );
    }

    #[tokio::test]
    async fn unrepresented_colliding_kernel_attributes_are_never_exact_success() {
        let mut body = encode_route_request(&route()).unwrap();
        append_attr(&mut body, 250, &[1, 2, 3, 4]).unwrap();
        let backend =
            LinuxRouteSteeringBackend::with_transport(CapturingTransport::with_dump_bodies(vec![
                body,
            ]));
        assert_eq!(
            backend.read_route(&route()).await.unwrap(),
            RouteReadback::Indeterminate(ReadbackIndeterminateReason::UnrepresentableObject)
        );
    }

    #[tokio::test]
    async fn ipv6_route_readback_accepts_only_structural_cache_metadata_and_neutral_preference() {
        let request = RouteRequest {
            destination: IpPrefix::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                64,
            ),
            oif_ifindex: 42,
            table: 1000,
            priority: Some(10),
        };
        let mut exact = encode_route_request(&request).unwrap();
        let mut volatile_only = [0xa5; ROUTE_CACHEINFO_LEN];
        volatile_only[8..16].fill(0);
        append_attr(&mut exact, RTA_CACHEINFO, &volatile_only).unwrap();
        append_attr(&mut exact, RTA_PREF, &[ICMPV6_ROUTER_PREF_MEDIUM]).unwrap();
        let backend =
            LinuxRouteSteeringBackend::with_transport(CapturingTransport::with_dump_bodies(vec![
                exact,
            ]));
        assert_eq!(
            backend.read_route(&request).await.unwrap(),
            RouteReadback::ExactPresent
        );

        for (offset, value) in [(8, 1_i32), (8, -1_i32), (12, 1_i32)] {
            let mut semantic = [0_u8; ROUTE_CACHEINFO_LEN];
            semantic[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            let mut body = encode_route_request(&request).unwrap();
            append_attr(&mut body, RTA_CACHEINFO, &semantic).unwrap();
            let backend = LinuxRouteSteeringBackend::with_transport(
                CapturingTransport::with_dump_bodies(vec![body]),
            );
            assert_eq!(
                backend.read_route(&request).await.unwrap(),
                RouteReadback::Indeterminate(ReadbackIndeterminateReason::UnrepresentableObject)
            );
        }

        let mut non_neutral = encode_route_request(&request).unwrap();
        append_attr(&mut non_neutral, RTA_PREF, &[1]).unwrap();
        let backend =
            LinuxRouteSteeringBackend::with_transport(CapturingTransport::with_dump_bodies(vec![
                non_neutral,
            ]));
        assert_eq!(
            backend.read_route(&request).await.unwrap(),
            RouteReadback::Indeterminate(ReadbackIndeterminateReason::UnrepresentableObject)
        );

        for len in [ROUTE_CACHEINFO_LEN - 1, ROUTE_CACHEINFO_LEN + 1] {
            let mut malformed = encode_route_request(&request).unwrap();
            append_attr(&mut malformed, RTA_CACHEINFO, &vec![0; len]).unwrap();
            let backend = LinuxRouteSteeringBackend::with_transport(
                CapturingTransport::with_dump_bodies(vec![malformed]),
            );
            assert_eq!(
                backend.read_route(&request).await.unwrap(),
                RouteReadback::Indeterminate(ReadbackIndeterminateReason::MalformedReply)
            );
        }

        let mut flagged = encode_route_request(&request).unwrap();
        append_attr(
            &mut flagged,
            RTA_CACHEINFO | 0x8000,
            &[0; ROUTE_CACHEINFO_LEN],
        )
        .unwrap();
        let backend =
            LinuxRouteSteeringBackend::with_transport(CapturingTransport::with_dump_bodies(vec![
                flagged,
            ]));
        assert_eq!(
            backend.read_route(&request).await.unwrap(),
            RouteReadback::Indeterminate(ReadbackIndeterminateReason::MalformedReply)
        );

        let mut duplicate = encode_route_request(&request).unwrap();
        append_attr(&mut duplicate, RTA_CACHEINFO, &[0; ROUTE_CACHEINFO_LEN]).unwrap();
        append_attr(&mut duplicate, RTA_CACHEINFO, &[0; ROUTE_CACHEINFO_LEN]).unwrap();
        let backend =
            LinuxRouteSteeringBackend::with_transport(CapturingTransport::with_dump_bodies(vec![
                duplicate,
            ]));
        assert_eq!(
            backend.read_route(&request).await.unwrap(),
            RouteReadback::Indeterminate(ReadbackIndeterminateReason::MalformedReply)
        );
    }

    #[tokio::test]
    async fn linux_paired_convergence_matches_mock_exact_and_owned_rollback_semantics() {
        let installed_transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(vec![encode_route_request(&route()).unwrap()])),
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(vec![encode_rule_request(&rule()).unwrap()])),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(installed_transport.clone());
        let outcome = backend
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap();
        assert_eq!(outcome.route, RouteConvergenceOutcome::Installed);
        assert_eq!(outcome.rule, RuleConvergenceOutcome::Installed);
        assert_eq!(outcome.rollback, RouteRuleRollback::NotNeeded);
        assert_eq!(
            installed_transport
                .requests()
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![
                RTM_GETROUTE,
                RTM_NEWROUTE,
                RTM_GETROUTE,
                RTM_GETRULE,
                RTM_NEWRULE,
                RTM_GETRULE
            ]
        );

        let exact_transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(vec![encode_route_request(&route()).unwrap()])),
            ScriptedResponse::Dump(Ok(vec![encode_rule_request(&rule()).unwrap()])),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(exact_transport.clone());
        let outcome = backend
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap();
        assert_eq!(outcome.route, RouteConvergenceOutcome::ExactAlreadyPresent);
        assert_eq!(outcome.rule, RuleConvergenceOutcome::ExactAlreadyPresent);
        assert_eq!(outcome.rollback, RouteRuleRollback::NotNeeded);
        assert_eq!(
            exact_transport
                .requests()
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![RTM_GETROUTE, RTM_GETRULE]
        );

        let mut conflicting_rule = rule();
        conflicting_rule.table = 2000;
        let rollback_transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(vec![encode_route_request(&route()).unwrap()])),
            ScriptedResponse::Dump(Ok(vec![encode_rule_request(&conflicting_rule).unwrap()])),
            ScriptedResponse::Dump(Ok(vec![encode_route_request(&route()).unwrap()])),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(Vec::new())),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(rollback_transport.clone());
        let outcome = backend
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap();
        assert_eq!(
            outcome.route,
            RouteConvergenceOutcome::InstalledThenRolledBack
        );
        assert!(matches!(outcome.rule, RuleConvergenceOutcome::Conflict(_)));
        assert_eq!(outcome.rollback, RouteRuleRollback::RemovedOwnedRoute);
        assert_eq!(
            rollback_transport
                .requests()
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![
                RTM_GETROUTE,
                RTM_NEWROUTE,
                RTM_GETROUTE,
                RTM_GETRULE,
                RTM_GETROUTE,
                RTM_DELROUTE,
                RTM_GETROUTE,
            ]
        );

        let post_install_transport = ScriptedTransport::new(vec![
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(vec![encode_route_request(&route()).unwrap()])),
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(vec![encode_rule_request(&conflicting_rule).unwrap()])),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(Vec::new())),
            ScriptedResponse::Dump(Ok(vec![encode_route_request(&route()).unwrap()])),
            ScriptedResponse::Transaction(Ok(None)),
            ScriptedResponse::Dump(Ok(Vec::new())),
        ]);
        let backend = LinuxRouteSteeringBackend::with_transport(post_install_transport.clone());
        let outcome = backend
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap();
        assert_eq!(
            outcome.route,
            RouteConvergenceOutcome::InstalledThenRolledBack
        );
        assert!(matches!(
            outcome.rule,
            RuleConvergenceOutcome::ConflictAfterOwnedRollback(_)
        ));
        assert_eq!(
            outcome.rollback,
            RouteRuleRollback::RemovedOwnedRouteAndRule
        );
        assert_eq!(
            post_install_transport
                .requests()
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![
                RTM_GETROUTE,
                RTM_NEWROUTE,
                RTM_GETROUTE,
                RTM_GETRULE,
                RTM_NEWRULE,
                RTM_GETRULE,
                RTM_DELRULE,
                RTM_GETRULE,
                RTM_GETROUTE,
                RTM_DELROUTE,
                RTM_GETROUTE,
            ]
        );
    }

    #[tokio::test]
    async fn cancelling_waiter_does_not_cancel_linux_owned_rollback_worker() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let transport = CancellationTransport {
            requests: Arc::new(Mutex::new(Vec::new())),
            rule_started: started_tx,
            release_rule: Arc::new(Mutex::new(release_rx)),
            route_present: Arc::new(AtomicBool::new(false)),
        };
        let backend = LinuxRouteSteeringBackend::with_transport(transport.clone());
        let worker_backend = backend.clone();
        let task = tokio::spawn(async move {
            worker_backend
                .converge_route_and_rule(route(), rule())
                .await
        });

        tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(2)))
            .await
            .unwrap()
            .unwrap();
        task.abort();
        let follower = tokio::spawn(async move { backend.read_route(&route()).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(transport.requests().len(), 5);
        release_tx.send(()).unwrap();
        assert_eq!(follower.await.unwrap().unwrap(), RouteReadback::Absent);
        assert_eq!(
            transport
                .requests()
                .iter()
                .map(|request| u16::from_ne_bytes([request[4], request[5]]))
                .collect::<Vec<_>>(),
            vec![
                RTM_GETROUTE,
                RTM_NEWROUTE,
                RTM_GETROUTE,
                RTM_GETRULE,
                RTM_NEWRULE,
                RTM_GETROUTE,
                RTM_DELROUTE,
                RTM_GETROUTE,
                RTM_GETROUTE,
            ]
        );
    }
}
