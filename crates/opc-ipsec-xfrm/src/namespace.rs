//! Namespace-bound Linux XFRM actor.

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

#[cfg(unix)]
use std::collections::HashMap;
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::Weak;

use async_trait::async_trait;
#[cfg(target_os = "linux")]
use nix::libc;
#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, socket, AddressFamily, SockFlag, SockType};
#[cfg(target_os = "linux")]
use nix::{getsockopt_impl, sockopt_impl};
use tokio::sync::{mpsc, oneshot};

use crate::counter_resume::{
    map_backend_error, CounterRecoveryActorRequest, CounterResumeActorRequest,
    EspCounterReceiptRegistry,
};
use crate::model::validate_exact_remove_policy_request;
#[cfg(target_os = "linux")]
use crate::observation::linux::LinuxEspPeerObservationKernelSource;
#[cfg(target_os = "linux")]
use crate::observation::{
    EspPeerObservationKey, EspPeerObservationRegistration, LinuxEspPeerObservationConfig,
    LinuxEspPeerObservationMonitor,
};
#[cfg(unix)]
use crate::{
    durable_install::{
        cut_durable_object_install_at_indeterminate_after_effect as cut_object_install_at_indeterminate_after_effect,
        cut_durable_object_install_at_issuing as cut_object_install_at_issuing,
        cut_durable_object_install_at_removal_admitted as cut_object_install_at_removal_admitted,
        durable_object_install_phase, finalize_durable_object_install as finalize_object_install,
        issue_durable_object_install as run_object_install,
        prepare_durable_object_install as prepare_object_install, readback_object_present,
        recover_durable_object_install as recover_object_install,
        validate_durable_object_install_admission as validate_object_install_admission,
        XfrmObjectInstallDurableOutcome, XfrmObjectInstallRestartOutcome,
    },
    durable_object::{
        XfrmObjectInstallDurableError, XfrmObjectInstallDurablePhase,
        XfrmObjectInstallOperationGeneration, XfrmObjectInstallOperationId,
        XfrmObjectInstallPreEffectProof, XfrmObjectInstallRecoveryHandle,
        XfrmObjectInstallRecoveryStore, XfrmObjectRecoveryProofKey,
    },
    durable_relocation::{
        XfrmSaRelocationDurableError, XfrmSaRelocationDurablePhase,
        XfrmSaRelocationOperationGeneration, XfrmSaRelocationOperationId,
        XfrmSaRelocationRecoveryHandle, XfrmSaRelocationRecoveryProofKey,
        XfrmSaRelocationRecoveryStore,
    },
    durable_relocation_flow::{
        cut_durable_sa_relocation_at_issuing as cut_sa_relocation_at_issuing,
        durable_sa_relocation_phase, issue_durable_sa_relocation as run_sa_relocation,
        prepare_durable_sa_relocation as prepare_sa_relocation,
        recover_durable_sa_relocation as recover_sa_relocation,
        validate_durable_sa_relocation_admission as validate_sa_relocation_admission,
        witness_sa_relocation_pre_effect_proof as witness_sa_relocation_proof,
        XfrmSaRelocationDurableOutcome, XfrmSaRelocationPreEffectRejection,
        XfrmSaRelocationRestartOutcome,
    },
    durable_roster::{
        XfrmObjectRosterDurableError, XfrmObjectRosterDurablePhase, XfrmObjectRosterGroupId,
        XfrmObjectRosterOperationGeneration, XfrmObjectRosterRecoveryHandle,
        XfrmObjectRosterRecoveryProofKey, XfrmObjectRosterRecoveryStore,
    },
    durable_roster_flow::{
        adopt_durable_object_roster as adopt_object_roster,
        cut_durable_object_roster_at_applied as cut_object_roster_at_applied,
        cut_durable_object_roster_at_compensating_member as cut_object_roster_at_compensating_member,
        cut_durable_object_roster_at_issuing_member as cut_object_roster_at_issuing_member,
        durable_object_roster_phase, finalize_durable_object_roster as finalize_object_roster,
        finish_durable_object_roster_effect_quiesced as finish_object_roster_effect_quiesced,
        issue_durable_object_roster as run_object_roster,
        issue_durable_object_roster_effect_quiesced as run_object_roster_effect_quiesced,
        prepare_object_roster as prepare_object_roster_record,
        recover_durable_object_roster as recover_object_roster, validate_object_roster_admission,
        XfrmObjectRosterDurableOutcome, XfrmObjectRosterIssueError, XfrmObjectRosterRequest,
        XfrmObjectRosterRestartOutcome,
    },
    XfrmObjectInstallRequest,
};
use crate::{
    outbound_binding::{validate_outbound_request, OutboundSaPolicyExpectation},
    AppliedEspCounterReceipt, EspCounterProofRequirement, EspCounterResumeApplyRequest,
    EspCounterResumeBinding, EspCounterResumeError, EspCounterResumeRecoveryRequest,
    InstalledOutboundSaBinding, OutboundSaBindingError, OutboundSaBindingId,
};
use crate::{
    AllocateSpiRequest, ExactRemovePolicyRequest, InstallPolicyRequest, InstallSaRequest,
    LinuxXfrmBackend, PolicyParameters, QueryPolicyRequest, QuerySaRequest, RekeyPolicyRequest,
    RekeySaRequest, RelocateSaRequest, RemovePolicyRequest, RemoveSaRequest, SaParameters,
    SaRelocationIdentity, SaState, SpiAllocation, XfrmBackend, XfrmCapability,
    XfrmCompositeInstallRequest, XfrmError, XfrmProbe,
};

/// Maximum number of admitted Linux XFRM operations waiting for the dedicated
/// network-namespace actor.
///
/// Admission is explicitly bounded so callers cannot turn kernel or netlink
/// backpressure into unbounded SDK memory growth.
pub const LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY: usize = 64;

#[cfg(target_os = "linux")]
sockopt_impl!(
    DurableNetworkNamespaceCookie,
    GetOnly,
    libc::SOL_SOCKET,
    libc::SO_NETNS_COOKIE,
    u64
);

/// Failure while atomically binding a namespace actor and durable recovery
/// store before any mutation-capable backend handle becomes visible.
#[cfg(unix)]
#[non_exhaustive]
pub enum XfrmObjectRecoveryBindError {
    /// The Linux namespace actor could not be captured, spawned, or prepared.
    Backend {
        /// Redaction-safe backend failure.
        source: XfrmError,
    },
    /// The durable recovery store could not be authenticated and leased.
    Store {
        /// Value-free durable-store failure.
        source: XfrmObjectInstallDurableError,
    },
    /// The durable SA relocation recovery store could not be authenticated
    /// and leased.
    SaRelocationStore {
        /// Value-free durable-store failure.
        source: XfrmSaRelocationDurableError,
    },
    /// The durable grouped object roster recovery store could not be
    /// authenticated and leased.
    RosterStore {
        /// Value-free durable-store failure.
        source: XfrmObjectRosterDurableError,
    },
}

#[cfg(unix)]
impl XfrmObjectRecoveryBindError {
    /// Stable, value-free error label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Backend { .. } => "xfrm_object_recovery_bind_backend",
            Self::Store { .. } => "xfrm_object_recovery_bind_store",
            Self::SaRelocationStore { .. } => "xfrm_sa_relocation_recovery_bind_store",
            Self::RosterStore { .. } => "xfrm_object_roster_recovery_bind_store",
        }
    }
}

#[cfg(unix)]
impl fmt::Debug for XfrmObjectRecoveryBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRecoveryBindError")
            .field("code", &self.as_str())
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl fmt::Display for XfrmObjectRecoveryBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(unix)]
impl Error for XfrmObjectRecoveryBindError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Backend { source } => Some(source),
            Self::Store { source } => Some(source),
            Self::SaRelocationStore { source } => Some(source),
            Self::RosterStore { source } => Some(source),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NetworkNamespaceBinding {
    device: u64,
    inode: u64,
    cookie: Option<u64>,
    boot_id: Option<[u8; 16]>,
}

/// Process-local identity of one exact namespace actor.
///
/// Namespace device/inode identity alone is insufficient for receipt
/// correlation: two independently spawned actors can legitimately target
/// the same namespace. The private `Arc` seal makes their live authority
/// distinct without putting process-local identity into the durable
/// [`OutboundSaBindingId`].
#[derive(Clone)]
pub(crate) struct NamespaceActorBinding {
    namespace: NetworkNamespaceBinding,
    identity: Arc<()>,
}

impl NamespaceActorBinding {
    pub(crate) fn new(namespace: NetworkNamespaceBinding) -> Self {
        Self {
            namespace,
            identity: Arc::new(()),
        }
    }

    pub(crate) const fn namespace(&self) -> NetworkNamespaceBinding {
        self.namespace
    }
}

impl PartialEq for NamespaceActorBinding {
    fn eq(&self, other: &Self) -> bool {
        self.namespace == other.namespace && Arc::ptr_eq(&self.identity, &other.identity)
    }
}

impl Eq for NamespaceActorBinding {}

impl fmt::Debug for NamespaceActorBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NamespaceActorBinding(<redacted>)")
    }
}

impl NetworkNamespaceBinding {
    #[cfg(unix)]
    fn durable_bytes(self) -> Result<[u8; 40], XfrmObjectInstallDurableError> {
        let cookie = self
            .cookie
            .ok_or(XfrmObjectInstallDurableError::WrongBinding)?;
        let boot_id = self
            .boot_id
            .ok_or(XfrmObjectInstallDurableError::WrongBinding)?;
        let mut bytes = [0_u8; 40];
        bytes[..8].copy_from_slice(&self.device.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.inode.to_be_bytes());
        bytes[16..24].copy_from_slice(&cookie.to_be_bytes());
        bytes[24..].copy_from_slice(&boot_id);
        Ok(bytes)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn capture() -> Result<Self, XfrmError> {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata("/proc/thread-self/ns/net")
            .map_err(|error| XfrmError::io("network_namespace_identity", error))?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            cookie: capture_network_namespace_cookie(),
            boot_id: capture_boot_id(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn capture() -> Result<Self, XfrmError> {
        Err(XfrmError::UnsupportedPlatform)
    }

    pub(crate) fn ensure_current(self) -> Result<(), XfrmError> {
        if Self::capture()? == self {
            Ok(())
        } else {
            Err(XfrmError::StateMismatch {
                operation: "network_namespace_binding",
            })
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_test(device: u64, inode: u64) -> Self {
        Self {
            device,
            inode,
            cookie: Some(if device ^ inode == 0 {
                1
            } else {
                device ^ inode
            }),
            boot_id: Some([0x42; 16]),
        }
    }
}

#[cfg(target_os = "linux")]
fn capture_network_namespace_cookie() -> Option<u64> {
    let socket = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .ok()?;
    getsockopt(&socket, DurableNetworkNamespaceCookie)
        .ok()
        .filter(|cookie| *cookie != 0)
}

#[cfg(target_os = "linux")]
fn capture_boot_id() -> Option<[u8; 16]> {
    let encoded = std::fs::read("/proc/sys/kernel/random/boot_id").ok()?;
    let mut hexadecimal = [0_u8; 32];
    let mut length = 0_usize;
    for byte in encoded {
        if byte == b'-' || byte == b'\n' || byte == b'\r' {
            continue;
        }
        if length == hexadecimal.len() || !byte.is_ascii_hexdigit() {
            return None;
        }
        hexadecimal[length] = byte;
        length += 1;
    }
    if length != hexadecimal.len() {
        return None;
    }
    let mut boot_id = [0_u8; 16];
    for (output, pair) in boot_id
        .iter_mut()
        .zip(hexadecimal.as_chunks::<2>().0.iter())
    {
        *output = (namespace_hex_nibble(pair[0])? << 4) | namespace_hex_nibble(pair[1])?;
    }
    if boot_id.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(boot_id)
}

#[cfg(target_os = "linux")]
fn namespace_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl fmt::Debug for NetworkNamespaceBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkNamespaceBinding")
            .finish_non_exhaustive()
    }
}

/// Opaque one-shot authority to admit one prepared durable object install.
///
/// The authority is bound to the exact open recovery store, namespace actor,
/// operation identity, generation, and complete SA-only or policy-only
/// request. It cannot be cloned or reconstructed from durable bytes. Passing
/// it to [`NamespaceBoundLinuxXfrmBackend::run_durable_object_install`]
/// consumes it exactly once. Dropping it before actor admission leaves the
/// authenticated `Prepared` record recoverable as authoritative no-mutation.
/// A registered live authority keeps same-process recovery fail closed. Any
/// independently admitted actor mutation invalidates all prepared authorities
/// before its backend effect, while process loss discards their live seals.
#[cfg(unix)]
#[must_use = "dropping this authority leaves a durable Prepared operation to reconcile"]
pub struct XfrmObjectInstallAdmissionAuthority {
    operation: DurableObjectOperation,
    prepared: XfrmObjectInstallRecoveryHandle,
    actor_binding: NamespaceActorBinding,
    seal: Arc<()>,
}

#[cfg(unix)]
impl XfrmObjectInstallAdmissionAuthority {
    fn key(
        &self,
    ) -> (
        XfrmObjectInstallOperationId,
        XfrmObjectInstallOperationGeneration,
    ) {
        (
            self.operation.operation_id,
            self.operation.operation_generation,
        )
    }
}

#[cfg(unix)]
impl fmt::Debug for XfrmObjectInstallAdmissionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectInstallAdmissionAuthority(<redacted>)")
    }
}

/// Value-free failure while admitting one prepared durable object install.
///
/// A DSCP-bearing SA rejected only because deferred activation is still
/// closed, and a pre-effect readback that could not be trusted, both return
/// the original affine authority through [`Self::into_retry_authority`]. In
/// either case no durable phase or writer epoch has changed, so the caller may
/// activate the same namespace actor and retry that exact authority. Every
/// other failure consumes the authority under the durable protocol's existing
/// fail-closed recovery contract.
#[cfg(unix)]
pub struct XfrmObjectInstallRunError {
    kind: XfrmObjectInstallRunErrorKind,
}

#[cfg(unix)]
enum XfrmObjectInstallRunErrorKind {
    Durable(XfrmObjectInstallDurableError),
    DscpActivationRequired(Box<XfrmObjectInstallAdmissionAuthority>),
    PreEffectReadbackFailed {
        authority: Box<XfrmObjectInstallAdmissionAuthority>,
        source: XfrmError,
    },
}

#[cfg(unix)]
impl XfrmObjectInstallRunError {
    const DSCP_ACTIVATION_REQUIRED: &'static str = "xfrm_object_install_dscp_activation_required";
    const PRE_EFFECT_READBACK_FAILED: &'static str =
        "xfrm_object_install_pre_effect_readback_failed";

    fn dscp_activation_required(authority: Box<XfrmObjectInstallAdmissionAuthority>) -> Self {
        Self {
            kind: XfrmObjectInstallRunErrorKind::DscpActivationRequired(authority),
        }
    }

    fn pre_effect_readback_failed(
        authority: Box<XfrmObjectInstallAdmissionAuthority>,
        source: XfrmError,
    ) -> Self {
        Self {
            kind: XfrmObjectInstallRunErrorKind::PreEffectReadbackFailed { authority, source },
        }
    }

    /// Stable, value-free error label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match &self.kind {
            XfrmObjectInstallRunErrorKind::Durable(error) => error.as_str(),
            XfrmObjectInstallRunErrorKind::DscpActivationRequired(_) => {
                Self::DSCP_ACTIVATION_REQUIRED
            }
            XfrmObjectInstallRunErrorKind::PreEffectReadbackFailed { .. } => {
                Self::PRE_EFFECT_READBACK_FAILED
            }
        }
    }

    /// Return the underlying durable-protocol error, when this was not a
    /// clean deferred-activation or pre-effect readback rejection.
    #[must_use]
    pub const fn durable_error(&self) -> Option<XfrmObjectInstallDurableError> {
        match &self.kind {
            XfrmObjectInstallRunErrorKind::Durable(error) => Some(*error),
            XfrmObjectInstallRunErrorKind::DscpActivationRequired(_)
            | XfrmObjectInstallRunErrorKind::PreEffectReadbackFailed { .. } => None,
        }
    }

    /// Return the redaction-safe readback failure, when this was a proved
    /// pre-effect readback rejection.
    #[must_use]
    pub fn readback_source(&self) -> Option<&XfrmError> {
        match &self.kind {
            XfrmObjectInstallRunErrorKind::PreEffectReadbackFailed { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Recover retry authority from a proved pre-effect rejection.
    ///
    /// `None` means the error follows the ordinary durable recovery contract
    /// and no authority may be replayed.
    #[must_use]
    pub fn into_retry_authority(self) -> Option<XfrmObjectInstallAdmissionAuthority> {
        match self.kind {
            XfrmObjectInstallRunErrorKind::DscpActivationRequired(authority) => Some(*authority),
            XfrmObjectInstallRunErrorKind::PreEffectReadbackFailed { authority, .. } => {
                Some(*authority)
            }
            XfrmObjectInstallRunErrorKind::Durable(_) => None,
        }
    }
}

#[cfg(unix)]
impl From<XfrmObjectInstallDurableError> for XfrmObjectInstallRunError {
    fn from(error: XfrmObjectInstallDurableError) -> Self {
        Self {
            kind: XfrmObjectInstallRunErrorKind::Durable(error),
        }
    }
}

#[cfg(unix)]
impl PartialEq<XfrmObjectInstallDurableError> for XfrmObjectInstallRunError {
    fn eq(&self, other: &XfrmObjectInstallDurableError) -> bool {
        self.durable_error() == Some(*other)
    }
}

#[cfg(unix)]
impl fmt::Debug for XfrmObjectInstallRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectInstallRunError")
            .field("code", &self.as_str())
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl fmt::Display for XfrmObjectInstallRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(unix)]
impl Error for XfrmObjectInstallRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            XfrmObjectInstallRunErrorKind::Durable(error) => Some(error),
            XfrmObjectInstallRunErrorKind::DscpActivationRequired(_) => None,
            XfrmObjectInstallRunErrorKind::PreEffectReadbackFailed { source, .. } => Some(source),
        }
    }
}

/// Opaque one-shot authority to admit one prepared durable SA relocation.
///
/// The authority is bound to the exact open recovery store, namespace actor,
/// operation identity, generation, and complete relocation request. It cannot
/// be cloned or reconstructed from durable bytes. Passing it to
/// [`NamespaceBoundLinuxXfrmBackend::run_durable_sa_relocation`] consumes it
/// exactly once. Dropping it before actor admission leaves the authenticated
/// `Prepared` record recoverable as authoritative no-mutation. A registered
/// live authority keeps same-process recovery fail closed. Any independently
/// admitted actor mutation invalidates all prepared authorities before its
/// backend effect, while process loss discards their live seals.
#[cfg(unix)]
#[must_use = "dropping this authority leaves a durable Prepared relocation to reconcile"]
pub struct XfrmSaRelocationAdmissionAuthority {
    operation: DurableSaRelocationOperation,
    prepared: XfrmSaRelocationRecoveryHandle,
    actor_binding: NamespaceActorBinding,
    seal: Arc<()>,
}

#[cfg(unix)]
impl XfrmSaRelocationAdmissionAuthority {
    fn key(
        &self,
    ) -> (
        XfrmSaRelocationOperationId,
        XfrmSaRelocationOperationGeneration,
    ) {
        (
            self.operation.operation_id,
            self.operation.operation_generation,
        )
    }
}

#[cfg(unix)]
impl fmt::Debug for XfrmSaRelocationAdmissionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmSaRelocationAdmissionAuthority(<redacted>)")
    }
}

/// Value-free failure while admitting one prepared durable SA relocation.
///
/// A deferred DSCP activation gate, a proved pre-effect target conflict, and
/// a pre-effect readback that could not be trusted all return the original
/// affine authority through [`Self::into_retry_authority`]. In those cases no
/// durable phase or writer epoch has changed, so the caller may retry that
/// exact authority. A mismatching current state consumes the authority under
/// a value-free label; the retained `Prepared` record recovers as
/// authoritative no-mutation. Every other failure consumes the authority
/// under the durable protocol's existing fail-closed recovery contract.
#[cfg(unix)]
pub struct XfrmSaRelocationRunError {
    kind: XfrmSaRelocationRunErrorKind,
}

#[cfg(unix)]
enum XfrmSaRelocationRunErrorKind {
    Durable(XfrmSaRelocationDurableError),
    DscpActivationRequired(Box<XfrmSaRelocationAdmissionAuthority>),
    TargetConflict(Box<XfrmSaRelocationAdmissionAuthority>),
    PreEffectReadbackFailed {
        authority: Box<XfrmSaRelocationAdmissionAuthority>,
        source: XfrmError,
    },
    CurrentStateMismatch,
}

#[cfg(unix)]
impl XfrmSaRelocationRunError {
    const DSCP_ACTIVATION_REQUIRED: &'static str = "xfrm_sa_relocation_dscp_activation_required";
    const TARGET_CONFLICT: &'static str = "xfrm_sa_relocation_target_conflict";
    const PRE_EFFECT_READBACK_FAILED: &'static str =
        "xfrm_sa_relocation_pre_effect_readback_failed";
    const CURRENT_STATE_MISMATCH: &'static str = "xfrm_sa_relocation_current_state_mismatch";

    fn dscp_activation_required(authority: Box<XfrmSaRelocationAdmissionAuthority>) -> Self {
        Self {
            kind: XfrmSaRelocationRunErrorKind::DscpActivationRequired(authority),
        }
    }

    fn target_conflict(authority: Box<XfrmSaRelocationAdmissionAuthority>) -> Self {
        Self {
            kind: XfrmSaRelocationRunErrorKind::TargetConflict(authority),
        }
    }

    fn pre_effect_readback_failed(
        authority: Box<XfrmSaRelocationAdmissionAuthority>,
        source: XfrmError,
    ) -> Self {
        Self {
            kind: XfrmSaRelocationRunErrorKind::PreEffectReadbackFailed { authority, source },
        }
    }

    fn current_state_mismatch() -> Self {
        Self {
            kind: XfrmSaRelocationRunErrorKind::CurrentStateMismatch,
        }
    }

    /// Stable, value-free error label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match &self.kind {
            XfrmSaRelocationRunErrorKind::Durable(error) => error.as_str(),
            XfrmSaRelocationRunErrorKind::DscpActivationRequired(_) => {
                Self::DSCP_ACTIVATION_REQUIRED
            }
            XfrmSaRelocationRunErrorKind::TargetConflict(_) => Self::TARGET_CONFLICT,
            XfrmSaRelocationRunErrorKind::PreEffectReadbackFailed { .. } => {
                Self::PRE_EFFECT_READBACK_FAILED
            }
            XfrmSaRelocationRunErrorKind::CurrentStateMismatch => Self::CURRENT_STATE_MISMATCH,
        }
    }

    /// Return the underlying durable-protocol error, when this was not a
    /// proved pre-effect rejection.
    #[must_use]
    pub const fn durable_error(&self) -> Option<XfrmSaRelocationDurableError> {
        match &self.kind {
            XfrmSaRelocationRunErrorKind::Durable(error) => Some(*error),
            XfrmSaRelocationRunErrorKind::DscpActivationRequired(_)
            | XfrmSaRelocationRunErrorKind::TargetConflict(_)
            | XfrmSaRelocationRunErrorKind::PreEffectReadbackFailed { .. }
            | XfrmSaRelocationRunErrorKind::CurrentStateMismatch => None,
        }
    }

    /// Return the redaction-safe readback failure, when this was a proved
    /// pre-effect readback rejection.
    #[must_use]
    pub fn readback_source(&self) -> Option<&XfrmError> {
        match &self.kind {
            XfrmSaRelocationRunErrorKind::PreEffectReadbackFailed { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Recover retry authority from a proved pre-effect rejection.
    ///
    /// `None` means the error follows the ordinary durable recovery contract
    /// and no authority may be replayed.
    #[must_use]
    pub fn into_retry_authority(self) -> Option<XfrmSaRelocationAdmissionAuthority> {
        match self.kind {
            XfrmSaRelocationRunErrorKind::DscpActivationRequired(authority)
            | XfrmSaRelocationRunErrorKind::TargetConflict(authority) => Some(*authority),
            XfrmSaRelocationRunErrorKind::PreEffectReadbackFailed { authority, .. } => {
                Some(*authority)
            }
            XfrmSaRelocationRunErrorKind::Durable(_)
            | XfrmSaRelocationRunErrorKind::CurrentStateMismatch => None,
        }
    }
}

#[cfg(unix)]
impl From<XfrmSaRelocationDurableError> for XfrmSaRelocationRunError {
    fn from(error: XfrmSaRelocationDurableError) -> Self {
        Self {
            kind: XfrmSaRelocationRunErrorKind::Durable(error),
        }
    }
}

#[cfg(unix)]
impl PartialEq<XfrmSaRelocationDurableError> for XfrmSaRelocationRunError {
    fn eq(&self, other: &XfrmSaRelocationDurableError) -> bool {
        self.durable_error() == Some(*other)
    }
}

#[cfg(unix)]
impl fmt::Debug for XfrmSaRelocationRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmSaRelocationRunError")
            .field("code", &self.as_str())
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl fmt::Display for XfrmSaRelocationRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(unix)]
impl Error for XfrmSaRelocationRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            XfrmSaRelocationRunErrorKind::Durable(error) => Some(error),
            XfrmSaRelocationRunErrorKind::DscpActivationRequired(_)
            | XfrmSaRelocationRunErrorKind::TargetConflict(_)
            | XfrmSaRelocationRunErrorKind::CurrentStateMismatch => None,
            XfrmSaRelocationRunErrorKind::PreEffectReadbackFailed { source, .. } => Some(source),
        }
    }
}

/// Opaque one-shot authority to admit one prepared durable object roster.
///
/// The authority is bound to the exact open roster recovery store, namespace
/// actor, group identity, generation, and complete ordered member set. It
/// cannot be cloned or reconstructed from durable bytes. Passing it to
/// [`NamespaceBoundLinuxXfrmBackend::run_durable_object_roster`] consumes it
/// exactly once, and that single call carries the whole group. Dropping it
/// before actor admission leaves the authenticated `Prepared` record
/// recoverable as authoritative no-mutation. A registered live authority keeps
/// same-process recovery fail closed. Any independently admitted actor mutation
/// invalidates all prepared authorities before its backend effect, while
/// process loss discards their live seals.
///
/// The affine, move-only receiver is the executable one-run invariant. The
/// error code is pinned so a later signature change cannot degrade this into
/// "fails to compile for some unrelated reason":
///
/// ```compile_fail,E0382
/// # use opc_ipsec_xfrm::{NamespaceBoundLinuxXfrmBackend, XfrmObjectRosterAdmissionAuthority};
/// # fn authority() -> XfrmObjectRosterAdmissionAuthority { unimplemented!() }
/// # async fn cannot_run_twice(backend: NamespaceBoundLinuxXfrmBackend) {
/// let admission = authority();
/// let first = backend.run_durable_object_roster(admission);
/// let second = backend.run_durable_object_roster(admission);
/// # let _ = (first, second);
/// # }
/// ```
#[cfg(unix)]
#[must_use = "dropping this authority leaves a durable Prepared roster to reconcile"]
pub struct XfrmObjectRosterAdmissionAuthority {
    operation: Box<DurableObjectRosterOperation>,
    prepared: XfrmObjectRosterRecoveryHandle,
    actor_binding: NamespaceActorBinding,
    seal: Arc<()>,
}

#[cfg(unix)]
impl XfrmObjectRosterAdmissionAuthority {
    fn key(&self) -> (XfrmObjectRosterGroupId, XfrmObjectRosterOperationGeneration) {
        (self.operation.group_id, self.operation.generation)
    }
}

#[cfg(unix)]
impl fmt::Debug for XfrmObjectRosterAdmissionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRosterAdmissionAuthority(<redacted>)")
    }
}

/// Affine proof that every roster effect acknowledged success but the final
/// durable `Applied` publication is intentionally deferred.
///
/// This is an opt-in response-activation boundary.  It is produced only after
/// the actor has durably published the per-member adjacent `Absent` witness
/// immediately before every effect and every requested effect has completed.
/// The final member is deliberately retained as `Issuing`/`Pending` until
/// [`NamespaceBoundLinuxXfrmBackend::finish_durable_object_roster_effect_quiesced`]
/// consumes this value.  Dropping it does not replay or complete anything:
/// the durable record remains unresolved and normal recovery reconciles that
/// final exact proof before any rollback deletion.
///
/// The token remains registered with the namespace actor while live, so a
/// same-process recovery cannot race response activation.  It is move-only;
/// the following is deliberately rejected by the compiler:
///
/// ```compile_fail,E0382
/// # use opc_ipsec_xfrm::{NamespaceBoundLinuxXfrmBackend, XfrmObjectRosterEffectQuiesced};
/// # fn effect() -> XfrmObjectRosterEffectQuiesced { unimplemented!() }
/// # async fn cannot_finish_twice(backend: NamespaceBoundLinuxXfrmBackend) {
/// let effect = effect();
/// let first = backend.finish_durable_object_roster_effect_quiesced(effect);
/// let second = backend.finish_durable_object_roster_effect_quiesced(effect);
/// # let _ = (first, second);
/// # }
/// ```
#[cfg(unix)]
#[must_use = "dropping this token leaves an unresolved issuing roster to recover"]
pub struct XfrmObjectRosterEffectQuiesced {
    operation: Box<DurableObjectRosterOperation>,
    issuing: XfrmObjectRosterRecoveryHandle,
    actor_binding: NamespaceActorBinding,
    seal: Arc<()>,
}

#[cfg(unix)]
impl XfrmObjectRosterEffectQuiesced {
    fn key(&self) -> (XfrmObjectRosterGroupId, XfrmObjectRosterOperationGeneration) {
        (self.operation.group_id, self.operation.generation)
    }
}

#[cfg(unix)]
impl fmt::Debug for XfrmObjectRosterEffectQuiesced {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRosterEffectQuiesced(<redacted>)")
    }
}

/// Value-free failure while admitting one prepared durable object roster.
///
/// Three rejections return the original affine authority through
/// [`Self::into_retry_authority`]: a closed cooperating-writer gate, a roster
/// whose SA members need a still-closed deferred DSCP activation, and a
/// pre-effect sweep readback that could not be trusted. In all three cases no
/// durable roster phase or roster writer epoch has changed and no member
/// effect was admitted, so the caller may retry that exact authority. Every
/// other failure consumes the authority under the durable protocol's existing
/// fail-closed recovery contract.
#[cfg(unix)]
pub struct XfrmObjectRosterRunError {
    kind: XfrmObjectRosterRunErrorKind,
}

#[cfg(unix)]
enum XfrmObjectRosterRunErrorKind {
    Durable(XfrmObjectRosterDurableError),
    Gated {
        authority: Box<XfrmObjectRosterAdmissionAuthority>,
        source: XfrmObjectRosterDurableError,
    },
    DscpActivationRequired(Box<XfrmObjectRosterAdmissionAuthority>),
    PreEffectReadbackFailed {
        authority: Box<XfrmObjectRosterAdmissionAuthority>,
        source: XfrmError,
    },
}

#[cfg(unix)]
impl XfrmObjectRosterRunError {
    const GATED: &'static str = "xfrm_object_roster_gated";
    const DSCP_ACTIVATION_REQUIRED: &'static str = "xfrm_object_roster_dscp_activation_required";
    const PRE_EFFECT_READBACK_FAILED: &'static str =
        "xfrm_object_roster_pre_effect_readback_failed";

    fn gated(
        authority: Box<XfrmObjectRosterAdmissionAuthority>,
        source: XfrmObjectRosterDurableError,
    ) -> Self {
        Self {
            kind: XfrmObjectRosterRunErrorKind::Gated { authority, source },
        }
    }

    fn dscp_activation_required(authority: Box<XfrmObjectRosterAdmissionAuthority>) -> Self {
        Self {
            kind: XfrmObjectRosterRunErrorKind::DscpActivationRequired(authority),
        }
    }

    fn pre_effect_readback_failed(
        authority: Box<XfrmObjectRosterAdmissionAuthority>,
        source: XfrmError,
    ) -> Self {
        Self {
            kind: XfrmObjectRosterRunErrorKind::PreEffectReadbackFailed { authority, source },
        }
    }

    /// Stable, value-free error label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match &self.kind {
            XfrmObjectRosterRunErrorKind::Durable(error) => error.as_str(),
            XfrmObjectRosterRunErrorKind::Gated { .. } => Self::GATED,
            XfrmObjectRosterRunErrorKind::DscpActivationRequired(_) => {
                Self::DSCP_ACTIVATION_REQUIRED
            }
            XfrmObjectRosterRunErrorKind::PreEffectReadbackFailed { .. } => {
                Self::PRE_EFFECT_READBACK_FAILED
            }
        }
    }

    /// Return the underlying durable-protocol error, when one was observed.
    ///
    /// A gated rejection reports the rejection its closed cooperating-writer
    /// gate produced AND returns the authority, because the gate was screened
    /// before anything was consumed. Compare [`Self::as_str`] to tell the two
    /// apart: only `xfrm_object_roster_gated` is retryable.
    #[must_use]
    pub const fn durable_error(&self) -> Option<XfrmObjectRosterDurableError> {
        match &self.kind {
            XfrmObjectRosterRunErrorKind::Durable(error)
            | XfrmObjectRosterRunErrorKind::Gated { source: error, .. } => Some(*error),
            XfrmObjectRosterRunErrorKind::DscpActivationRequired(_)
            | XfrmObjectRosterRunErrorKind::PreEffectReadbackFailed { .. } => None,
        }
    }

    /// Return the redaction-safe readback failure, when this was a proved
    /// pre-effect readback rejection.
    #[must_use]
    pub fn readback_source(&self) -> Option<&XfrmError> {
        match &self.kind {
            XfrmObjectRosterRunErrorKind::PreEffectReadbackFailed { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Recover retry authority from a proved pre-effect rejection.
    ///
    /// `None` means the error follows the ordinary durable recovery contract
    /// and no authority may be replayed.
    #[must_use]
    pub fn into_retry_authority(self) -> Option<XfrmObjectRosterAdmissionAuthority> {
        match self.kind {
            XfrmObjectRosterRunErrorKind::Gated { authority, .. }
            | XfrmObjectRosterRunErrorKind::DscpActivationRequired(authority)
            | XfrmObjectRosterRunErrorKind::PreEffectReadbackFailed { authority, .. } => {
                Some(*authority)
            }
            XfrmObjectRosterRunErrorKind::Durable(_) => None,
        }
    }
}

#[cfg(unix)]
impl From<XfrmObjectRosterDurableError> for XfrmObjectRosterRunError {
    fn from(error: XfrmObjectRosterDurableError) -> Self {
        Self {
            kind: XfrmObjectRosterRunErrorKind::Durable(error),
        }
    }
}

#[cfg(unix)]
impl PartialEq<XfrmObjectRosterDurableError> for XfrmObjectRosterRunError {
    fn eq(&self, other: &XfrmObjectRosterDurableError) -> bool {
        self.durable_error() == Some(*other)
    }
}

#[cfg(unix)]
impl fmt::Debug for XfrmObjectRosterRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterRunError")
            .field("code", &self.as_str())
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl fmt::Display for XfrmObjectRosterRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(unix)]
impl Error for XfrmObjectRosterRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            XfrmObjectRosterRunErrorKind::Durable(error)
            | XfrmObjectRosterRunErrorKind::Gated { source: error, .. } => Some(error),
            XfrmObjectRosterRunErrorKind::DscpActivationRequired(_) => None,
            XfrmObjectRosterRunErrorKind::PreEffectReadbackFailed { source, .. } => Some(source),
        }
    }
}

/// Linux XFRM backend pinned to the network namespace of the thread that
/// created it.
///
/// A dedicated OS thread inherits and synchronously verifies the caller's
/// opaque network-namespace identity. It owns a current-thread Tokio runtime
/// and serially executes every [`XfrmBackend`] operation, including fixed-DSCP
/// readiness work. Netlink transactions execute inline on that actor and open
/// a fresh socket only after rechecking the namespace identity.
///
/// Queue admission is bounded by [`LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY`]. A
/// future cancelled while waiting for capacity has not submitted work, except
/// that a polled
/// [`Self::finish_durable_object_roster_effect_quiesced`] transfers its
/// already-effect-quiesced roster token to a retained actor-runtime task before
/// it waits for a permit. Once a permit is obtained, submission is synchronous
/// and the actor completes the admitted operation even if its response receiver
/// is dropped. If an admitted mutation loses its reply, the caller receives
/// [`XfrmError::StateIndeterminate`]; read-only operations receive
/// [`XfrmError::Unavailable`]. Dropping the final backend clone closes its
/// caller-held sender; a retained roster finish keeps exactly one sender alive
/// until it submits or observes actor shutdown. The detached actor then drains
/// admitted commands and exits without blocking the dropping thread.
#[derive(Clone)]
pub struct NamespaceBoundLinuxXfrmBackend {
    inner: Arc<NamespaceBoundLinuxXfrmBackendInner>,
}

struct NamespaceBoundLinuxXfrmBackendInner {
    sender: mpsc::Sender<NamespaceCommand>,
    actor_binding: NamespaceActorBinding,
    // The actor runtime owns retained finish tasks.  This lets the special
    // post-response roster finish survive cancellation of its caller without
    // turning the bounded namespace command channel into another queue.
    #[cfg(unix)]
    retained_finish_runtime: Option<tokio::runtime::Handle>,
    #[cfg(test)]
    retained_finish_completed: Arc<std::sync::atomic::AtomicBool>,
}

impl fmt::Debug for NamespaceBoundLinuxXfrmBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamespaceBoundLinuxXfrmBackend")
            .field("network_namespace", &self.network_namespace_binding())
            .field("queue_capacity", &LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY)
            .finish_non_exhaustive()
    }
}

pub(crate) fn bind_current_network_namespace(
    backend: LinuxXfrmBackend,
) -> Result<NamespaceBoundLinuxXfrmBackend, XfrmError> {
    bind_with_capacity(backend, LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY)
}

#[cfg(unix)]
fn bind_with_capacity(
    backend: LinuxXfrmBackend,
    capacity: usize,
) -> Result<NamespaceBoundLinuxXfrmBackend, XfrmError> {
    bind_with_capacity_and_recovery(backend, capacity, None, None, None)
        .map(|(backend, _, _, _)| backend)
        .map_err(|error| match error {
            XfrmObjectRecoveryBindError::Backend { source } => source,
            // No store was requested, so these variants are unreachable
            // without an internal protocol defect. Keep the legacy API
            // value-free.
            XfrmObjectRecoveryBindError::Store { .. }
            | XfrmObjectRecoveryBindError::SaRelocationStore { .. }
            | XfrmObjectRecoveryBindError::RosterStore { .. } => XfrmError::Unavailable,
        })
}

#[cfg(not(unix))]
fn bind_with_capacity(
    backend: LinuxXfrmBackend,
    capacity: usize,
) -> Result<NamespaceBoundLinuxXfrmBackend, XfrmError> {
    let binding = NetworkNamespaceBinding::capture()?;
    let actor_binding = NamespaceActorBinding::new(binding);
    let backend = backend.for_namespace_actor(binding);
    let (sender, receiver) = mpsc::channel(capacity);
    let (startup_sender, startup_receiver) = std::sync::mpsc::sync_channel(1);

    let worker = std::thread::Builder::new()
        .name(String::from("opc-xfrm-netns"))
        .spawn({
            let actor_binding = actor_binding.clone();
            move || run_actor(backend, actor_binding, receiver, startup_sender)
        })
        .map_err(|error| XfrmError::io("network_namespace_actor_spawn", error))?;

    let startup = startup_receiver
        .recv()
        .map_err(|_| XfrmError::Unavailable)?;
    // A JoinHandle detaches on drop. The channel lifetime is authoritative:
    // closing the final sender makes the actor drain and then exit, without a
    // potentially blocking Drop implementation.
    drop(worker);
    startup?;

    Ok(NamespaceBoundLinuxXfrmBackend {
        inner: Arc::new(NamespaceBoundLinuxXfrmBackendInner {
            sender,
            actor_binding,
            #[cfg(test)]
            retained_finish_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }),
    })
}

#[cfg(unix)]
pub(crate) fn bind_current_network_namespace_with_object_recovery(
    backend: LinuxXfrmBackend,
    path: PathBuf,
    proof_key: XfrmObjectRecoveryProofKey,
) -> Result<
    (
        NamespaceBoundLinuxXfrmBackend,
        XfrmObjectInstallRecoveryStore,
    ),
    XfrmObjectRecoveryBindError,
> {
    let (backend, store, _, _) = bind_with_capacity_and_recovery(
        backend,
        LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
        Some((path, proof_key)),
        None,
        None,
    )?;
    let store = store.ok_or(XfrmObjectRecoveryBindError::Store {
        source: XfrmObjectInstallDurableError::WrongBinding,
    })?;
    Ok((backend, store))
}

#[cfg(unix)]
pub(crate) fn bind_current_network_namespace_with_sa_relocation_recovery(
    backend: LinuxXfrmBackend,
    path: PathBuf,
    proof_key: XfrmSaRelocationRecoveryProofKey,
) -> Result<
    (
        NamespaceBoundLinuxXfrmBackend,
        XfrmSaRelocationRecoveryStore,
    ),
    XfrmObjectRecoveryBindError,
> {
    let (backend, _, store, _) = bind_with_capacity_and_recovery(
        backend,
        LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
        None,
        Some((path, proof_key)),
        None,
    )?;
    let store = store.ok_or(XfrmObjectRecoveryBindError::SaRelocationStore {
        source: XfrmSaRelocationDurableError::WrongBinding,
    })?;
    Ok((backend, store))
}

#[cfg(unix)]
pub(crate) fn bind_current_network_namespace_with_object_roster_recovery(
    backend: LinuxXfrmBackend,
    path: PathBuf,
    proof_key: XfrmObjectRosterRecoveryProofKey,
) -> Result<
    (
        NamespaceBoundLinuxXfrmBackend,
        XfrmObjectRosterRecoveryStore,
    ),
    XfrmObjectRecoveryBindError,
> {
    let (backend, _, _, store) = bind_with_capacity_and_recovery(
        backend,
        LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
        None,
        None,
        Some((path, proof_key)),
    )?;
    let store = store.ok_or(XfrmObjectRecoveryBindError::RosterStore {
        source: XfrmObjectRosterDurableError::WrongBinding,
    })?;
    Ok((backend, store))
}

#[cfg(unix)]
pub(crate) fn bind_current_network_namespace_with_object_sa_relocation_and_roster_recovery(
    backend: LinuxXfrmBackend,
    object_path: PathBuf,
    object_proof_key: XfrmObjectRecoveryProofKey,
    relocation_path: PathBuf,
    relocation_proof_key: XfrmSaRelocationRecoveryProofKey,
    roster_path: PathBuf,
    roster_proof_key: XfrmObjectRosterRecoveryProofKey,
) -> Result<
    (
        NamespaceBoundLinuxXfrmBackend,
        XfrmObjectInstallRecoveryStore,
        XfrmSaRelocationRecoveryStore,
        XfrmObjectRosterRecoveryStore,
    ),
    XfrmObjectRecoveryBindError,
> {
    let (backend, object_store, relocation_store, roster_store) = bind_with_capacity_and_recovery(
        backend,
        LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
        Some((object_path, object_proof_key)),
        Some((relocation_path, relocation_proof_key)),
        Some((roster_path, roster_proof_key)),
    )?;
    let object_store = object_store.ok_or(XfrmObjectRecoveryBindError::Store {
        source: XfrmObjectInstallDurableError::WrongBinding,
    })?;
    let relocation_store =
        relocation_store.ok_or(XfrmObjectRecoveryBindError::SaRelocationStore {
            source: XfrmSaRelocationDurableError::WrongBinding,
        })?;
    let roster_store = roster_store.ok_or(XfrmObjectRecoveryBindError::RosterStore {
        source: XfrmObjectRosterDurableError::WrongBinding,
    })?;
    Ok((backend, object_store, relocation_store, roster_store))
}

#[cfg(unix)]
pub(crate) fn bind_current_network_namespace_with_object_and_sa_relocation_recovery(
    backend: LinuxXfrmBackend,
    object_path: PathBuf,
    object_proof_key: XfrmObjectRecoveryProofKey,
    relocation_path: PathBuf,
    relocation_proof_key: XfrmSaRelocationRecoveryProofKey,
) -> Result<
    (
        NamespaceBoundLinuxXfrmBackend,
        XfrmObjectInstallRecoveryStore,
        XfrmSaRelocationRecoveryStore,
    ),
    XfrmObjectRecoveryBindError,
> {
    let (backend, object_store, relocation_store, _) = bind_with_capacity_and_recovery(
        backend,
        LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
        Some((object_path, object_proof_key)),
        Some((relocation_path, relocation_proof_key)),
        None,
    )?;
    let object_store = object_store.ok_or(XfrmObjectRecoveryBindError::Store {
        source: XfrmObjectInstallDurableError::WrongBinding,
    })?;
    let relocation_store =
        relocation_store.ok_or(XfrmObjectRecoveryBindError::SaRelocationStore {
            source: XfrmSaRelocationDurableError::WrongBinding,
        })?;
    Ok((backend, object_store, relocation_store))
}

#[cfg(unix)]
type DurableRecoveryBindResult = (
    NamespaceBoundLinuxXfrmBackend,
    Option<XfrmObjectInstallRecoveryStore>,
    Option<XfrmSaRelocationRecoveryStore>,
    Option<XfrmObjectRosterRecoveryStore>,
);

#[cfg(unix)]
fn bind_with_capacity_and_recovery(
    backend: LinuxXfrmBackend,
    capacity: usize,
    recovery: Option<(PathBuf, XfrmObjectRecoveryProofKey)>,
    relocation_recovery: Option<(PathBuf, XfrmSaRelocationRecoveryProofKey)>,
    roster_recovery: Option<(PathBuf, XfrmObjectRosterRecoveryProofKey)>,
) -> Result<DurableRecoveryBindResult, XfrmObjectRecoveryBindError> {
    let binding = NetworkNamespaceBinding::capture()
        .map_err(|source| XfrmObjectRecoveryBindError::Backend { source })?;
    let actor_binding = NamespaceActorBinding::new(binding);
    let backend = backend.for_namespace_actor(binding);
    let (sender, receiver) = mpsc::channel(capacity);
    let (startup_sender, startup_receiver) = std::sync::mpsc::sync_channel(1);

    let worker = std::thread::Builder::new()
        .name(String::from("opc-xfrm-netns"))
        .spawn({
            let actor_binding = actor_binding.clone();
            move || {
                run_actor(
                    backend,
                    actor_binding,
                    receiver,
                    startup_sender,
                    recovery,
                    relocation_recovery,
                    roster_recovery,
                )
            }
        })
        .map_err(|error| XfrmObjectRecoveryBindError::Backend {
            source: XfrmError::io("network_namespace_actor_spawn", error),
        })?;

    let startup = startup_receiver
        .recv()
        .map_err(|_| XfrmObjectRecoveryBindError::Backend {
            source: XfrmError::Unavailable,
        })?;
    // A JoinHandle detaches on drop. The channel lifetime is authoritative:
    // closing the final sender makes the actor drain and then exit, without a
    // potentially blocking Drop implementation.
    drop(worker);
    let (store, relocation_store, roster_store, retained_finish_runtime) = startup?;

    Ok((
        NamespaceBoundLinuxXfrmBackend {
            inner: Arc::new(NamespaceBoundLinuxXfrmBackendInner {
                sender,
                actor_binding,
                retained_finish_runtime: Some(retained_finish_runtime),
                #[cfg(test)]
                retained_finish_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }),
        },
        store,
        relocation_store,
        roster_store,
    ))
}

#[cfg(unix)]
type DurableRecoveryStartupStores = (
    Option<XfrmObjectInstallRecoveryStore>,
    Option<XfrmSaRelocationRecoveryStore>,
    Option<XfrmObjectRosterRecoveryStore>,
    tokio::runtime::Handle,
);

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn run_actor(
    backend: LinuxXfrmBackend,
    actor_binding: NamespaceActorBinding,
    mut receiver: mpsc::Receiver<NamespaceCommand>,
    startup: std::sync::mpsc::SyncSender<
        Result<DurableRecoveryStartupStores, XfrmObjectRecoveryBindError>,
    >,
    recovery: Option<(PathBuf, XfrmObjectRecoveryProofKey)>,
    relocation_recovery: Option<(PathBuf, XfrmSaRelocationRecoveryProofKey)>,
    roster_recovery: Option<(PathBuf, XfrmObjectRosterRecoveryProofKey)>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = startup.send(Err(XfrmObjectRecoveryBindError::Backend {
                source: XfrmError::io("network_namespace_actor_runtime", error),
            }));
            return;
        }
    };
    let retained_finish_runtime = runtime.handle().clone();

    if let Err(error) = backend.prepare_namespace_actor() {
        let _ = startup.send(Err(XfrmObjectRecoveryBindError::Backend { source: error }));
        return;
    }

    let mut state = NamespaceActorState::new(actor_binding);
    let namespace_binding =
        if recovery.is_some() || relocation_recovery.is_some() || roster_recovery.is_some() {
            match state.actor_binding.namespace().durable_bytes() {
                Ok(binding) => Some(binding),
                Err(source) if recovery.is_some() => {
                    let _ = startup.send(Err(XfrmObjectRecoveryBindError::Store { source }));
                    return;
                }
                // `durable_bytes` fails closed only with a missing namespace
                // identity; report that through whichever store was requested.
                Err(_) if relocation_recovery.is_some() => {
                    let _ = startup.send(Err(XfrmObjectRecoveryBindError::SaRelocationStore {
                        source: XfrmSaRelocationDurableError::WrongBinding,
                    }));
                    return;
                }
                Err(_) => {
                    let _ = startup.send(Err(XfrmObjectRecoveryBindError::RosterStore {
                        source: XfrmObjectRosterDurableError::WrongBinding,
                    }));
                    return;
                }
            }
        } else {
            None
        };
    let store = match recovery {
        Some((path, proof_key)) => {
            let Some(binding) = namespace_binding else {
                // A missing namespace binding already failed closed above;
                // this keeps the unreachable case fail-closed as well.
                let _ = startup.send(Err(XfrmObjectRecoveryBindError::Store {
                    source: XfrmObjectInstallDurableError::WrongBinding,
                }));
                return;
            };
            match XfrmObjectInstallRecoveryStore::open_bound(&path, proof_key, binding) {
                Ok(store) => {
                    state.object_recovery_store = Some(store.clone());
                    Some(store)
                }
                Err(source) => {
                    let _ = startup.send(Err(XfrmObjectRecoveryBindError::Store { source }));
                    return;
                }
            }
        }
        None => None,
    };
    let relocation_store = match relocation_recovery {
        Some((path, proof_key)) => {
            let Some(binding) = namespace_binding else {
                // A missing namespace binding already failed closed above;
                // this keeps the unreachable case fail-closed as well.
                let _ = startup.send(Err(XfrmObjectRecoveryBindError::SaRelocationStore {
                    source: XfrmSaRelocationDurableError::WrongBinding,
                }));
                return;
            };
            match XfrmSaRelocationRecoveryStore::open_bound(&path, proof_key, binding) {
                Ok(store) => {
                    state.relocation_recovery_store = Some(store.clone());
                    Some(store)
                }
                Err(source) => {
                    let _ = startup.send(Err(XfrmObjectRecoveryBindError::SaRelocationStore {
                        source,
                    }));
                    return;
                }
            }
        }
        None => None,
    };
    let roster_store = match roster_recovery {
        Some((path, proof_key)) => {
            let Some(binding) = namespace_binding else {
                // A missing namespace binding already failed closed above;
                // this keeps the unreachable case fail-closed as well.
                let _ = startup.send(Err(XfrmObjectRecoveryBindError::RosterStore {
                    source: XfrmObjectRosterDurableError::WrongBinding,
                }));
                return;
            };
            match XfrmObjectRosterRecoveryStore::open_bound(&path, proof_key, binding) {
                Ok(store) => {
                    state.roster_recovery_store = Some(store.clone());
                    Some(store)
                }
                Err(source) => {
                    let _ = startup.send(Err(XfrmObjectRecoveryBindError::RosterStore { source }));
                    return;
                }
            }
        }
        None => None,
    };
    if startup
        .send(Ok((
            store,
            relocation_store,
            roster_store,
            retained_finish_runtime,
        )))
        .is_err()
    {
        return;
    }

    runtime.block_on(async move {
        while let Some(command) = receiver.recv().await {
            command.execute(&backend, &mut state).await;
        }
    });
}

#[cfg(not(unix))]
fn run_actor(
    backend: LinuxXfrmBackend,
    actor_binding: NamespaceActorBinding,
    mut receiver: mpsc::Receiver<NamespaceCommand>,
    startup: std::sync::mpsc::SyncSender<Result<(), XfrmError>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = startup.send(Err(XfrmError::io("network_namespace_actor_runtime", error)));
            return;
        }
    };
    if let Err(error) = backend.prepare_namespace_actor() {
        let _ = startup.send(Err(error));
        return;
    }
    if startup.send(Ok(())).is_err() {
        return;
    }

    runtime.block_on(async move {
        let mut state = NamespaceActorState::new(actor_binding);
        while let Some(command) = receiver.recv().await {
            command.execute(&backend, &mut state).await;
        }
    });
}

struct NamespaceActorState {
    actor_binding: NamespaceActorBinding,
    counter_receipts: EspCounterReceiptRegistry,
    #[cfg(unix)]
    object_recovery_store: Option<XfrmObjectInstallRecoveryStore>,
    #[cfg(unix)]
    object_install_admissions: HashMap<
        (
            XfrmObjectInstallOperationId,
            XfrmObjectInstallOperationGeneration,
        ),
        Weak<()>,
    >,
    #[cfg(unix)]
    relocation_recovery_store: Option<XfrmSaRelocationRecoveryStore>,
    #[cfg(unix)]
    relocation_admissions: HashMap<
        (
            XfrmSaRelocationOperationId,
            XfrmSaRelocationOperationGeneration,
        ),
        Weak<()>,
    >,
    #[cfg(unix)]
    roster_recovery_store: Option<XfrmObjectRosterRecoveryStore>,
    #[cfg(unix)]
    roster_admissions:
        HashMap<(XfrmObjectRosterGroupId, XfrmObjectRosterOperationGeneration), Weak<()>>,
}

impl NamespaceActorState {
    fn new(actor_binding: NamespaceActorBinding) -> Self {
        Self {
            actor_binding,
            counter_receipts: EspCounterReceiptRegistry::default(),
            #[cfg(unix)]
            object_recovery_store: None,
            #[cfg(unix)]
            object_install_admissions: HashMap::new(),
            #[cfg(unix)]
            relocation_recovery_store: None,
            #[cfg(unix)]
            relocation_admissions: HashMap::new(),
            #[cfg(unix)]
            roster_recovery_store: None,
            #[cfg(unix)]
            roster_admissions: HashMap::new(),
        }
    }

    fn invalidate_counter_receipts(&mut self) {
        self.counter_receipts.invalidate_all();
    }

    #[cfg(unix)]
    fn require_object_recovery_store(
        &self,
        supplied: &XfrmObjectInstallRecoveryStore,
    ) -> Result<(), XfrmObjectInstallDurableError> {
        match &self.object_recovery_store {
            Some(bound) if bound.is_same_instance(supplied) => Ok(()),
            _ => Err(XfrmObjectInstallDurableError::WrongBinding),
        }
    }

    #[cfg(unix)]
    fn register_object_install_admission(
        &mut self,
        authority: &XfrmObjectInstallAdmissionAuthority,
    ) {
        self.object_install_admissions
            .insert(authority.key(), Arc::downgrade(&authority.seal));
    }

    #[cfg(unix)]
    fn require_object_install_admission(
        &self,
        authority: &XfrmObjectInstallAdmissionAuthority,
    ) -> Result<(), XfrmObjectInstallDurableError> {
        if self.actor_binding != authority.actor_binding {
            return Err(XfrmObjectInstallDurableError::WrongBinding);
        }
        self.require_object_recovery_store(&authority.operation.store)?;
        let Some(registered) = self.object_install_admissions.get(&authority.key()) else {
            return Err(XfrmObjectInstallDurableError::Stale);
        };
        let Some(live) = registered.upgrade() else {
            return Err(XfrmObjectInstallDurableError::Stale);
        };
        if !Arc::ptr_eq(&live, &authority.seal) {
            return Err(XfrmObjectInstallDurableError::Stale);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn admit_durable_object_install_mutation(
        &mut self,
        authority: &XfrmObjectInstallAdmissionAuthority,
    ) -> Result<(), XfrmObjectInstallDurableError> {
        self.require_object_install_admission(authority)?;
        // The object's own `Prepared -> Issuing` transition advances the
        // object-store epoch. Fence the other two durable families first so a
        // previously prepared relocation or roster authority cannot survive
        // this independently admitted kernel mutation. Both advances complete
        // before any registry is cleared.
        if let Some(store) = &self.relocation_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        }
        if let Some(store) = &self.roster_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        }
        self.object_install_admissions.remove(&authority.key());
        self.relocation_admissions.clear();
        self.roster_admissions.clear();
        self.invalidate_counter_receipts();
        Ok(())
    }

    #[cfg(unix)]
    fn admit_durable_object_install_recovery(
        &mut self,
        phase: XfrmObjectInstallDurablePhase,
    ) -> Result<(), XfrmObjectInstallDurableError> {
        if matches!(
            phase,
            XfrmObjectInstallDurablePhase::Issuing
                | XfrmObjectInstallDurablePhase::Indeterminate
                | XfrmObjectInstallDurablePhase::Acquired
                | XfrmObjectInstallDurablePhase::RemovalAdmitted
        ) {
            // These recovery phases may issue exact cleanup and carry the
            // same cross-family fencing obligation as a live run. Prepared
            // and terminal recovery are metadata-only.
            self.require_relocation_gate_open_for_install()?;
            if let Some(store) = &self.relocation_recovery_store {
                store
                    .advance_writer_epoch()
                    .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
            }
            if let Some(store) = &self.roster_recovery_store {
                store
                    .advance_writer_epoch()
                    .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
            }
            self.relocation_admissions.clear();
            self.roster_admissions.clear();
        }
        self.invalidate_counter_receipts();
        Ok(())
    }

    #[cfg(unix)]
    fn reconcile_object_install_admission(
        &mut self,
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
    ) -> Result<(), XfrmObjectInstallDurableError> {
        let key = (operation_id, operation_generation);
        let Some(registered) = self.object_install_admissions.get(&key) else {
            return Ok(());
        };
        if registered.upgrade().is_some() {
            return Err(XfrmObjectInstallDurableError::InvalidTransition);
        }
        self.object_install_admissions.remove(&key);
        Ok(())
    }

    #[cfg(unix)]
    fn require_sa_recovery_store(
        &self,
        supplied: &XfrmSaRelocationRecoveryStore,
    ) -> Result<(), XfrmSaRelocationDurableError> {
        match &self.relocation_recovery_store {
            Some(bound) if bound.is_same_instance(supplied) => Ok(()),
            _ => Err(XfrmSaRelocationDurableError::WrongBinding),
        }
    }

    #[cfg(unix)]
    fn register_sa_relocation_admission(&mut self, authority: &XfrmSaRelocationAdmissionAuthority) {
        self.relocation_admissions
            .insert(authority.key(), Arc::downgrade(&authority.seal));
    }

    #[cfg(unix)]
    fn require_sa_relocation_admission(
        &self,
        authority: &XfrmSaRelocationAdmissionAuthority,
    ) -> Result<(), XfrmSaRelocationDurableError> {
        if self.actor_binding != authority.actor_binding {
            return Err(XfrmSaRelocationDurableError::WrongBinding);
        }
        self.require_sa_recovery_store(&authority.operation.store)?;
        let Some(registered) = self.relocation_admissions.get(&authority.key()) else {
            return Err(XfrmSaRelocationDurableError::Stale);
        };
        let Some(live) = registered.upgrade() else {
            return Err(XfrmSaRelocationDurableError::Stale);
        };
        if !Arc::ptr_eq(&live, &authority.seal) {
            return Err(XfrmSaRelocationDurableError::Stale);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn admit_durable_sa_relocation_mutation(
        &mut self,
        authority: &XfrmSaRelocationAdmissionAuthority,
    ) -> Result<(), XfrmSaRelocationDurableError> {
        self.require_sa_relocation_admission(authority)?;
        // Object and roster `Prepared` records are deliberately not writer
        // gates, so either may be prepared behind one. Burn both other stores'
        // epochs before admitting the relocation and clear every live affine
        // seal; otherwise an older object or roster authority could mutate
        // after the move. Both advances complete before any registry is
        // cleared.
        if let Some(store) = &self.object_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        }
        if let Some(store) = &self.roster_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        }
        self.object_install_admissions.clear();
        self.relocation_admissions.clear();
        self.roster_admissions.clear();
        self.invalidate_counter_receipts();
        Ok(())
    }

    #[cfg(unix)]
    fn admit_durable_sa_relocation_recovery(
        &mut self,
        phase: XfrmSaRelocationDurablePhase,
    ) -> Result<(), XfrmSaRelocationDurableError> {
        if matches!(
            phase,
            XfrmSaRelocationDurablePhase::Issuing
                | XfrmSaRelocationDurablePhase::Indeterminate
                | XfrmSaRelocationDurablePhase::RemovalAdmitted
        ) {
            // These phases may remove exact residue. Prepared and terminal
            // recovery only update metadata and preserve unrelated prepared
            // object or roster authorities.
            self.require_install_gate_open_for_relocation()?;
            if let Some(store) = &self.object_recovery_store {
                store
                    .advance_writer_epoch()
                    .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
            }
            if let Some(store) = &self.roster_recovery_store {
                store
                    .advance_writer_epoch()
                    .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
            }
            self.object_install_admissions.clear();
            self.roster_admissions.clear();
        }
        self.invalidate_counter_receipts();
        Ok(())
    }

    #[cfg(unix)]
    fn reconcile_sa_relocation_admission(
        &mut self,
        operation_id: XfrmSaRelocationOperationId,
        operation_generation: XfrmSaRelocationOperationGeneration,
    ) -> Result<(), XfrmSaRelocationDurableError> {
        let key = (operation_id, operation_generation);
        let Some(registered) = self.relocation_admissions.get(&key) else {
            return Ok(());
        };
        if registered.upgrade().is_some() {
            return Err(XfrmSaRelocationDurableError::InvalidTransition);
        }
        self.relocation_admissions.remove(&key);
        Ok(())
    }

    #[cfg(unix)]
    fn require_object_roster_store(
        &self,
        supplied: &XfrmObjectRosterRecoveryStore,
    ) -> Result<(), XfrmObjectRosterDurableError> {
        match &self.roster_recovery_store {
            Some(bound) if bound.is_same_instance(supplied) => Ok(()),
            _ => Err(XfrmObjectRosterDurableError::WrongBinding),
        }
    }

    #[cfg(unix)]
    fn register_object_roster_admission(&mut self, authority: &XfrmObjectRosterAdmissionAuthority) {
        self.roster_admissions
            .insert(authority.key(), Arc::downgrade(&authority.seal));
    }

    #[cfg(unix)]
    fn register_object_roster_effect_quiesced(&mut self, effect: &XfrmObjectRosterEffectQuiesced) {
        self.roster_admissions
            .insert(effect.key(), Arc::downgrade(&effect.seal));
    }

    #[cfg(unix)]
    fn require_object_roster_admission(
        &self,
        authority: &XfrmObjectRosterAdmissionAuthority,
    ) -> Result<(), XfrmObjectRosterDurableError> {
        if self.actor_binding != authority.actor_binding {
            return Err(XfrmObjectRosterDurableError::WrongBinding);
        }
        self.require_object_roster_store(&authority.operation.store)?;
        let Some(registered) = self.roster_admissions.get(&authority.key()) else {
            return Err(XfrmObjectRosterDurableError::Stale);
        };
        let Some(live) = registered.upgrade() else {
            return Err(XfrmObjectRosterDurableError::Stale);
        };
        if !Arc::ptr_eq(&live, &authority.seal) {
            return Err(XfrmObjectRosterDurableError::Stale);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn require_object_roster_effect_quiesced(
        &self,
        effect: &XfrmObjectRosterEffectQuiesced,
    ) -> Result<(), XfrmObjectRosterDurableError> {
        if self.actor_binding != effect.actor_binding {
            return Err(XfrmObjectRosterDurableError::WrongBinding);
        }
        self.require_object_roster_store(&effect.operation.store)?;
        let Some(registered) = self.roster_admissions.get(&effect.key()) else {
            return Err(XfrmObjectRosterDurableError::Stale);
        };
        let Some(live) = registered.upgrade() else {
            return Err(XfrmObjectRosterDurableError::Stale);
        };
        if !Arc::ptr_eq(&live, &effect.seal) {
            return Err(XfrmObjectRosterDurableError::Stale);
        }
        Ok(())
    }

    #[cfg(unix)]
    fn admit_durable_object_roster_mutation(
        &mut self,
        authority: &XfrmObjectRosterAdmissionAuthority,
    ) -> Result<(), XfrmObjectRosterDurableError> {
        self.require_object_roster_admission(authority)?;
        // The roster's own single `Prepared -> Issuing` transition advances the
        // roster-store epoch. Fence the other two durable families first so a
        // previously prepared install or relocation authority cannot survive
        // this independently admitted group of kernel mutations. Both advances
        // complete before any registry is cleared, and only this roster's own
        // key leaves the roster registry: a sibling prepared roster is fenced
        // by the store's unresolved gate, not by seal invalidation.
        if let Some(store) = &self.object_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        }
        if let Some(store) = &self.relocation_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        }
        self.roster_admissions.remove(&authority.key());
        self.object_install_admissions.clear();
        self.relocation_admissions.clear();
        self.invalidate_counter_receipts();
        Ok(())
    }

    #[cfg(unix)]
    fn admit_durable_object_roster_recovery(
        &mut self,
        phase: XfrmObjectRosterDurablePhase,
    ) -> Result<(), XfrmObjectRosterDurableError> {
        if matches!(
            phase,
            XfrmObjectRosterDurablePhase::Issuing
                | XfrmObjectRosterDurablePhase::Applied
                | XfrmObjectRosterDurablePhase::Compensating
        ) {
            // These recovery phases may issue exact per-member cleanup and
            // carry the same cross-family fencing obligation as a live run.
            // Prepared and terminal recovery are metadata-only.
            self.require_install_gate_open_for_roster()?;
            self.require_relocation_gate_open_for_roster()?;
            if let Some(store) = &self.object_recovery_store {
                store
                    .advance_writer_epoch()
                    .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
            }
            if let Some(store) = &self.relocation_recovery_store {
                store
                    .advance_writer_epoch()
                    .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
            }
            self.object_install_admissions.clear();
            self.relocation_admissions.clear();
        }
        self.invalidate_counter_receipts();
        Ok(())
    }

    #[cfg(unix)]
    fn reconcile_object_roster_admission(
        &mut self,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
    ) -> Result<(), XfrmObjectRosterDurableError> {
        let key = (group_id, generation);
        let Some(registered) = self.roster_admissions.get(&key) else {
            return Ok(());
        };
        if registered.upgrade().is_some() {
            return Err(XfrmObjectRosterDurableError::InvalidTransition);
        }
        self.roster_admissions.remove(&key);
        Ok(())
    }

    /// Cross-family cooperating-writer gate: object installs are rejected
    /// while the relocation store (when bound) retains any unresolved
    /// `Prepared`, `Issuing`, `Indeterminate`, or `RemovalAdmitted` record, or
    /// the roster store (when bound) retains any unresolved `Issuing`,
    /// `Applied`, or `Compensating` roster.
    ///
    /// The per-family unresolved predicate stays authoritative on each side:
    /// the three families disagree deliberately about whether `Prepared`
    /// gates, and that asymmetry lives inside each store, never here.
    #[cfg(unix)]
    fn require_relocation_gate_open_for_install(
        &self,
    ) -> Result<(), XfrmObjectInstallDurableError> {
        if let Some(store) = &self.relocation_recovery_store {
            let unresolved = store
                .has_unresolved_writer_authority()
                .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
            if unresolved {
                return Err(XfrmObjectInstallDurableError::InvalidTransition);
            }
        }
        if let Some(store) = &self.roster_recovery_store {
            let unresolved = store
                .has_unresolved_writer_authority()
                .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
            if unresolved {
                return Err(XfrmObjectInstallDurableError::InvalidTransition);
            }
        }
        Ok(())
    }

    /// Cross-family cooperating-writer gate: SA relocations are rejected
    /// while the object install store (when bound) retains any unresolved
    /// `Issuing`, `Indeterminate`, `Acquired`, or `RemovalAdmitted` record, or
    /// the roster store (when bound) retains any unresolved `Issuing`,
    /// `Applied`, or `Compensating` roster.
    #[cfg(unix)]
    fn require_install_gate_open_for_relocation(&self) -> Result<(), XfrmSaRelocationDurableError> {
        if let Some(store) = &self.object_recovery_store {
            let unresolved = store
                .has_unresolved_writer_authority()
                .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
            if unresolved {
                return Err(XfrmSaRelocationDurableError::InvalidTransition);
            }
        }
        if let Some(store) = &self.roster_recovery_store {
            let unresolved = store
                .has_unresolved_writer_authority()
                .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
            if unresolved {
                return Err(XfrmSaRelocationDurableError::InvalidTransition);
            }
        }
        Ok(())
    }

    /// Cross-family cooperating-writer gate: grouped rosters are rejected
    /// while the object install store (when bound) retains any unresolved
    /// `Issuing`, `Indeterminate`, `Acquired`, or `RemovalAdmitted` record.
    #[cfg(unix)]
    fn require_install_gate_open_for_roster(&self) -> Result<(), XfrmObjectRosterDurableError> {
        if let Some(store) = &self.object_recovery_store {
            let unresolved = store
                .has_unresolved_writer_authority()
                .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
            if unresolved {
                return Err(XfrmObjectRosterDurableError::InvalidTransition);
            }
        }
        Ok(())
    }

    /// Cross-family cooperating-writer gate: grouped rosters are rejected
    /// while the relocation store (when bound) retains any unresolved
    /// `Prepared`, `Issuing`, `Indeterminate`, or `RemovalAdmitted` record.
    #[cfg(unix)]
    fn require_relocation_gate_open_for_roster(&self) -> Result<(), XfrmObjectRosterDurableError> {
        if let Some(store) = &self.relocation_recovery_store {
            let unresolved = store
                .has_unresolved_writer_authority()
                .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
            if unresolved {
                return Err(XfrmObjectRosterDurableError::InvalidTransition);
            }
        }
        Ok(())
    }

    /// Same-family cooperating-writer gate: a grouped roster is rejected while
    /// a SIBLING roster in the same store is still `Issuing`, `Applied`, or
    /// `Compensating`.
    ///
    /// The store enforces this too, inside `Prepared -> Issuing`, but it does
    /// so after admission has already been consumed and after the other two
    /// families were fenced. Screening it here keeps a sibling block what it
    /// is — a transient rejection that consumes nothing and can succeed later.
    /// It cannot false-positive on the roster being run: that roster is
    /// `Prepared`, and `Prepared` is never an unresolved writer authority, so
    /// a true answer always names some other roster.
    #[cfg(unix)]
    fn require_roster_gate_open_for_roster(&self) -> Result<(), XfrmObjectRosterDurableError> {
        if let Some(store) = &self.roster_recovery_store {
            let unresolved = store
                .has_unresolved_writer_authority()
                .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
            if unresolved {
                return Err(XfrmObjectRosterDurableError::InvalidTransition);
            }
        }
        Ok(())
    }

    fn admit_xfrm_mutation(&mut self) -> Result<(), XfrmError> {
        // Three-part invariant for an ordinary, independently admitted
        // namespace mutation across every bound durable family:
        //
        // (i)   epoch advancement is monotone and only ever invalidates, so a
        //       partial advance can never leave any family less fenced than it
        //       was before this call;
        // (ii)  the admission registries are cleared only after EVERY advance
        //       succeeds, so an authority that survives a rejected advance is
        //       still fenced at the store level by its now-stale epoch;
        // (iii) no kernel effect proceeds unless every bound store's epoch
        //       advance succeeded.
        //
        // Together these make an early rejection safe: the mutation does not
        // happen, the surviving authorities stay cross-gated on the family
        // whose store refused, and the extra epoch burns only fence harder.
        #[cfg(unix)]
        if let Some(store) = &self.object_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmError::Unavailable)?;
        }
        #[cfg(unix)]
        if let Some(store) = &self.relocation_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmError::Unavailable)?;
        }
        #[cfg(unix)]
        if let Some(store) = &self.roster_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmError::Unavailable)?;
        }
        #[cfg(unix)]
        {
            self.object_install_admissions.clear();
            self.relocation_admissions.clear();
            self.roster_admissions.clear();
        }
        self.invalidate_counter_receipts();
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum LostReply {
    Mutation(&'static str),
    ReadOnly,
}

impl LostReply {
    fn error(self) -> XfrmError {
        match self {
            Self::Mutation(operation) => XfrmError::StateIndeterminate { operation },
            Self::ReadOnly => XfrmError::Unavailable,
        }
    }
}

impl NamespaceBoundLinuxXfrmBackend {
    /// Return the actor's captured namespace binding to crate-internal sealed
    /// authorities without exposing device or inode values publicly.
    pub(crate) fn network_namespace_binding(&self) -> NetworkNamespaceBinding {
        self.inner.actor_binding.namespace()
    }

    pub(crate) fn namespace_actor_binding(&self) -> NamespaceActorBinding {
        self.inner.actor_binding.clone()
    }

    /// Activate retained fixed-DSCP configuration on this namespace actor.
    ///
    /// Deferred construction and namespace binding perform no DSCP runtime
    /// effects. This method serially loads/adopts and attaches the companion
    /// on the same actor that owns XFRM and durable-recovery operations. A
    /// successful activation is idempotent: later calls return success without
    /// repeating runtime activation. Failure does not publish readiness, so a
    /// proved-clean failure can be retried on this same backend.
    ///
    /// Cancellation before the actor can deliver success also leaves the
    /// readiness gate closed. Runtime state created by an interrupted attempt
    /// is never treated as authority; a later call must revalidate or adopt it
    /// before DSCP-bearing SA mutations are admitted.
    pub async fn activate_dscp_marking(&self) -> Result<(), XfrmError> {
        let permit = self
            .inner
            .sender
            .reserve()
            .await
            .map_err(|_| XfrmError::Unavailable)?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        let (observed_sender, observed_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::ActivateDscpMarking {
            reply: reply_sender,
            observed: observed_receiver,
        });
        reply_receiver
            .await
            .map_err(|_| XfrmError::StateIndeterminate {
                operation: "activate_dscp_marking",
            })??;
        // There is deliberately no await between observing success and
        // acknowledging it. The actor retains its FIFO slot until this send,
        // so a cancelled observer cannot publish readiness and a later marked
        // mutation cannot overtake publication.
        observed_sender
            .send(())
            .map_err(|_| XfrmError::StateIndeterminate {
                operation: "activate_dscp_marking",
            })?;
        Ok(())
    }

    /// Durably prepare one create-exclusive object install without admitting
    /// its backend effect.
    ///
    /// The returned affine authority is created only after authenticated
    /// `Prepared` truth is durable. The consumer must commit its own poll-
    /// admitted transition before passing the authority to
    /// [`Self::run_durable_object_install`]. Duplicate preparation fails
    /// closed and never remints authority for an existing record.
    #[cfg(unix)]
    pub async fn prepare_durable_object_install(
        &self,
        store: &XfrmObjectInstallRecoveryStore,
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
        request: XfrmObjectInstallRequest,
    ) -> Result<XfrmObjectInstallAdmissionAuthority, XfrmObjectInstallDurableError> {
        let operation = DurableObjectOperation {
            store: store.clone(),
            operation_id,
            operation_generation,
            request,
        };
        self.dispatch_durable(|reply| {
            NamespaceCommand::PrepareDurableObjectInstall(Box::new(operation), reply)
        })
        .await
    }

    /// Consume prepared authority and run its actor-serialized external effect.
    ///
    /// A deferred DSCP activation gate is checked before authority or durable
    /// state is consumed. [`XfrmObjectInstallRunError::into_retry_authority`]
    /// returns that exact authority so the caller can activate this actor and
    /// retry without reminting admission.
    ///
    /// The exact current `Prepared` record is authenticated and transitioned
    /// durably to `Issuing` before the backend is invoked. The authority is
    /// consumed even when admission fails closed; callers reconcile retained
    /// durable state rather than replaying it.
    /// The returned terminal outcome is published durably before it becomes
    /// visible to the caller. An acquired outcome blocks all later cooperating
    /// namespace mutations until it is explicitly finalized or recovered.
    #[cfg(unix)]
    pub async fn run_durable_object_install(
        &self,
        authority: XfrmObjectInstallAdmissionAuthority,
    ) -> Result<XfrmObjectInstallDurableOutcome, XfrmObjectInstallRunError> {
        if authority.actor_binding != self.inner.actor_binding {
            return Err(XfrmObjectInstallDurableError::WrongBinding.into());
        }
        let permit =
            self.inner.sender.reserve().await.map_err(|_| {
                XfrmObjectInstallRunError::from(XfrmObjectInstallDurableError::Storage)
            })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::RunDurableObjectInstall(
            Box::new(authority),
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| XfrmObjectInstallRunError::from(XfrmObjectInstallDurableError::Storage))?
    }

    /// Crash-detector seam: consume a prepared authority and leave the durable
    /// record at `Issuing` without any terminal publication.
    ///
    /// This reproduces, deterministically, the exact crash window that
    /// [`Self::run_durable_object_install`] would leave if the process died
    /// between the `Issuing` publication and its terminal record. It performs
    /// the same validation, deferred-DSCP gate, pre-effect readback, and
    /// admission consumption as the run path. When `admit_backend_effect` is
    /// true the install is additionally admitted (as the real effect is), so
    /// the kernel object exists while the record remains `Issuing`; when false
    /// the backend is never touched. The record stays unresolved and
    /// recoverable. This grants no deletion authority and exists solely so
    /// privileged process-loss detectors can exercise `Issuing` reconciliation
    /// against the real kernel. The returned handle authenticates the exact
    /// cut phase across the detector's process restart.
    #[cfg(unix)]
    #[doc(hidden)]
    pub async fn detector_cut_prepared_issuing(
        &self,
        authority: XfrmObjectInstallAdmissionAuthority,
        admit_backend_effect: bool,
    ) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallRunError> {
        if authority.actor_binding != self.inner.actor_binding {
            return Err(XfrmObjectInstallDurableError::WrongBinding.into());
        }
        let permit =
            self.inner.sender.reserve().await.map_err(|_| {
                XfrmObjectInstallRunError::from(XfrmObjectInstallDurableError::Storage)
            })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::DetectorCutPrepared(
            Box::new(authority),
            DetectorPreparedCut::Issuing {
                admit_backend_effect,
            },
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| XfrmObjectInstallRunError::from(XfrmObjectInstallDurableError::Storage))?
    }

    /// Crash-detector seam: consume a prepared authority, admit the backend
    /// effect, and leave the authenticated durable record at `Indeterminate`.
    ///
    /// This is the process-loss counterpart to an install whose backend reply
    /// cannot be trusted. It follows the production validation, pre-effect
    /// proof, writer-epoch, and admission path, then deliberately stops before
    /// reconciliation. The returned handle authenticates the cut phase for a
    /// privileged restart detector.
    #[cfg(unix)]
    #[doc(hidden)]
    pub async fn detector_cut_prepared_indeterminate_after_effect(
        &self,
        authority: XfrmObjectInstallAdmissionAuthority,
    ) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallRunError> {
        if authority.actor_binding != self.inner.actor_binding {
            return Err(XfrmObjectInstallDurableError::WrongBinding.into());
        }
        let permit =
            self.inner.sender.reserve().await.map_err(|_| {
                XfrmObjectInstallRunError::from(XfrmObjectInstallDurableError::Storage)
            })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::DetectorCutPrepared(
            Box::new(authority),
            DetectorPreparedCut::IndeterminateAfterEffect,
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| XfrmObjectInstallRunError::from(XfrmObjectInstallDurableError::Storage))?
    }

    /// Crash-detector seam: leave an authenticated acquired operation at
    /// `RemovalAdmitted`, optionally after issuing its exact deletion.
    ///
    /// This models process loss during durable removal. The operation remains
    /// the only cleanup authority and continues to gate cooperating writers;
    /// restart recovery must retry the exact delete or confirm absence before
    /// retiring it.
    #[cfg(unix)]
    #[doc(hidden)]
    pub async fn detector_cut_acquired_removal_admitted(
        &self,
        store: &XfrmObjectInstallRecoveryStore,
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
        request: XfrmObjectInstallRequest,
        admit_backend_effect: bool,
    ) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError> {
        let permit = self
            .inner
            .sender
            .reserve()
            .await
            .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::DetectorCutAcquiredRemovalAdmitted(
            Box::new(DurableObjectOperation {
                store: store.clone(),
                operation_id,
                operation_generation,
                request,
            }),
            admit_backend_effect,
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| XfrmObjectInstallDurableError::Storage)?
    }

    /// Surrender durable cleanup authority after the product has adopted an
    /// acquired object, or retire an explicit no-mutation result.
    #[cfg(unix)]
    pub async fn finalize_durable_object_install(
        &self,
        store: &XfrmObjectInstallRecoveryStore,
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
        request: XfrmObjectInstallRequest,
    ) -> Result<XfrmObjectInstallDurablePhase, XfrmObjectInstallDurableError> {
        let operation = DurableObjectOperation {
            store: store.clone(),
            operation_id,
            operation_generation,
            request,
        };
        self.dispatch_durable(|reply| {
            NamespaceCommand::FinalizeDurableObjectInstall(Box::new(operation), reply)
        })
        .await
    }

    /// Reconcile one retained durable operation after process loss.
    ///
    /// An authenticated, epoch-current acquired record authorizes exact
    /// deletion. An `Issuing` or `Indeterminate` record can authorize deletion
    /// only when its durable pre-effect proof witnessed exact absence and a
    /// fresh exact readback now proves presence under the same writer gate.
    /// Prepared, explicit no-mutation, stale, malformed, mismatched, and
    /// pre-effect-conflict records never authorize deletion.
    #[cfg(unix)]
    pub async fn recover_durable_object_install(
        &self,
        store: &XfrmObjectInstallRecoveryStore,
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
        request: XfrmObjectInstallRequest,
    ) -> Result<XfrmObjectInstallRestartOutcome, XfrmObjectInstallDurableError> {
        let operation = DurableObjectOperation {
            store: store.clone(),
            operation_id,
            operation_generation,
            request,
        };
        self.dispatch_durable(|reply| {
            NamespaceCommand::RecoverDurableObjectInstall(Box::new(operation), reply)
        })
        .await
    }

    /// Durably prepare one exact SA relocation without admitting its backend
    /// effect.
    ///
    /// The returned affine authority is created only after authenticated
    /// `Prepared` truth is durable. The consumer must commit its own poll-
    /// admitted transition before passing the authority to
    /// [`Self::run_durable_sa_relocation`]. Duplicate preparation fails
    /// closed and never remints authority for an existing record. A prepared
    /// relocation keeps the namespace-wide writer gate closed until it is
    /// recovered or admitted, and preparation is itself rejected while any
    /// durable install or relocation record remains unresolved.
    ///
    /// After a terminal `Relocated` proof, a re-preparation with the same
    /// operation identity and generation succeeds: terminal records are
    /// pruned by preparation, so the replay is not stopped by prepare-time
    /// correlation. A replayed run is then stopped by the pre-effect
    /// witness, which reports a value-free current-state mismatch because
    /// the bound old identity no longer matches the kernel — mirroring the
    /// released install boundary.
    #[cfg(unix)]
    pub async fn prepare_sa_relocation(
        &self,
        store: &XfrmSaRelocationRecoveryStore,
        operation_id: XfrmSaRelocationOperationId,
        operation_generation: XfrmSaRelocationOperationGeneration,
        request: RelocateSaRequest,
    ) -> Result<XfrmSaRelocationAdmissionAuthority, XfrmSaRelocationDurableError> {
        let operation = DurableSaRelocationOperation {
            store: store.clone(),
            operation_id,
            operation_generation,
            request,
        };
        self.dispatch_sa_relocation_durable(|reply| {
            NamespaceCommand::PrepareSaRelocation(Box::new(operation), reply)
        })
        .await
    }

    /// Consume prepared relocation authority and run its actor-serialized
    /// external effect.
    ///
    /// After the deferred DSCP gate, the actor performs exact readbacks of
    /// the old and target identities and embeds the witnessed target
    /// disposition as a durable pre-effect proof in the same authenticated
    /// record, then publishes `Issuing`, and only then admits the effect. The
    /// method durably publishes `Relocated`, `NoMutation`, or `Indeterminate`
    /// before returning its outcome. Pre-consumption rejections return the
    /// same authenticated authority and retain `Prepared` for an exact retry
    /// when they are proved and deterministic: a deferred DSCP activation
    /// gate, a present target identity, and an untrustworthy pre-effect
    /// readback. A mismatching current state consumes the authority under a
    /// value-free label; the retained `Prepared` record recovers as
    /// authoritative no-mutation.
    ///
    /// The authority is consumed even when admission fails closed; callers
    /// reconcile retained durable state rather than replaying it. The
    /// returned terminal outcome is published durably before it becomes
    /// visible to the caller. An unresolved relocation record blocks all
    /// later cooperating namespace mutations until it is recovered.
    #[cfg(unix)]
    pub async fn run_durable_sa_relocation(
        &self,
        authority: XfrmSaRelocationAdmissionAuthority,
    ) -> Result<XfrmSaRelocationDurableOutcome, XfrmSaRelocationRunError> {
        if authority.actor_binding != self.inner.actor_binding {
            return Err(XfrmSaRelocationDurableError::WrongBinding.into());
        }
        let permit =
            self.inner.sender.reserve().await.map_err(|_| {
                XfrmSaRelocationRunError::from(XfrmSaRelocationDurableError::Storage)
            })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::RunDurableSaRelocation(
            Box::new(authority),
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| XfrmSaRelocationRunError::from(XfrmSaRelocationDurableError::Storage))?
    }

    /// Reconcile one retained durable relocation after process loss.
    ///
    /// A prepared record is retired as authoritative no-mutation. Terminal
    /// `Relocated` and `StateAbsent` proofs are returned idempotently and never
    /// authorize deletion. Unresolved `Issuing`/`Indeterminate` records are
    /// classified from their pre-effect proof plus fresh exact readbacks;
    /// only a proved owned residue is removed, through the exact target
    /// deletion identity. Absent state never claims no mutation. Unreadable
    /// readbacks keep the record unresolved; stale epochs or missing or
    /// inconsistent proofs keep it gating for repair.
    ///
    /// Idempotent recovery of a terminal phase holds only until the next
    /// cooperating write prunes the terminal record; once pruned, the
    /// correlation is unknown to the store and restore fails
    /// [`XfrmSaRelocationDurableError::NotFound`].
    #[cfg(unix)]
    pub async fn recover_durable_sa_relocation(
        &self,
        store: &XfrmSaRelocationRecoveryStore,
        operation_id: XfrmSaRelocationOperationId,
        operation_generation: XfrmSaRelocationOperationGeneration,
        request: RelocateSaRequest,
    ) -> Result<XfrmSaRelocationRestartOutcome, XfrmSaRelocationDurableError> {
        let operation = DurableSaRelocationOperation {
            store: store.clone(),
            operation_id,
            operation_generation,
            request,
        };
        self.dispatch_sa_relocation_durable(|reply| {
            NamespaceCommand::RecoverSaRelocation(Box::new(operation), reply)
        })
        .await
    }

    /// Crash-detector seam: consume a prepared relocation authority and leave
    /// the durable record at `Issuing` without any terminal publication.
    ///
    /// This reproduces, deterministically, the exact crash window that
    /// [`Self::run_durable_sa_relocation`] would leave if the process died
    /// between the `Issuing` publication and its terminal record. It performs
    /// the same validation, deferred-DSCP gate, pre-effect readbacks, and
    /// admission consumption as the run path. When `admit_backend_effect` is
    /// true the relocation is additionally admitted (as the real effect is),
    /// so the kernel state moved while the record remains `Issuing`; when
    /// false the backend is never touched. The record stays unresolved and
    /// recoverable. This grants no deletion authority and exists solely so
    /// privileged process-loss detectors can exercise `Issuing`
    /// reconciliation against the real kernel.
    #[cfg(unix)]
    #[doc(hidden)]
    pub async fn detector_cut_prepared_sa_relocation_issuing(
        &self,
        authority: XfrmSaRelocationAdmissionAuthority,
        admit_backend_effect: bool,
    ) -> Result<(), XfrmSaRelocationRunError> {
        if authority.actor_binding != self.inner.actor_binding {
            return Err(XfrmSaRelocationDurableError::WrongBinding.into());
        }
        let permit =
            self.inner.sender.reserve().await.map_err(|_| {
                XfrmSaRelocationRunError::from(XfrmSaRelocationDurableError::Storage)
            })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::DetectorCutSaRelocationIssuing(
            Box::new(authority),
            admit_backend_effect,
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| XfrmSaRelocationRunError::from(XfrmSaRelocationDurableError::Storage))?
    }

    /// Durably prepare one grouped, dependency-ordered object roster without
    /// admitting any member's backend effect.
    ///
    /// The whole ordered group becomes ONE durable record, so a consumer that
    /// must apply several XFRM objects for a single IKEv2 Child SA pays one
    /// prepare, one run, and one finalize instead of one lifecycle per object.
    /// The returned affine authority is created only after authenticated
    /// `Prepared` truth is durable. The consumer must commit its own
    /// poll-admitted transition before passing the authority to
    /// [`Self::run_durable_object_roster`]. Duplicate preparation of the same
    /// group identity and generation fails closed and never remints authority
    /// for an existing record.
    ///
    /// A `Prepared` roster has no effects and recovers as authoritative
    /// no-mutation, so it does not itself fence cooperating writers. It is
    /// nonetheless invalidated by any independently admitted actor mutation,
    /// and preparation is rejected while a durable install or relocation
    /// record remains unresolved.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::WrongBinding`] when the store is
    /// not the one leased by this actor,
    /// [`XfrmObjectRosterDurableError::InvalidTransition`] while another
    /// durable family is unresolved,
    /// [`XfrmObjectRosterDurableError::Duplicate`] for a repeated preparation,
    /// and any authentication or storage failure.
    #[cfg(unix)]
    pub async fn prepare_durable_object_roster(
        &self,
        store: &XfrmObjectRosterRecoveryStore,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: XfrmObjectRosterRequest,
    ) -> Result<XfrmObjectRosterAdmissionAuthority, XfrmObjectRosterDurableError> {
        let operation = DurableObjectRosterOperation {
            store: store.clone(),
            group_id,
            generation,
            roster,
        };
        self.dispatch_object_roster_durable(|reply| {
            NamespaceCommand::PrepareDurableObjectRoster(Box::new(operation), reply)
        })
        .await
    }

    /// Consume prepared roster authority and apply the whole ordered group as
    /// one actor-serialized transaction.
    ///
    /// This is a single actor command and a single queue permit regardless of
    /// arity. The actor validates the authority, runs the deferred-DSCP
    /// preflight for every SA member, sweeps every member's exact identity,
    /// burns the roster's one writer epoch on `Prepared -> Issuing`, then
    /// applies members in the caller-declared order, publishing each member's
    /// adjacent absence proof BEFORE its effect. Any member result other than
    /// a clean acquisition diverts the whole group: a conflict proved before
    /// any effect terminates as `NoMutation` with zero backend calls, and a
    /// failure after at least one acquisition reverse-compensates the acquired
    /// prefix and terminates as `RolledBack`.
    ///
    /// `AlreadyExists` from a member install under an `Absent` adjacent proof
    /// records that member as no-mutation and FAILS the roster, deliberately
    /// diverging from the single-object family's `AlreadyExists` success
    /// semantics. A dependency-ordered Child SA roster must not report success
    /// when one leg is a foreign object of unknown parameters: RFC 7296
    /// sections 1.3 and 2.8 give partial Child SA installation no wire
    /// representation, and RFC 4301 section 4.4 treats the SPD and SAD entries
    /// of one protected flow as a single consistent unit. The foreign object is
    /// never deleted.
    ///
    /// # Proved-clean rejections
    ///
    /// Three rejections prove that no member effect was admitted and no roster
    /// phase or roster writer epoch changed: a closed cooperating-writer gate
    /// (`xfrm_object_roster_gated`), a still-closed deferred DSCP activation
    /// gate, and a pre-effect sweep readback that could not be trusted. All
    /// three return the exact affine authority through
    /// [`XfrmObjectRosterRunError::into_retry_authority`], so the same
    /// authority can be retried without reminting.
    ///
    /// A gated rejection is screened before anything at all is consumed: the
    /// admission seal is never removed and no sibling family is fenced, which
    /// is what makes "run me again once the blocking writer resolves" true
    /// rather than aspirational. It covers an unresolved single-object install,
    /// an unresolved SA relocation, AND an unresolved sibling roster in this
    /// same store.
    ///
    /// A returned authority must be retried or dropped promptly: while it is
    /// held, its live admission seal defers `recover_durable_object_roster`
    /// and `adopt_durable_object_roster` for that group with
    /// `InvalidTransition`, exactly like any other live authority.
    ///
    /// The DSCP and sweep rejections happen later. The sweep in particular runs
    /// inside the admitted command rather than ahead of admission consumption,
    /// so a sweep rejection has already fenced the other durable families and
    /// the actor re-registers the admission seal before returning; that fencing
    /// is monotone and only ever invalidates, and the roster's own durable
    /// state is untouched. Every other failure consumes the authority under the
    /// durable protocol's existing fail-closed recovery contract.
    ///
    /// # Deadlines
    ///
    /// The SDK imposes no deadline of its own. The whole point of a roster is
    /// that it collapses N consumer deadline scopes into one, so a caller times
    /// the group, not the members. A caller-side timeout does NOT stop the
    /// actor: once admitted, the command runs to a durable terminal record even
    /// if the observing future is dropped. The correct action after a
    /// caller-side timeout is therefore [`Self::adopt_durable_object_roster`]
    /// or [`Self::recover_durable_object_roster`], never a replay.
    ///
    /// # Migration
    ///
    /// An unresolved roster fences single-object durable installs and durable
    /// SA relocations, and an unresolved install or relocation fences rosters.
    /// A consumer migrating to rosters should bind all three stores and use
    /// either one roster or the equivalent single-object operations per Child
    /// SA, never both interleaved for the same Child SA.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterRunError`]; use
    /// [`XfrmObjectRosterRunError::into_retry_authority`] to distinguish the
    /// three proved-clean rejections from the durable-protocol failures.
    #[cfg(unix)]
    pub async fn run_durable_object_roster(
        &self,
        authority: XfrmObjectRosterAdmissionAuthority,
    ) -> Result<XfrmObjectRosterDurableOutcome, XfrmObjectRosterRunError> {
        if authority.actor_binding != self.inner.actor_binding {
            return Err(XfrmObjectRosterDurableError::WrongBinding.into());
        }
        let permit =
            self.inner.sender.reserve().await.map_err(|_| {
                XfrmObjectRosterRunError::from(XfrmObjectRosterDurableError::Storage)
            })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::RunDurableObjectRoster(
            Box::new(authority),
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| XfrmObjectRosterRunError::from(XfrmObjectRosterDurableError::Storage))?
    }

    /// Apply every member effect and return before the final `Applied`
    /// publication.
    ///
    /// This opt-in variant has the same admission, sweep, writer-epoch, and
    /// per-member adjacent-proof protocol as [`Self::run_durable_object_roster`].
    /// It stops only after all effects have acknowledged success: for a
    /// five-member roster, the returned token follows the six durable
    /// publications `Prepared`, `Issuing/member0`, and the four adjacent
    /// acquire-plus-next-absent transitions.  The token may be held while the
    /// product activates its response; only then pass it to
    /// [`Self::finish_durable_object_roster_effect_quiesced`] to publish
    /// `Applied`.
    ///
    /// A dropped token is intentionally not auto-completed.  Its final member
    /// remains at the adjacent `Absent` witness, so normal recovery performs
    /// the exact same reconciliation and rollback it would after a process
    /// crash at that point.  While the token is live, the actor keeps recovery
    /// for this group quiesced and the unresolved roster keeps cooperating
    /// XFRM mutations fenced.
    ///
    /// # Errors
    ///
    /// Returns the same proved-clean retry errors as
    /// [`Self::run_durable_object_roster`].  After any durable issuance step,
    /// the authority is consumed and recovery—not replay—is authoritative.
    #[cfg(unix)]
    pub async fn run_durable_object_roster_effect_quiesced(
        &self,
        authority: XfrmObjectRosterAdmissionAuthority,
    ) -> Result<XfrmObjectRosterEffectQuiesced, XfrmObjectRosterRunError> {
        if authority.actor_binding != self.inner.actor_binding {
            return Err(XfrmObjectRosterDurableError::WrongBinding.into());
        }
        let permit =
            self.inner.sender.reserve().await.map_err(|_| {
                XfrmObjectRosterRunError::from(XfrmObjectRosterDurableError::Storage)
            })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::RunDurableObjectRosterEffectQuiesced(
            Box::new(authority),
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| XfrmObjectRosterRunError::from(XfrmObjectRosterDurableError::Storage))?
    }

    /// Consume one all-effects-quiesced token and durably publish `Applied`.
    ///
    /// The operation performs no kernel call and no request replay.  It is the
    /// post-response bookkeeping step for
    /// [`Self::run_durable_object_roster_effect_quiesced`]; product code should
    /// supervise it after response activation, then use the existing finalize
    /// API after its own ownership/adoption bookkeeping is durable.
    ///
    /// Dropping an unpolled future drops the token normally and leaves the
    /// `Issuing` record to exact recovery. Once this future is first polled
    /// with the right actor binding, it moves the token into a retained task on
    /// the namespace actor's runtime before waiting for the bounded command
    /// permit. Cancelling the caller then loses only the response observer: the
    /// retained task still obtains one normal permit and submits this exact
    /// finish command. This guarantee is limited to caller cancellation while
    /// the namespace actor runtime remains alive; runtime termination or a
    /// process crash leaves the durable `Issuing` record for the established
    /// recovery protocol.
    #[cfg(unix)]
    pub async fn finish_durable_object_roster_effect_quiesced(
        &self,
        effect: XfrmObjectRosterEffectQuiesced,
    ) -> Result<XfrmObjectRosterDurableOutcome, XfrmObjectRosterDurableError> {
        if effect.actor_binding != self.inner.actor_binding {
            return Err(XfrmObjectRosterDurableError::WrongBinding);
        }
        let Some(runtime) = &self.inner.retained_finish_runtime else {
            return Err(XfrmObjectRosterDurableError::Storage);
        };
        // Spawning is synchronous: after the first poll of this method the
        // child owns the affine token before this observer can await or be
        // cancelled. Dropping this JoinHandle detaches the child, which still
        // waits for the same bounded permit and sends the same actor command.
        let retained = runtime.spawn(finish_object_roster_effect_quiesced_retained(
            self.inner.sender.clone(),
            Box::new(effect),
            #[cfg(test)]
            Arc::clone(&self.inner.retained_finish_completed),
        ));
        retained
            .await
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?
    }

    /// Surrender durable cleanup authority for one applied roster after the
    /// product has adopted the whole group, or retire a terminal no-mutation
    /// or rolled-back result.
    ///
    /// `Applied` becomes `Committed` with every member slot preserved as
    /// acquired, so a crash immediately afterwards still classifies each member
    /// exactly.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::InvalidTransition`] while the
    /// roster is still unresolved, and any authentication or storage failure.
    #[cfg(unix)]
    pub async fn finalize_durable_object_roster(
        &self,
        store: &XfrmObjectRosterRecoveryStore,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
    ) -> Result<XfrmObjectRosterDurablePhase, XfrmObjectRosterDurableError> {
        let operation = DurableObjectRosterOperation {
            store: store.clone(),
            group_id,
            generation,
            roster: roster.clone(),
        };
        self.dispatch_object_roster_durable(|reply| {
            NamespaceCommand::FinalizeDurableObjectRoster(Box::new(operation), reply)
        })
        .await
    }

    /// Adopt one unfinalized applied roster after process loss, additively and
    /// without deleting anything.
    ///
    /// # Contract
    ///
    /// Call this (or [`Self::recover_durable_object_roster`]) BEFORE any other
    /// namespace mutation after process start. An intervening ordinary mutation
    /// burns the writer epoch, which removes the ordering guarantee every
    /// adjacent absence proof depends on, and the roster then classifies as
    /// repair-required with the record retained and nothing deleted.
    ///
    /// # Adopt against recover
    ///
    /// | Situation | Call |
    /// |---|---|
    /// | Record is `Applied` and the consumer's bookkeeping can still accept the group | `adopt` |
    /// | Record is `Applied` but the consumer already gave up on the group | `recover` |
    /// | Caller-side deadline expired while the actor converged | `adopt` first, `recover` if refused |
    /// | Record is `Prepared`, `Issuing`, `Compensating`, `NoMutation`, or `RolledBack` | `recover` (adopt refuses) |
    /// | Record is `Committed` or `Retired` | either; both report it idempotently |
    ///
    /// Adoption re-authenticates the binding, incarnations, member digest, and
    /// epoch currency, reads every member back exactly, and commits only when
    /// every acquired member is present. Otherwise it publishes nothing, leaves
    /// the record `Applied` with the writer gate closed, and reports adoption
    /// refused so the consumer can still choose recovery.
    ///
    /// # Cost of a refused probe
    ///
    /// A refusal decided by an unresolved `Issuing` or `Compensating` phase
    /// costs nothing across families: no writer epoch is burned and no prepared
    /// single-object install or SA relocation authority is invalidated, so
    /// "adopt first, recover if refused" is safe to use as a probe. Only an
    /// `Applied` record — the one adoption can actually commit — carries the
    /// same cross-family fencing obligation as recovery, because committing it
    /// surrenders cleanup authority for real kernel objects. A refusal decided
    /// later, by a member that no longer reads back present, has therefore
    /// already fenced.
    ///
    /// # Errors
    ///
    /// Returns any authentication, binding, or storage failure from the store.
    #[cfg(unix)]
    pub async fn adopt_durable_object_roster(
        &self,
        store: &XfrmObjectRosterRecoveryStore,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
    ) -> Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError> {
        let operation = DurableObjectRosterOperation {
            store: store.clone(),
            group_id,
            generation,
            roster: roster.clone(),
        };
        self.dispatch_object_roster_durable(|reply| {
            NamespaceCommand::AdoptDurableObjectRoster(Box::new(operation), reply)
        })
        .await
    }

    /// Reconcile one retained durable roster after process loss.
    ///
    /// # Contract
    ///
    /// Call this (or [`Self::adopt_durable_object_roster`]) BEFORE any other
    /// namespace mutation after process start. An intervening ordinary mutation
    /// burns the writer epoch, which removes the ordering guarantee every
    /// adjacent absence proof depends on, and recovery then reports
    /// repair-required with the record retained and nothing deleted.
    ///
    /// A prepared roster retires as authoritative no-mutation without any
    /// backend call. Every unresolved member is classified from its own
    /// adjacent proof plus a fresh exact readback: there is no conflict
    /// shortcut, a member that never entered its effect window is never
    /// deleted, and a member that witnessed a foreign object is left exactly as
    /// it was found. An acquired prefix is always reverse-compensated. A live
    /// admission authority for the same group keeps same-process recovery fail
    /// closed until it is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::InvalidTransition`] while a live
    /// authority for this group is still registered, and any authentication,
    /// binding, or storage failure.
    #[cfg(unix)]
    pub async fn recover_durable_object_roster(
        &self,
        store: &XfrmObjectRosterRecoveryStore,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
    ) -> Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError> {
        let operation = DurableObjectRosterOperation {
            store: store.clone(),
            group_id,
            generation,
            roster: roster.clone(),
        };
        self.dispatch_object_roster_durable(|reply| {
            NamespaceCommand::RecoverDurableObjectRoster(Box::new(operation), reply)
        })
        .await
    }

    /// Crash-detector seam: consume prepared roster authority and leave the
    /// durable record at `Issuing` with the cursor at member `ordinal`.
    ///
    /// This reproduces, deterministically, the exact crash window
    /// [`Self::run_durable_object_roster`] would leave if the process died
    /// between the cursor-`ordinal` publication and that member's terminal
    /// record. It performs the same validation chain, deferred-DSCP preflight,
    /// pre-effect sweep, and admission consumption as the run path. Members
    /// below `ordinal` are applied for real, so the durable prefix is genuine
    /// acquisition authority. When `admit_backend_effect` is true member
    /// `ordinal`'s install is invoked exactly as the real effect admission
    /// does; when false the backend is never asked to mutate it. The record
    /// stays unresolved and recoverable, and this grants no deletion authority.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterRunError`], including
    /// [`XfrmObjectRosterDurableError::InvalidTransition`] when the roster
    /// diverts before reaching `ordinal`.
    #[cfg(unix)]
    #[doc(hidden)]
    pub async fn detector_cut_roster_issuing_at_member(
        &self,
        authority: XfrmObjectRosterAdmissionAuthority,
        ordinal: usize,
        admit_backend_effect: bool,
    ) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterRunError> {
        self.dispatch_roster_cut(
            authority,
            DetectorRosterCut::IssuingAtMember {
                ordinal,
                admit_backend_effect,
            },
        )
        .await
    }

    /// Crash-detector seam: consume prepared roster authority, apply every
    /// member, and stop at the unfinalized `Applied` record.
    ///
    /// This is the production run path with the consumer's finalize
    /// deliberately omitted, which is exactly the window in which both
    /// [`Self::adopt_durable_object_roster`] and
    /// [`Self::recover_durable_object_roster`] are legal.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterRunError`], including
    /// [`XfrmObjectRosterDurableError::InvalidTransition`] when the roster does
    /// not reach `Applied`.
    #[cfg(unix)]
    #[doc(hidden)]
    pub async fn detector_cut_roster_applied(
        &self,
        authority: XfrmObjectRosterAdmissionAuthority,
    ) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterRunError> {
        self.dispatch_roster_cut(authority, DetectorRosterCut::Applied)
            .await
    }

    /// Crash-detector seam: reverse-compensate an applied roster down to member
    /// `ordinal`, durably admit that member's removal, optionally issue the
    /// deletion, and stop before publishing its retired slot.
    ///
    /// Before any delete this runs the identical validation chain
    /// [`Self::recover_durable_object_roster`] runs: the actor's store-instance
    /// check, the live-authority reconcile gate, the cross-family gates, an
    /// authenticated restore of the exact group identity, generation, and
    /// member set, the group phase legality check, and writer-epoch currency.
    /// Leaving the member at removal-admitted models a crash after the deletion
    /// was admitted, including after the kernel effect but before its
    /// acknowledgement became durable.
    ///
    /// # Errors
    ///
    /// Returns any authentication, binding, or storage failure, and
    /// [`XfrmObjectRosterDurableError::InvalidTransition`] when compensation
    /// never reaches `ordinal`.
    #[cfg(unix)]
    #[doc(hidden)]
    pub async fn detector_cut_roster_compensating_at_member(
        &self,
        store: &XfrmObjectRosterRecoveryStore,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
        ordinal: usize,
        admit_backend_effect: bool,
    ) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterDurableError> {
        let operation = DurableObjectRosterOperation {
            store: store.clone(),
            group_id,
            generation,
            roster: roster.clone(),
        };
        self.dispatch_object_roster_durable(|reply| {
            NamespaceCommand::DetectorCutRosterCompensating(
                Box::new(operation),
                ordinal,
                admit_backend_effect,
                reply,
            )
        })
        .await
    }

    #[cfg(unix)]
    async fn dispatch_roster_cut(
        &self,
        authority: XfrmObjectRosterAdmissionAuthority,
        cut: DetectorRosterCut,
    ) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterRunError> {
        if authority.actor_binding != self.inner.actor_binding {
            return Err(XfrmObjectRosterDurableError::WrongBinding.into());
        }
        let permit =
            self.inner.sender.reserve().await.map_err(|_| {
                XfrmObjectRosterRunError::from(XfrmObjectRosterDurableError::Storage)
            })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::DetectorCutRosterPrepared(
            Box::new(authority),
            cut,
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| XfrmObjectRosterRunError::from(XfrmObjectRosterDurableError::Storage))?
    }

    /// Load and attach the production CO-RE ESP peer observation source in
    /// this backend's pinned network namespace.
    ///
    /// The host must expose kernel BTF and permit loading and attaching every
    /// required tracing program. Construction fails closed if any program,
    /// map, namespace-cookie binding, verifier check, or link attachment is
    /// unavailable; it never returns a partially admitted monitor.
    #[cfg(target_os = "linux")]
    pub async fn create_esp_peer_observation_monitor(
        &self,
        config: LinuxEspPeerObservationConfig,
    ) -> Result<LinuxEspPeerObservationMonitor, XfrmError> {
        let source = self
            .dispatch(LostReply::ReadOnly, |reply| {
                NamespaceCommand::CreateEspPeerObservationSource(config, reply)
            })
            .await?;
        Ok(LinuxEspPeerObservationMonitor::from_kernel_source(
            self.clone(),
            config,
            source,
        ))
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn query_esp_peer_observation_registration(
        &self,
        key: EspPeerObservationKey,
    ) -> Result<EspPeerObservationRegistration, XfrmError> {
        self.dispatch(LostReply::ReadOnly, |reply| {
            NamespaceCommand::QueryEspPeerObservationRegistration(key, reply)
        })
        .await
    }

    async fn dispatch<T>(
        &self,
        lost_reply: LostReply,
        command: impl FnOnce(oneshot::Sender<Result<T, XfrmError>>) -> NamespaceCommand,
    ) -> Result<T, XfrmError> {
        let permit = self
            .inner
            .sender
            .reserve()
            .await
            .map_err(|_| XfrmError::Unavailable)?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        // No await is permitted between admission and send: after reserve
        // succeeds, the command is synchronously owned by the draining actor.
        permit.send(command(reply_sender));
        reply_receiver.await.map_err(|_| lost_reply.error())?
    }

    #[cfg(unix)]
    async fn dispatch_durable<T>(
        &self,
        command: impl FnOnce(
            oneshot::Sender<Result<T, XfrmObjectInstallDurableError>>,
        ) -> NamespaceCommand,
    ) -> Result<T, XfrmObjectInstallDurableError> {
        let permit = self
            .inner
            .sender
            .reserve()
            .await
            .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        // No await is permitted between admission and send. Once reserved,
        // the draining actor owns completion even if this future is dropped.
        permit.send(command(reply_sender));
        reply_receiver
            .await
            .map_err(|_| XfrmObjectInstallDurableError::Storage)?
    }

    #[cfg(unix)]
    async fn dispatch_sa_relocation_durable<T>(
        &self,
        command: impl FnOnce(
            oneshot::Sender<Result<T, XfrmSaRelocationDurableError>>,
        ) -> NamespaceCommand,
    ) -> Result<T, XfrmSaRelocationDurableError> {
        let permit = self
            .inner
            .sender
            .reserve()
            .await
            .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        // No await is permitted between admission and send. Once reserved,
        // the draining actor owns completion even if this future is dropped.
        permit.send(command(reply_sender));
        reply_receiver
            .await
            .map_err(|_| XfrmSaRelocationDurableError::Storage)?
    }

    #[cfg(unix)]
    async fn dispatch_object_roster_durable<T>(
        &self,
        command: impl FnOnce(
            oneshot::Sender<Result<T, XfrmObjectRosterDurableError>>,
        ) -> NamespaceCommand,
    ) -> Result<T, XfrmObjectRosterDurableError> {
        let permit = self
            .inner
            .sender
            .reserve()
            .await
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        // No await is permitted between admission and send. Once reserved,
        // the draining actor owns completion even if this future is dropped.
        permit.send(command(reply_sender));
        reply_receiver
            .await
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?
    }

    async fn dispatch_outbound_binding(
        &self,
        expectation: OutboundSaPolicyExpectation,
        supplied_sa: SaParameters,
    ) -> Result<(), OutboundSaBindingError> {
        let permit =
            self.inner
                .sender
                .reserve()
                .await
                .map_err(|_| OutboundSaBindingError::Readback {
                    source: XfrmError::Unavailable,
                })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::ValidateOutboundBinding(
            Box::new(OutboundBindingValidation {
                expectation,
                supplied_sa,
            }),
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| OutboundSaBindingError::Readback {
                source: XfrmError::Unavailable,
            })?
    }

    pub(crate) async fn validate_current_outbound_sa_binding(
        &self,
        expectation: OutboundSaPolicyExpectation,
        supplied_sa: SaParameters,
    ) -> Result<(), OutboundSaBindingError> {
        self.dispatch_outbound_binding(expectation, supplied_sa)
            .await
    }

    /// Recover an opaque outbound-SA direction binding after process loss.
    ///
    /// The caller supplies the retained install intent, but that declaration is
    /// not authority. The namespace actor performs exact `GETPOLICY` followed
    /// by `GETSA` readback and validates the kernel policy direction, action,
    /// selector, mark, interface ID, sole template, ESP identity, source,
    /// request ID, and mode before issuing a binding. Missing, ambiguous,
    /// malformed, or mismatched state fails closed.
    pub async fn recover_installed_outbound_sa_binding(
        &self,
        request: XfrmCompositeInstallRequest,
    ) -> Result<InstalledOutboundSaBinding, OutboundSaBindingError> {
        let expectation = validate_outbound_request(&request)?;
        let binding = InstalledOutboundSaBinding::new(self.namespace_actor_binding(), expectation);
        binding
            .validate_current(self, &request.sa.parameters, binding.id())
            .await?;
        Ok(binding)
    }

    /// Atomically advance and prove the outbound ESP sequence for one opaque
    /// installed-SA binding.
    ///
    /// Direction is not caller-selectable. The dedicated namespace actor
    /// validates the opaque binding and durable ID, performs exact OUT-policy
    /// and transient-key readback, reads the current last-assigned sequence,
    /// applies the dedicated Linux replay-state update only when moving
    /// forward, and repeats exact readback
    /// before issuing a key-free receipt. An exact retry is idempotent; a
    /// request below the live counter fails with
    /// `esp_counter_already_advanced` and never mutates kernel state.
    ///
    /// Once admitted, cancellation cannot cancel the actor command. A caller
    /// that loses the reply repeats the same request; preflight then recovers
    /// the already-applied value without a second update.
    ///
    /// The successor SA must remain quiescent and unpublished until the
    /// returned receipt has been validated at the required boundary. This
    /// preserves the preflight-to-`NEWAE` monotonicity contract; a second raw
    /// netlink writer or packet source for the same SA violates the backend's
    /// exclusive-writer contract and invalidates the proof.
    pub async fn apply_and_read_back_outbound_esp_counter(
        &self,
        authority: &InstalledOutboundSaBinding,
        expected_id: OutboundSaBindingId,
        request: EspCounterResumeApplyRequest,
    ) -> Result<AppliedEspCounterReceipt, EspCounterResumeError> {
        let binding = request.binding();
        let target = authority.outbound_esp_counter_target();
        let permit =
            self.inner
                .sender
                .reserve()
                .await
                .map_err(|_| EspCounterResumeError::Backend {
                    code: "esp_counter_backend_unavailable",
                })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::ApplyOutboundEspCounter(
            Box::new(CounterResumeActorRequest {
                authority: authority.clone(),
                expected_id,
                request,
            }),
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| EspCounterResumeError::Backend {
                code: "esp_counter_backend_state_indeterminate",
            })??;
        Ok(AppliedEspCounterReceipt::new(binding, target, self.clone()))
    }

    pub(crate) async fn validate_outbound_esp_counter_receipt(
        &self,
        binding: EspCounterResumeBinding,
        requirement: EspCounterProofRequirement,
    ) -> Result<(), EspCounterResumeError> {
        let permit =
            self.inner
                .sender
                .reserve()
                .await
                .map_err(|_| EspCounterResumeError::Backend {
                    code: "esp_counter_backend_unavailable",
                })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::ValidateOutboundEspCounter(
            binding,
            requirement,
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| EspCounterResumeError::Backend {
                code: "esp_counter_backend_unavailable",
            })?
    }

    pub(crate) async fn acquire_outbound_esp_counter_publication_guard(
        &self,
        binding: EspCounterResumeBinding,
        requirement: EspCounterProofRequirement,
    ) -> Result<crate::EspCounterPublicationGuard, EspCounterResumeError> {
        let permit =
            self.inner
                .sender
                .reserve()
                .await
                .map_err(|_| EspCounterResumeError::Backend {
                    code: "esp_counter_backend_unavailable",
                })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        let (release_sender, release_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::AcquireOutboundEspCounterPublicationGuard(
            binding,
            requirement,
            reply_sender,
            release_receiver,
        ));
        let expires_at = reply_receiver
            .await
            .map_err(|_| EspCounterResumeError::Backend {
                code: "esp_counter_backend_unavailable",
            })??;
        Ok(crate::EspCounterPublicationGuard::new(
            release_sender,
            expires_at,
        ))
    }

    /// Rebuild a receipt after an already-committed ownership grant survives
    /// process loss and the live outbound SA may have advanced.
    ///
    /// This method is read-only. It performs exact actor-local OUT-policy, SA,
    /// and transient-key readback and requires the observed sequence to be at
    /// or above the durable requested floor. The returned receipt is
    /// structurally capped to
    /// [`EspCounterProofRequirement::CommittedRecovery`]. It can never
    /// authorize a new fence. A caller may use it while resuming publication
    /// only after independently proving the exact ownership fence was already
    /// committed before process loss.
    pub async fn recover_committed_outbound_esp_counter(
        &self,
        authority: &InstalledOutboundSaBinding,
        expected_id: OutboundSaBindingId,
        request: EspCounterResumeRecoveryRequest,
    ) -> Result<AppliedEspCounterReceipt, EspCounterResumeError> {
        let binding = request.binding();
        let target = authority.outbound_esp_counter_target();
        let permit =
            self.inner
                .sender
                .reserve()
                .await
                .map_err(|_| EspCounterResumeError::Backend {
                    code: "esp_counter_backend_unavailable",
                })?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::RecoverCommittedOutboundEspCounter(
            Box::new(CounterRecoveryActorRequest {
                authority: authority.clone(),
                expected_id,
                request,
            }),
            reply_sender,
        ));
        reply_receiver
            .await
            .map_err(|_| EspCounterResumeError::Backend {
                code: "esp_counter_backend_unavailable",
            })??;
        Ok(AppliedEspCounterReceipt::new(binding, target, self.clone()))
    }
}

#[cfg(unix)]
struct DurableObjectOperation {
    store: XfrmObjectInstallRecoveryStore,
    operation_id: XfrmObjectInstallOperationId,
    operation_generation: XfrmObjectInstallOperationGeneration,
    request: XfrmObjectInstallRequest,
}

#[cfg(unix)]
enum DetectorPreparedCut {
    Issuing { admit_backend_effect: bool },
    IndeterminateAfterEffect,
}

#[cfg(unix)]
struct DurableSaRelocationOperation {
    store: XfrmSaRelocationRecoveryStore,
    operation_id: XfrmSaRelocationOperationId,
    operation_generation: XfrmSaRelocationOperationGeneration,
    request: RelocateSaRequest,
}

#[cfg(unix)]
struct DurableObjectRosterOperation {
    store: XfrmObjectRosterRecoveryStore,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: XfrmObjectRosterRequest,
}

/// Which unresolved roster crash window a detector seam must stop at.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum DetectorRosterCut {
    IssuingAtMember {
        ordinal: usize,
        admit_backend_effect: bool,
    },
    Applied,
}

enum NamespaceCommand {
    #[cfg(unix)]
    PrepareDurableObjectInstall(
        Box<DurableObjectOperation>,
        oneshot::Sender<Result<XfrmObjectInstallAdmissionAuthority, XfrmObjectInstallDurableError>>,
    ),
    #[cfg(unix)]
    RunDurableObjectInstall(
        Box<XfrmObjectInstallAdmissionAuthority>,
        oneshot::Sender<Result<XfrmObjectInstallDurableOutcome, XfrmObjectInstallRunError>>,
    ),
    #[cfg(unix)]
    DetectorCutPrepared(
        Box<XfrmObjectInstallAdmissionAuthority>,
        DetectorPreparedCut,
        oneshot::Sender<Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallRunError>>,
    ),
    #[cfg(unix)]
    DetectorCutAcquiredRemovalAdmitted(
        Box<DurableObjectOperation>,
        bool,
        oneshot::Sender<Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError>>,
    ),
    #[cfg(unix)]
    FinalizeDurableObjectInstall(
        Box<DurableObjectOperation>,
        oneshot::Sender<Result<XfrmObjectInstallDurablePhase, XfrmObjectInstallDurableError>>,
    ),
    #[cfg(unix)]
    RecoverDurableObjectInstall(
        Box<DurableObjectOperation>,
        oneshot::Sender<Result<XfrmObjectInstallRestartOutcome, XfrmObjectInstallDurableError>>,
    ),
    #[cfg(unix)]
    PrepareSaRelocation(
        Box<DurableSaRelocationOperation>,
        oneshot::Sender<Result<XfrmSaRelocationAdmissionAuthority, XfrmSaRelocationDurableError>>,
    ),
    #[cfg(unix)]
    RunDurableSaRelocation(
        Box<XfrmSaRelocationAdmissionAuthority>,
        oneshot::Sender<Result<XfrmSaRelocationDurableOutcome, XfrmSaRelocationRunError>>,
    ),
    #[cfg(unix)]
    RecoverSaRelocation(
        Box<DurableSaRelocationOperation>,
        oneshot::Sender<Result<XfrmSaRelocationRestartOutcome, XfrmSaRelocationDurableError>>,
    ),
    #[cfg(unix)]
    DetectorCutSaRelocationIssuing(
        Box<XfrmSaRelocationAdmissionAuthority>,
        bool,
        oneshot::Sender<Result<(), XfrmSaRelocationRunError>>,
    ),
    #[cfg(unix)]
    PrepareDurableObjectRoster(
        Box<DurableObjectRosterOperation>,
        oneshot::Sender<Result<XfrmObjectRosterAdmissionAuthority, XfrmObjectRosterDurableError>>,
    ),
    #[cfg(unix)]
    RunDurableObjectRoster(
        Box<XfrmObjectRosterAdmissionAuthority>,
        oneshot::Sender<Result<XfrmObjectRosterDurableOutcome, XfrmObjectRosterRunError>>,
    ),
    #[cfg(unix)]
    RunDurableObjectRosterEffectQuiesced(
        Box<XfrmObjectRosterAdmissionAuthority>,
        oneshot::Sender<Result<XfrmObjectRosterEffectQuiesced, XfrmObjectRosterRunError>>,
    ),
    #[cfg(unix)]
    FinishDurableObjectRosterEffectQuiesced(
        Box<XfrmObjectRosterEffectQuiesced>,
        oneshot::Sender<Result<XfrmObjectRosterDurableOutcome, XfrmObjectRosterDurableError>>,
    ),
    #[cfg(unix)]
    FinalizeDurableObjectRoster(
        Box<DurableObjectRosterOperation>,
        oneshot::Sender<Result<XfrmObjectRosterDurablePhase, XfrmObjectRosterDurableError>>,
    ),
    #[cfg(unix)]
    AdoptDurableObjectRoster(
        Box<DurableObjectRosterOperation>,
        oneshot::Sender<Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError>>,
    ),
    #[cfg(unix)]
    RecoverDurableObjectRoster(
        Box<DurableObjectRosterOperation>,
        oneshot::Sender<Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError>>,
    ),
    #[cfg(unix)]
    DetectorCutRosterPrepared(
        Box<XfrmObjectRosterAdmissionAuthority>,
        DetectorRosterCut,
        oneshot::Sender<Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterRunError>>,
    ),
    #[cfg(unix)]
    DetectorCutRosterCompensating(
        Box<DurableObjectRosterOperation>,
        usize,
        bool,
        oneshot::Sender<Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterDurableError>>,
    ),
    ActivateDscpMarking {
        reply: oneshot::Sender<Result<(), XfrmError>>,
        observed: oneshot::Receiver<()>,
    },
    AllocateSpi(
        AllocateSpiRequest,
        oneshot::Sender<Result<SpiAllocation, XfrmError>>,
    ),
    InstallSa(InstallSaRequest, oneshot::Sender<Result<(), XfrmError>>),
    QuerySa(QuerySaRequest, oneshot::Sender<Result<SaState, XfrmError>>),
    QuerySaRelocationIdentity(
        QuerySaRequest,
        oneshot::Sender<Result<SaRelocationIdentity, XfrmError>>,
    ),
    QueryPolicy(
        QueryPolicyRequest,
        oneshot::Sender<Result<PolicyParameters, XfrmError>>,
    ),
    #[cfg(target_os = "linux")]
    QueryEspPeerObservationRegistration(
        EspPeerObservationKey,
        oneshot::Sender<Result<EspPeerObservationRegistration, XfrmError>>,
    ),
    #[cfg(target_os = "linux")]
    CreateEspPeerObservationSource(
        LinuxEspPeerObservationConfig,
        oneshot::Sender<Result<LinuxEspPeerObservationKernelSource, XfrmError>>,
    ),
    RekeySa(RekeySaRequest, oneshot::Sender<Result<(), XfrmError>>),
    RelocateSa(RelocateSaRequest, oneshot::Sender<Result<(), XfrmError>>),
    RemoveSa(RemoveSaRequest, oneshot::Sender<Result<(), XfrmError>>),
    InstallPolicy(InstallPolicyRequest, oneshot::Sender<Result<(), XfrmError>>),
    RekeyPolicy(RekeyPolicyRequest, oneshot::Sender<Result<(), XfrmError>>),
    RemovePolicy(RemovePolicyRequest, oneshot::Sender<Result<(), XfrmError>>),
    RemovePolicyExact(
        ExactRemovePolicyRequest,
        oneshot::Sender<Result<(), XfrmError>>,
    ),
    ValidateOutboundBinding(
        Box<OutboundBindingValidation>,
        oneshot::Sender<Result<(), OutboundSaBindingError>>,
    ),
    ApplyOutboundEspCounter(
        Box<CounterResumeActorRequest>,
        oneshot::Sender<Result<(), EspCounterResumeError>>,
    ),
    RecoverCommittedOutboundEspCounter(
        Box<CounterRecoveryActorRequest>,
        oneshot::Sender<Result<(), EspCounterResumeError>>,
    ),
    ValidateOutboundEspCounter(
        EspCounterResumeBinding,
        EspCounterProofRequirement,
        oneshot::Sender<Result<(), EspCounterResumeError>>,
    ),
    AcquireOutboundEspCounterPublicationGuard(
        EspCounterResumeBinding,
        EspCounterProofRequirement,
        oneshot::Sender<Result<Instant, EspCounterResumeError>>,
        oneshot::Receiver<()>,
    ),
    Probe(oneshot::Sender<Result<XfrmProbe, XfrmError>>),
    SaRelocationCapability(oneshot::Sender<Result<XfrmCapability, XfrmError>>),
}

/// Whether any SA member of this roster is blocked only by a still-closed
/// deferred DSCP activation gate.
///
/// The preflight is all-or-nothing by construction: a roster is a single
/// transaction, so one blocked member rejects the whole group before any
/// durable step. Policy-only members are unaffected.
#[cfg(unix)]
fn roster_requires_dscp_activation(
    backend: &LinuxXfrmBackend,
    roster: &XfrmObjectRosterRequest,
) -> bool {
    (0..roster.arity()).any(|ordinal| {
        roster
            .member(ordinal)
            .is_some_and(|member| match member.request() {
                XfrmObjectInstallRequest::Sa(request) => matches!(
                    backend.ensure_dscp_mutation_activated(&request.parameters),
                    Err(XfrmError::Unavailable)
                ),
                XfrmObjectInstallRequest::Policy(_) => false,
            })
    })
}

/// How a pre-admission rejection must be reported back to the caller.
///
/// Both arms consume nothing, but only one of them proves that the run can
/// succeed later with this exact authority.
#[cfg(unix)]
enum RosterRunAdmissionRejection {
    /// A cooperating-writer gate is closed. The rejection is transient: the
    /// authority is still registered and still valid, so it is handed back for
    /// an exact retry once the blocking writer resolves.
    Gated(XfrmObjectRosterDurableError),
    /// The admission itself is not usable, so the caller must follow the
    /// durable recovery contract.
    Rejected(XfrmObjectRosterDurableError),
}

/// The run path's validation chain, shared verbatim with the
/// authority-consuming crash-detector seams.
///
/// Store instance, live admission seal, all three cooperating-writer gates
/// (both other families AND a sibling roster in this same store), then the
/// authenticated `Prepared` record and roster digest. A failure here consumes
/// nothing: no epoch is burned and the admission stays registered.
///
/// The roster's own gate is screened HERE rather than being left to the
/// store's `Prepared -> Issuing` check, because by then admission has been
/// consumed and both sibling families have been fenced — turning a transient
/// sibling block into a permanently stranded `Prepared` record.
#[cfg(unix)]
fn validate_object_roster_run_admission(
    state: &NamespaceActorState,
    authority: &XfrmObjectRosterAdmissionAuthority,
) -> Result<(), RosterRunAdmissionRejection> {
    state
        .require_object_roster_store(&authority.operation.store)
        .and_then(|()| state.require_object_roster_admission(authority))
        .map_err(RosterRunAdmissionRejection::Rejected)?;
    state
        .require_install_gate_open_for_roster()
        .and_then(|()| state.require_relocation_gate_open_for_roster())
        .and_then(|()| state.require_roster_gate_open_for_roster())
        .map_err(RosterRunAdmissionRejection::Gated)?;
    validate_object_roster_admission(
        &authority.operation.store,
        &authority.prepared,
        authority.operation.group_id,
        authority.operation.generation,
        &authority.operation.roster,
    )
    .map_err(RosterRunAdmissionRejection::Rejected)
}

/// Turn a pre-admission rejection into the actor's reply, returning the exact
/// affine authority whenever the rejection was a transient gate block.
#[cfg(unix)]
fn reject_roster_run(
    authority: Box<XfrmObjectRosterAdmissionAuthority>,
    rejection: RosterRunAdmissionRejection,
) -> XfrmObjectRosterRunError {
    match rejection {
        RosterRunAdmissionRejection::Gated(error) => {
            XfrmObjectRosterRunError::gated(authority, error)
        }
        RosterRunAdmissionRejection::Rejected(error) => error.into(),
    }
}

/// The recovery path's admission chain, shared by recover and the compensating
/// crash-detector seam.
///
/// Store instance, then the authenticated current group phase, then the
/// live-authority reconcile gate, then the cross-family fencing obligation the
/// phase carries.
#[cfg(unix)]
fn admit_object_roster_recovery(
    state: &mut NamespaceActorState,
    operation: &DurableObjectRosterOperation,
) -> Result<(), XfrmObjectRosterDurableError> {
    state.require_object_roster_store(&operation.store)?;
    let phase = durable_object_roster_phase(
        &operation.store,
        operation.group_id,
        operation.generation,
        &operation.roster,
    )?;
    state.reconcile_object_roster_admission(operation.group_id, operation.generation)?;
    state.admit_durable_object_roster_recovery(phase)
}

/// Adoption's admission chain: every check recovery runs, except that a phase
/// adoption will refuse outright is screened BEFORE any cross-family fencing.
///
/// Adoption is purely additive and can only ever publish from `Applied`, so a
/// diagnostic "adopt first, recover if refused" probe against an `Issuing` or
/// `Compensating` record must not pay recovery's fencing cost: it would burn
/// the object and relocation writer epochs and destroy any legitimately
/// prepared install or relocation authority for a call that then publishes
/// nothing. The store-instance check, the authenticated phase read, and the
/// live-authority reconcile gate all still run first, so a refusal is never
/// less validated than a recovery. Recovery keeps its fencing unchanged: it
/// really can issue per-member cleanup.
#[cfg(unix)]
fn admit_object_roster_adoption(
    state: &mut NamespaceActorState,
    operation: &DurableObjectRosterOperation,
) -> Result<(), XfrmObjectRosterDurableError> {
    state.require_object_roster_store(&operation.store)?;
    let phase = durable_object_roster_phase(
        &operation.store,
        operation.group_id,
        operation.generation,
        &operation.roster,
    )?;
    state.reconcile_object_roster_admission(operation.group_id, operation.generation)?;
    if matches!(
        phase,
        XfrmObjectRosterDurablePhase::Issuing | XfrmObjectRosterDurablePhase::Compensating
    ) {
        // The two unresolved phases adoption always refuses. Nothing durable
        // is read past this point and nothing is published, so no sibling
        // family is fenced.
        state.invalidate_counter_receipts();
        return Ok(());
    }
    state.admit_durable_object_roster_recovery(phase)
}

/// Turn one issue-protocol result into the actor's reply, re-arming the
/// consumed admission when the rejection proved that nothing was published.
///
/// This is how the roster family keeps the single-object contract "a returned
/// authority means durable state is untouched AND the retry is possible". The
/// group's pre-effect sweep lives inside the issue protocol, because its proofs
/// are persisted by the same publication that burns the roster's writer epoch,
/// so admission is already consumed by the time a proved-clean sweep rejection
/// surfaces. Re-registering the seal restores exactly the retry the caller
/// would have had if the sweep had run ahead of admission.
#[cfg(unix)]
fn finish_roster_issue<T>(
    state: &mut NamespaceActorState,
    authority: Box<XfrmObjectRosterAdmissionAuthority>,
    result: Result<T, XfrmObjectRosterIssueError>,
) -> Result<T, XfrmObjectRosterRunError> {
    let error = match result {
        Ok(value) => return Ok(value),
        Err(error) => error,
    };
    if error.is_proved_clean() {
        state.register_object_roster_admission(&authority);
    }
    Err(match error {
        XfrmObjectRosterIssueError::PreEffectReadbackFailed(source) => {
            XfrmObjectRosterRunError::pre_effect_readback_failed(authority, source)
        }
        XfrmObjectRosterIssueError::Durable(error) => error.into(),
    })
}

#[cfg(unix)]
async fn witness_object_install_pre_effect(
    backend: &LinuxXfrmBackend,
    request: &XfrmObjectInstallRequest,
) -> Result<XfrmObjectInstallPreEffectProof, XfrmError> {
    readback_object_present(backend, request)
        .await
        .map(|present| {
            if present {
                XfrmObjectInstallPreEffectProof::Conflict
            } else {
                XfrmObjectInstallPreEffectProof::Absent
            }
        })
}

/// Complete the response-activation finish after its affine token has moved
/// into the namespace runtime.  It deliberately uses the ordinary bounded
/// command sender: retained ownership survives observer cancellation, but it
/// neither bypasses queue admission nor creates a second mutation queue.
#[cfg(unix)]
async fn finish_object_roster_effect_quiesced_retained(
    sender: mpsc::Sender<NamespaceCommand>,
    effect: Box<XfrmObjectRosterEffectQuiesced>,
    #[cfg(test)] retained_finish_completed: Arc<std::sync::atomic::AtomicBool>,
) -> Result<XfrmObjectRosterDurableOutcome, XfrmObjectRosterDurableError> {
    let permit = sender
        .reserve_owned()
        .await
        .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    let (reply_sender, reply_receiver) = oneshot::channel();
    // No await is permitted between admission and send. Once reserved, the
    // draining actor owns completion even if this retained task is detached.
    permit.send(NamespaceCommand::FinishDurableObjectRosterEffectQuiesced(
        effect,
        reply_sender,
    ));
    let outcome = reply_receiver
        .await
        .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    #[cfg(test)]
    if outcome.is_ok() {
        retained_finish_completed.store(true, std::sync::atomic::Ordering::Release);
    }
    outcome
}

impl NamespaceCommand {
    async fn execute(self, backend: &LinuxXfrmBackend, state: &mut NamespaceActorState) {
        if let Err(error) = backend.verify_namespace_actor() {
            self.send_error(error);
            return;
        }

        match self {
            #[cfg(unix)]
            Self::PrepareDurableObjectInstall(operation, reply) => {
                let result = match state.require_object_recovery_store(&operation.store) {
                    Ok(()) => state
                        .require_relocation_gate_open_for_install()
                        .and_then(|()| {
                            prepare_object_install(
                                &operation.store,
                                operation.operation_id,
                                operation.operation_generation,
                                &operation.request,
                            )
                        })
                        .map(|prepared| {
                            let authority = XfrmObjectInstallAdmissionAuthority {
                                operation: *operation,
                                prepared,
                                actor_binding: state.actor_binding.clone(),
                                seal: Arc::new(()),
                            };
                            state.register_object_install_admission(&authority);
                            authority
                        }),
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::RunDurableObjectInstall(authority, reply) => {
                let validation = state
                    .require_object_recovery_store(&authority.operation.store)
                    .and_then(|()| state.require_object_install_admission(&authority))
                    .and_then(|()| state.require_relocation_gate_open_for_install())
                    .and_then(|()| {
                        validate_object_install_admission(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.operation_id,
                            authority.operation.operation_generation,
                            &authority.operation.request,
                        )
                    });
                if let Err(error) = validation {
                    let _ = reply.send(Err(error.into()));
                    return;
                }
                let activation_required = match &authority.operation.request {
                    XfrmObjectInstallRequest::Sa(request) => matches!(
                        backend.ensure_dscp_mutation_activated(&request.parameters),
                        Err(XfrmError::Unavailable)
                    ),
                    XfrmObjectInstallRequest::Policy(_) => false,
                };
                if activation_required {
                    // This is a proved pre-effect rejection. Keep the durable
                    // record at Prepared and return the exact affine authority
                    // so the caller can activate this actor and retry it.
                    let _ = reply.send(Err(XfrmObjectInstallRunError::dscp_activation_required(
                        authority,
                    )));
                    return;
                }
                // Witness the exact deletion identity before admitting the
                // effect. The readback is read-only, so a failure neither burns
                // an epoch nor consumes the admission; the authority is
                // returned for an exact retry, exactly like the DSCP gate.
                let pre_effect_proof =
                    match witness_object_install_pre_effect(backend, &authority.operation.request)
                        .await
                    {
                        Ok(proof) => proof,
                        Err(source) => {
                            let _ = reply.send(Err(
                                XfrmObjectInstallRunError::pre_effect_readback_failed(
                                    authority, source,
                                ),
                            ));
                            return;
                        }
                    };
                let result = match state.admit_durable_object_install_mutation(&authority) {
                    Ok(()) => {
                        run_object_install(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.operation_id,
                            authority.operation.operation_generation,
                            &authority.operation.request,
                            backend,
                            pre_effect_proof,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result.map_err(XfrmObjectInstallRunError::from));
            }
            #[cfg(unix)]
            Self::DetectorCutPrepared(authority, cut, reply) => {
                // Crash-detector seams share the run path's validation, DSCP
                // gate, pre-effect readback, and admission consumption. They
                // stop at the selected unresolved phase before recovery.
                let validation = state
                    .require_object_recovery_store(&authority.operation.store)
                    .and_then(|()| state.require_object_install_admission(&authority))
                    .and_then(|()| state.require_relocation_gate_open_for_install())
                    .and_then(|()| {
                        validate_object_install_admission(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.operation_id,
                            authority.operation.operation_generation,
                            &authority.operation.request,
                        )
                    });
                if let Err(error) = validation {
                    let _ = reply.send(Err(error.into()));
                    return;
                }
                let activation_required = match &authority.operation.request {
                    XfrmObjectInstallRequest::Sa(request) => matches!(
                        backend.ensure_dscp_mutation_activated(&request.parameters),
                        Err(XfrmError::Unavailable)
                    ),
                    XfrmObjectInstallRequest::Policy(_) => false,
                };
                if activation_required {
                    let _ = reply.send(Err(XfrmObjectInstallRunError::dscp_activation_required(
                        authority,
                    )));
                    return;
                }
                let pre_effect_proof =
                    match witness_object_install_pre_effect(backend, &authority.operation.request)
                        .await
                    {
                        Ok(proof) => proof,
                        Err(source) => {
                            let _ = reply.send(Err(
                                XfrmObjectInstallRunError::pre_effect_readback_failed(
                                    authority, source,
                                ),
                            ));
                            return;
                        }
                    };
                let result = match state.admit_durable_object_install_mutation(&authority) {
                    Ok(()) => match cut {
                        DetectorPreparedCut::Issuing {
                            admit_backend_effect,
                        } => {
                            cut_object_install_at_issuing(
                                &authority.operation.store,
                                &authority.prepared,
                                authority.operation.operation_id,
                                authority.operation.operation_generation,
                                &authority.operation.request,
                                backend,
                                pre_effect_proof,
                                admit_backend_effect,
                            )
                            .await
                        }
                        DetectorPreparedCut::IndeterminateAfterEffect => {
                            cut_object_install_at_indeterminate_after_effect(
                                &authority.operation.store,
                                &authority.prepared,
                                authority.operation.operation_id,
                                authority.operation.operation_generation,
                                &authority.operation.request,
                                backend,
                                pre_effect_proof,
                            )
                            .await
                        }
                    },
                    Err(error) => Err(error),
                };
                let _ = reply.send(result.map_err(XfrmObjectInstallRunError::from));
            }
            #[cfg(unix)]
            Self::DetectorCutAcquiredRemovalAdmitted(operation, admit_backend_effect, reply) => {
                // Reproduce a process cut after durable cleanup admission and
                // optionally after the exact kernel delete, while retaining
                // the same restart gate and cleanup authority as production.
                let validation = state
                    .require_object_recovery_store(&operation.store)
                    .and_then(|()| {
                        durable_object_install_phase(
                            &operation.store,
                            operation.operation_id,
                            operation.operation_generation,
                            &operation.request,
                        )
                    })
                    .and_then(|phase| {
                        state.reconcile_object_install_admission(
                            operation.operation_id,
                            operation.operation_generation,
                        )?;
                        Ok(phase)
                    });
                let result = match validation
                    .and_then(|phase| state.admit_durable_object_install_recovery(phase))
                {
                    Ok(()) => {
                        cut_object_install_at_removal_admitted(
                            &operation.store,
                            operation.operation_id,
                            operation.operation_generation,
                            &operation.request,
                            backend,
                            admit_backend_effect,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::FinalizeDurableObjectInstall(operation, reply) => {
                let result = state
                    .require_object_recovery_store(&operation.store)
                    .and_then(|()| {
                        finalize_object_install(
                            &operation.store,
                            operation.operation_id,
                            operation.operation_generation,
                            &operation.request,
                        )
                    });
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::RecoverDurableObjectInstall(operation, reply) => {
                let validation = state
                    .require_object_recovery_store(&operation.store)
                    .and_then(|()| {
                        durable_object_install_phase(
                            &operation.store,
                            operation.operation_id,
                            operation.operation_generation,
                            &operation.request,
                        )
                    })
                    .and_then(|phase| {
                        state.reconcile_object_install_admission(
                            operation.operation_id,
                            operation.operation_generation,
                        )?;
                        Ok(phase)
                    });
                let result = match validation
                    .and_then(|phase| state.admit_durable_object_install_recovery(phase))
                {
                    Ok(()) => {
                        recover_object_install(
                            &operation.store,
                            operation.operation_id,
                            operation.operation_generation,
                            &operation.request,
                            backend,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::PrepareSaRelocation(operation, reply) => {
                let result = match state.require_sa_recovery_store(&operation.store) {
                    Ok(()) => state
                        .require_install_gate_open_for_relocation()
                        .and_then(|()| {
                            prepare_sa_relocation(
                                &operation.store,
                                operation.operation_id,
                                operation.operation_generation,
                                &operation.request,
                            )
                        })
                        .map(|prepared| {
                            let authority = XfrmSaRelocationAdmissionAuthority {
                                operation: *operation,
                                prepared,
                                actor_binding: state.actor_binding.clone(),
                                seal: Arc::new(()),
                            };
                            state.register_sa_relocation_admission(&authority);
                            authority
                        }),
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::RunDurableSaRelocation(authority, reply) => {
                let validation = state
                    .require_sa_recovery_store(&authority.operation.store)
                    .and_then(|()| state.require_sa_relocation_admission(&authority))
                    .and_then(|()| state.require_install_gate_open_for_relocation())
                    .and_then(|()| {
                        validate_sa_relocation_admission(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.operation_id,
                            authority.operation.operation_generation,
                            &authority.operation.request,
                        )
                    });
                if let Err(error) = validation {
                    let _ = reply.send(Err(error.into()));
                    return;
                }
                let activation_required = matches!(
                    backend.ensure_dscp_relocation_activated(&authority.operation.request),
                    Err(XfrmError::Unavailable)
                );
                if activation_required {
                    // This is a proved pre-effect rejection. Keep the durable
                    // record at Prepared and return the exact affine authority
                    // so the caller can activate this actor and retry it.
                    let _ = reply.send(Err(XfrmSaRelocationRunError::dscp_activation_required(
                        authority,
                    )));
                    return;
                }
                // Witness the exact old/target identities before admitting the
                // effect. The readbacks are read-only, so a rejection neither
                // burns an epoch nor consumes the admission; the authority is
                // returned for an exact retry unless the current state is
                // provably mismatched.
                let pre_effect_proof = match witness_sa_relocation_proof(
                    backend,
                    &authority.operation.request,
                )
                .await
                {
                    Ok(proof) => proof,
                    Err(XfrmSaRelocationPreEffectRejection::CurrentStateMismatch) => {
                        let _ = reply.send(Err(XfrmSaRelocationRunError::current_state_mismatch()));
                        return;
                    }
                    Err(XfrmSaRelocationPreEffectRejection::TargetConflict) => {
                        let _ =
                            reply.send(Err(XfrmSaRelocationRunError::target_conflict(authority)));
                        return;
                    }
                    Err(XfrmSaRelocationPreEffectRejection::ReadbackFailed(source)) => {
                        let _ = reply.send(Err(
                            XfrmSaRelocationRunError::pre_effect_readback_failed(authority, source),
                        ));
                        return;
                    }
                };
                let result = match state.admit_durable_sa_relocation_mutation(&authority) {
                    Ok(()) => {
                        run_sa_relocation(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.operation_id,
                            authority.operation.operation_generation,
                            &authority.operation.request,
                            backend,
                            pre_effect_proof,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result.map_err(XfrmSaRelocationRunError::from));
            }
            #[cfg(unix)]
            Self::RecoverSaRelocation(operation, reply) => {
                let validation = state
                    .require_sa_recovery_store(&operation.store)
                    .and_then(|()| {
                        durable_sa_relocation_phase(
                            &operation.store,
                            operation.operation_id,
                            operation.operation_generation,
                            &operation.request,
                        )
                    })
                    .and_then(|phase| {
                        state.reconcile_sa_relocation_admission(
                            operation.operation_id,
                            operation.operation_generation,
                        )?;
                        Ok(phase)
                    });
                let result = match validation
                    .and_then(|phase| state.admit_durable_sa_relocation_recovery(phase))
                {
                    Ok(()) => {
                        recover_sa_relocation(
                            &operation.store,
                            operation.operation_id,
                            operation.operation_generation,
                            &operation.request,
                            backend,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::DetectorCutSaRelocationIssuing(authority, admit_backend_effect, reply) => {
                // Crash-detector seam: reproduce the Issuing crash window. It
                // shares the run path's validation, DSCP gate, pre-effect
                // readbacks, and admission consumption, then stops before any
                // terminal publication so the record stays unresolved.
                let validation = state
                    .require_sa_recovery_store(&authority.operation.store)
                    .and_then(|()| state.require_sa_relocation_admission(&authority))
                    .and_then(|()| state.require_install_gate_open_for_relocation())
                    .and_then(|()| {
                        validate_sa_relocation_admission(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.operation_id,
                            authority.operation.operation_generation,
                            &authority.operation.request,
                        )
                    });
                if let Err(error) = validation {
                    let _ = reply.send(Err(error.into()));
                    return;
                }
                let activation_required = matches!(
                    backend.ensure_dscp_relocation_activated(&authority.operation.request),
                    Err(XfrmError::Unavailable)
                );
                if activation_required {
                    let _ = reply.send(Err(XfrmSaRelocationRunError::dscp_activation_required(
                        authority,
                    )));
                    return;
                }
                let pre_effect_proof = match witness_sa_relocation_proof(
                    backend,
                    &authority.operation.request,
                )
                .await
                {
                    Ok(proof) => proof,
                    Err(XfrmSaRelocationPreEffectRejection::CurrentStateMismatch) => {
                        let _ = reply.send(Err(XfrmSaRelocationRunError::current_state_mismatch()));
                        return;
                    }
                    Err(XfrmSaRelocationPreEffectRejection::TargetConflict) => {
                        let _ =
                            reply.send(Err(XfrmSaRelocationRunError::target_conflict(authority)));
                        return;
                    }
                    Err(XfrmSaRelocationPreEffectRejection::ReadbackFailed(source)) => {
                        let _ = reply.send(Err(
                            XfrmSaRelocationRunError::pre_effect_readback_failed(authority, source),
                        ));
                        return;
                    }
                };
                let result = match state.admit_durable_sa_relocation_mutation(&authority) {
                    Ok(()) => {
                        cut_sa_relocation_at_issuing(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.operation_id,
                            authority.operation.operation_generation,
                            &authority.operation.request,
                            backend,
                            pre_effect_proof,
                            admit_backend_effect,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result.map_err(XfrmSaRelocationRunError::from));
            }
            #[cfg(unix)]
            Self::PrepareDurableObjectRoster(operation, reply) => {
                let result = match state.require_object_roster_store(&operation.store) {
                    Ok(()) => state
                        .require_install_gate_open_for_roster()
                        .and_then(|()| state.require_relocation_gate_open_for_roster())
                        .and_then(|()| {
                            prepare_object_roster_record(
                                &operation.store,
                                operation.group_id,
                                operation.generation,
                                &operation.roster,
                            )
                        })
                        .map(|prepared| {
                            let authority = XfrmObjectRosterAdmissionAuthority {
                                operation,
                                prepared,
                                actor_binding: state.actor_binding.clone(),
                                seal: Arc::new(()),
                            };
                            state.register_object_roster_admission(&authority);
                            authority
                        }),
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::RunDurableObjectRoster(authority, reply) => {
                if let Err(rejection) = validate_object_roster_run_admission(state, &authority) {
                    let _ = reply.send(Err(reject_roster_run(authority, rejection)));
                    return;
                }
                // All-or-nothing deferred DSCP preflight over every SA member,
                // before any durable step. One blocked member is a proved
                // pre-effect rejection for the whole group: the record stays
                // Prepared and the exact affine authority is returned.
                if roster_requires_dscp_activation(backend, &authority.operation.roster) {
                    let _ = reply.send(Err(XfrmObjectRosterRunError::dscp_activation_required(
                        authority,
                    )));
                    return;
                }
                // The group's pre-effect sweep runs inside the issue protocol,
                // because the sweep proofs it witnesses are persisted by the
                // very `Prepared -> Issuing` publication that burns the
                // roster's single writer epoch. Admission is therefore consumed
                // first, and a proved-clean sweep rejection re-registers the
                // seal below so the returned authority is retryable. The
                // roster's own durable state is untouched in that case; the
                // cross-family fencing already performed is monotone and only
                // ever invalidates.
                let result = match state.admit_durable_object_roster_mutation(&authority) {
                    Ok(()) => {
                        run_object_roster(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.group_id,
                            authority.operation.generation,
                            &authority.operation.roster,
                            backend,
                        )
                        .await
                    }
                    Err(error) => Err(XfrmObjectRosterIssueError::Durable(error)),
                };
                let _ = reply.send(finish_roster_issue(state, authority, result));
            }
            #[cfg(unix)]
            Self::RunDurableObjectRosterEffectQuiesced(authority, reply) => {
                if let Err(rejection) = validate_object_roster_run_admission(state, &authority) {
                    let _ = reply.send(Err(reject_roster_run(authority, rejection)));
                    return;
                }
                if roster_requires_dscp_activation(backend, &authority.operation.roster) {
                    let _ = reply.send(Err(XfrmObjectRosterRunError::dscp_activation_required(
                        authority,
                    )));
                    return;
                }
                let result = match state.admit_durable_object_roster_mutation(&authority) {
                    Ok(()) => {
                        run_object_roster_effect_quiesced(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.group_id,
                            authority.operation.generation,
                            &authority.operation.roster,
                            backend,
                        )
                        .await
                    }
                    Err(error) => Err(XfrmObjectRosterIssueError::Durable(error)),
                };
                match result {
                    Ok(issuing) => {
                        let effect = XfrmObjectRosterEffectQuiesced {
                            operation: authority.operation,
                            issuing,
                            actor_binding: state.actor_binding.clone(),
                            seal: Arc::new(()),
                        };
                        state.register_object_roster_effect_quiesced(&effect);
                        let _ = reply.send(Ok(effect));
                    }
                    Err(error) => {
                        let _ = reply.send(finish_roster_issue(state, authority, Err(error)));
                    }
                }
            }
            #[cfg(unix)]
            Self::FinishDurableObjectRosterEffectQuiesced(effect, reply) => {
                let result = state
                    .require_object_roster_effect_quiesced(&effect)
                    .and_then(|()| {
                        finish_object_roster_effect_quiesced(
                            &effect.operation.store,
                            &effect.issuing,
                            effect.operation.group_id,
                            effect.operation.generation,
                            &effect.operation.roster,
                        )
                    });
                // The affine value is consumed whether publication succeeds
                // or fails.  On failure the authenticated `Issuing` record
                // remains the recovery authority; on success it is now
                // `Applied`.  Either way a later recover/adopt command sees
                // the durable state rather than a stale live seal.
                state.roster_admissions.remove(&effect.key());
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::DetectorCutRosterPrepared(authority, cut, reply) => {
                // Crash-detector seams share the run path's validation chain,
                // DSCP preflight, sweep, and admission consumption. They stop
                // at the selected unresolved phase before recovery.
                if let Err(rejection) = validate_object_roster_run_admission(state, &authority) {
                    let _ = reply.send(Err(reject_roster_run(authority, rejection)));
                    return;
                }
                if roster_requires_dscp_activation(backend, &authority.operation.roster) {
                    let _ = reply.send(Err(XfrmObjectRosterRunError::dscp_activation_required(
                        authority,
                    )));
                    return;
                }
                let result = match state.admit_durable_object_roster_mutation(&authority) {
                    Ok(()) => match cut {
                        DetectorRosterCut::IssuingAtMember {
                            ordinal,
                            admit_backend_effect,
                        } => {
                            cut_object_roster_at_issuing_member(
                                &authority.operation.store,
                                &authority.prepared,
                                authority.operation.group_id,
                                authority.operation.generation,
                                &authority.operation.roster,
                                backend,
                                ordinal,
                                admit_backend_effect,
                            )
                            .await
                        }
                        DetectorRosterCut::Applied => {
                            cut_object_roster_at_applied(
                                &authority.operation.store,
                                &authority.prepared,
                                authority.operation.group_id,
                                authority.operation.generation,
                                &authority.operation.roster,
                                backend,
                            )
                            .await
                        }
                    },
                    Err(error) => Err(XfrmObjectRosterIssueError::Durable(error)),
                };
                let _ = reply.send(finish_roster_issue(state, authority, result));
            }
            #[cfg(unix)]
            Self::FinalizeDurableObjectRoster(operation, reply) => {
                let result = state
                    .require_object_roster_store(&operation.store)
                    .and_then(|()| {
                        finalize_object_roster(
                            &operation.store,
                            operation.group_id,
                            operation.generation,
                            &operation.roster,
                        )
                    });
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::AdoptDurableObjectRoster(operation, reply) => {
                let result = match admit_object_roster_adoption(state, &operation) {
                    Ok(()) => {
                        adopt_object_roster(
                            &operation.store,
                            operation.group_id,
                            operation.generation,
                            &operation.roster,
                            backend,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::RecoverDurableObjectRoster(operation, reply) => {
                let result = match admit_object_roster_recovery(state, &operation) {
                    Ok(()) => {
                        recover_object_roster(
                            &operation.store,
                            operation.group_id,
                            operation.generation,
                            &operation.roster,
                            backend,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Self::DetectorCutRosterCompensating(
                operation,
                ordinal,
                admit_backend_effect,
                reply,
            ) => {
                // Reproduce a process cut after durable per-member cleanup
                // admission and optionally after the exact kernel delete, under
                // the identical validation chain recovery runs.
                let result = match admit_object_roster_recovery(state, &operation) {
                    Ok(()) => {
                        cut_object_roster_at_compensating_member(
                            &operation.store,
                            operation.group_id,
                            operation.generation,
                            &operation.roster,
                            backend,
                            ordinal,
                            admit_backend_effect,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::ActivateDscpMarking { reply, observed } => {
                let was_ready = backend.dscp_activation_is_ready();
                match if was_ready {
                    Ok(())
                } else {
                    backend.prepare_dscp_activation()
                } {
                    Ok(()) => {
                        // A successful send alone does not prove that the
                        // observer polled the reply. Hold the actor's FIFO slot
                        // until the public future acknowledges observation.
                        if reply.send(Ok(())).is_ok() && observed.await.is_ok() && !was_ready {
                            backend.publish_dscp_activation();
                        }
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            Self::AllocateSpi(request, reply) => {
                let result = match state.admit_xfrm_mutation() {
                    Ok(()) => backend.allocate_spi(request).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::InstallSa(request, reply) => {
                let result = match backend
                    .ensure_dscp_mutation_activated(&request.parameters)
                    .and_then(|()| state.admit_xfrm_mutation())
                {
                    Ok(()) => backend.install_sa(request).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::QuerySa(request, reply) => {
                let _ = reply.send(backend.query_sa(request).await);
            }
            Self::QuerySaRelocationIdentity(request, reply) => {
                let _ = reply.send(backend.query_sa_relocation_identity(request).await);
            }
            Self::QueryPolicy(request, reply) => {
                let _ = reply.send(backend.query_policy(request).await);
            }
            #[cfg(target_os = "linux")]
            Self::QueryEspPeerObservationRegistration(key, reply) => {
                let _ = reply.send(backend.query_esp_peer_observation_registration(key).await);
            }
            #[cfg(target_os = "linux")]
            Self::CreateEspPeerObservationSource(config, reply) => {
                let _ = reply.send(LinuxEspPeerObservationKernelSource::load(config));
            }
            Self::RekeySa(request, reply) => {
                let result = match backend
                    .ensure_dscp_mutation_activated(&request.parameters)
                    .and_then(|()| state.admit_xfrm_mutation())
                {
                    Ok(()) => backend.rekey_sa(request).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::RelocateSa(request, reply) => {
                let result = match backend
                    .ensure_dscp_relocation_activated(&request)
                    .and_then(|()| state.admit_xfrm_mutation())
                {
                    Ok(()) => backend.relocate_sa(request).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::RemoveSa(request, reply) => {
                let result = match state.admit_xfrm_mutation() {
                    Ok(()) => backend.remove_sa(request).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::InstallPolicy(request, reply) => {
                let result = match state.admit_xfrm_mutation() {
                    Ok(()) => backend.install_policy(request).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::RekeyPolicy(request, reply) => {
                let result = match state.admit_xfrm_mutation() {
                    Ok(()) => backend.rekey_policy(request).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::RemovePolicy(request, reply) => {
                let result = match state.admit_xfrm_mutation() {
                    Ok(()) => backend.remove_policy(request).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::RemovePolicyExact(request, reply) => {
                let result = match state.admit_xfrm_mutation() {
                    Ok(()) => backend.remove_policy_exact(request).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Self::ValidateOutboundBinding(validation, reply) => {
                let _ = reply.send(
                    backend
                        .validate_outbound_sa_binding(
                            &validation.expectation,
                            &validation.supplied_sa,
                        )
                        .await,
                );
            }
            Self::ApplyOutboundEspCounter(request, reply) => {
                let result = match backend
                    .ensure_dscp_mutation_activated(request.parameters())
                    .and_then(|()| state.admit_xfrm_mutation())
                {
                    Ok(()) => {
                        state
                            .counter_receipts
                            .apply(backend, &state.actor_binding, *request)
                            .await
                    }
                    Err(error) => Err(map_backend_error(error)),
                };
                let _ = reply.send(result);
            }
            Self::RecoverCommittedOutboundEspCounter(request, reply) => {
                let _ = reply.send(
                    state
                        .counter_receipts
                        .recover_committed(backend, &state.actor_binding, *request)
                        .await,
                );
            }
            Self::ValidateOutboundEspCounter(binding, requirement, reply) => {
                let _ = reply.send(
                    state
                        .counter_receipts
                        .validate(backend, binding, requirement)
                        .await,
                );
            }
            Self::AcquireOutboundEspCounterPublicationGuard(
                binding,
                requirement,
                reply,
                release,
            ) => {
                let result = state
                    .counter_receipts
                    .validate_for_publication(backend, binding, requirement)
                    .await;
                let acquired = result.is_ok();
                let _ = reply.send(result);
                if acquired {
                    // Deliberately keep the actor command in flight until the
                    // publication owner drops its opaque guard. Subsequent
                    // mutations remain queued and therefore cannot invalidate
                    // the just-validated receipt during Host publication.
                    let _ = release.await;
                }
            }
            Self::Probe(reply) => {
                let _ = reply.send(backend.probe().await);
            }
            Self::SaRelocationCapability(reply) => {
                let _ = reply.send(backend.sa_relocation_capability().await);
            }
        }
    }

    fn send_error(self, error: XfrmError) {
        match self {
            #[cfg(unix)]
            Self::PrepareDurableObjectInstall(_, reply) => {
                let _ = reply.send(Err(XfrmObjectInstallDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::RunDurableObjectInstall(_, reply) => {
                let _ = reply.send(Err(XfrmObjectInstallDurableError::WrongBinding.into()));
            }
            #[cfg(unix)]
            Self::DetectorCutPrepared(_, _, reply) => {
                let _ = reply.send(Err(XfrmObjectInstallDurableError::WrongBinding.into()));
            }
            #[cfg(unix)]
            Self::DetectorCutAcquiredRemovalAdmitted(_, _, reply) => {
                let _ = reply.send(Err(XfrmObjectInstallDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::FinalizeDurableObjectInstall(_, reply) => {
                let _ = reply.send(Err(XfrmObjectInstallDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::RecoverDurableObjectInstall(_, reply) => {
                let _ = reply.send(Err(XfrmObjectInstallDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::PrepareSaRelocation(_, reply) => {
                let _ = reply.send(Err(XfrmSaRelocationDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::RunDurableSaRelocation(_, reply) => {
                let _ = reply.send(Err(XfrmSaRelocationDurableError::WrongBinding.into()));
            }
            #[cfg(unix)]
            Self::RecoverSaRelocation(_, reply) => {
                let _ = reply.send(Err(XfrmSaRelocationDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::DetectorCutSaRelocationIssuing(_, _, reply) => {
                let _ = reply.send(Err(XfrmSaRelocationDurableError::WrongBinding.into()));
            }
            #[cfg(unix)]
            Self::PrepareDurableObjectRoster(_, reply) => {
                let _ = reply.send(Err(XfrmObjectRosterDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::RunDurableObjectRoster(_, reply) => {
                let _ = reply.send(Err(XfrmObjectRosterDurableError::WrongBinding.into()));
            }
            #[cfg(unix)]
            Self::RunDurableObjectRosterEffectQuiesced(_, reply) => {
                let _ = reply.send(Err(XfrmObjectRosterDurableError::WrongBinding.into()));
            }
            #[cfg(unix)]
            Self::FinishDurableObjectRosterEffectQuiesced(_, reply) => {
                let _ = reply.send(Err(XfrmObjectRosterDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::FinalizeDurableObjectRoster(_, reply) => {
                let _ = reply.send(Err(XfrmObjectRosterDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::AdoptDurableObjectRoster(_, reply)
            | Self::RecoverDurableObjectRoster(_, reply) => {
                let _ = reply.send(Err(XfrmObjectRosterDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::DetectorCutRosterPrepared(_, _, reply) => {
                let _ = reply.send(Err(XfrmObjectRosterDurableError::WrongBinding.into()));
            }
            #[cfg(unix)]
            Self::DetectorCutRosterCompensating(_, _, _, reply) => {
                let _ = reply.send(Err(XfrmObjectRosterDurableError::WrongBinding));
            }
            Self::ActivateDscpMarking { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::AllocateSpi(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::InstallSa(_, reply)
            | Self::RekeySa(_, reply)
            | Self::RelocateSa(_, reply)
            | Self::RemoveSa(_, reply)
            | Self::InstallPolicy(_, reply)
            | Self::RekeyPolicy(_, reply)
            | Self::RemovePolicy(_, reply)
            | Self::RemovePolicyExact(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::QuerySa(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::QuerySaRelocationIdentity(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::QueryPolicy(_, reply) => {
                let _ = reply.send(Err(error));
            }
            #[cfg(target_os = "linux")]
            Self::QueryEspPeerObservationRegistration(_, reply) => {
                let _ = reply.send(Err(error));
            }
            #[cfg(target_os = "linux")]
            Self::CreateEspPeerObservationSource(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::ValidateOutboundBinding(_, reply) => {
                let _ = reply.send(Err(OutboundSaBindingError::Readback { source: error }));
            }
            Self::ApplyOutboundEspCounter(_, reply)
            | Self::RecoverCommittedOutboundEspCounter(_, reply)
            | Self::ValidateOutboundEspCounter(_, _, reply) => {
                let _ = reply.send(Err(map_backend_error(error)));
            }
            Self::AcquireOutboundEspCounterPublicationGuard(_, _, reply, _) => {
                let _ = reply.send(Err(map_backend_error(error)));
            }
            Self::Probe(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::SaRelocationCapability(reply) => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

struct OutboundBindingValidation {
    expectation: OutboundSaPolicyExpectation,
    supplied_sa: SaParameters,
}

#[async_trait]
impl XfrmBackend for NamespaceBoundLinuxXfrmBackend {
    async fn allocate_spi(&self, request: AllocateSpiRequest) -> Result<SpiAllocation, XfrmError> {
        self.dispatch(LostReply::Mutation("allocspi"), |reply| {
            NamespaceCommand::AllocateSpi(request, reply)
        })
        .await
    }

    async fn install_sa(&self, request: InstallSaRequest) -> Result<(), XfrmError> {
        self.dispatch(LostReply::Mutation("install_sa"), |reply| {
            NamespaceCommand::InstallSa(request, reply)
        })
        .await
    }

    async fn query_sa(&self, request: QuerySaRequest) -> Result<SaState, XfrmError> {
        self.dispatch(LostReply::ReadOnly, |reply| {
            NamespaceCommand::QuerySa(request, reply)
        })
        .await
    }

    async fn query_sa_relocation_identity(
        &self,
        request: QuerySaRequest,
    ) -> Result<SaRelocationIdentity, XfrmError> {
        self.dispatch(LostReply::ReadOnly, |reply| {
            NamespaceCommand::QuerySaRelocationIdentity(request, reply)
        })
        .await
    }

    async fn query_policy(
        &self,
        request: QueryPolicyRequest,
    ) -> Result<PolicyParameters, XfrmError> {
        self.dispatch(LostReply::ReadOnly, |reply| {
            NamespaceCommand::QueryPolicy(request, reply)
        })
        .await
    }

    async fn rekey_sa(&self, request: RekeySaRequest) -> Result<(), XfrmError> {
        self.dispatch(LostReply::Mutation("rekey_sa"), |reply| {
            NamespaceCommand::RekeySa(request, reply)
        })
        .await
    }

    async fn relocate_sa(&self, request: RelocateSaRequest) -> Result<(), XfrmError> {
        self.dispatch(LostReply::Mutation("relocate_sa"), |reply| {
            NamespaceCommand::RelocateSa(request, reply)
        })
        .await
    }

    async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError> {
        self.dispatch(LostReply::Mutation("remove_sa"), |reply| {
            NamespaceCommand::RemoveSa(request, reply)
        })
        .await
    }

    async fn install_policy(&self, request: InstallPolicyRequest) -> Result<(), XfrmError> {
        self.dispatch(LostReply::Mutation("install_policy"), |reply| {
            NamespaceCommand::InstallPolicy(request, reply)
        })
        .await
    }

    async fn rekey_policy(&self, request: RekeyPolicyRequest) -> Result<(), XfrmError> {
        self.dispatch(LostReply::Mutation("rekey_policy"), |reply| {
            NamespaceCommand::RekeyPolicy(request, reply)
        })
        .await
    }

    async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError> {
        self.dispatch(LostReply::Mutation("remove_policy"), |reply| {
            NamespaceCommand::RemovePolicy(request, reply)
        })
        .await
    }

    async fn remove_policy_exact(
        &self,
        request: ExactRemovePolicyRequest,
    ) -> Result<(), XfrmError> {
        validate_exact_remove_policy_request(&request)?;
        self.dispatch(LostReply::Mutation("remove_policy_exact"), |reply| {
            NamespaceCommand::RemovePolicyExact(request, reply)
        })
        .await
    }

    async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
        self.dispatch(LostReply::ReadOnly, NamespaceCommand::Probe)
            .await
    }

    async fn sa_relocation_capability(&self) -> Result<XfrmCapability, XfrmError> {
        self.dispatch(
            LostReply::ReadOnly,
            NamespaceCommand::SaRelocationCapability,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    #[cfg(unix)]
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    #[cfg(unix)]
    use std::task::Poll;
    use std::thread::ThreadId;
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::path::{Path, PathBuf};

    use zeroize::Zeroizing;

    use super::*;
    use crate::dscp::{LinuxXfrmDscpMarkingConfig, XfrmDscpRuntime};
    use crate::linux::{
        test_outbound_binding_readback_bodies, LinuxXfrmBackendConfig, LinuxXfrmTransport,
        SensitiveBuffer,
    };
    use crate::outbound_binding::validate_outbound_request;
    use crate::{
        Algorithm, AuthAlgorithm, DscpCodepoint, EspCounterResumeProofSet, IpAddress, KeyMaterial,
        LifetimeConfig, PolicyParameters, SaParameters, SaRelocationDirection, SaRelocationEncap,
        SaRelocationSelector, SaReplayState, XfrmAction, XfrmBackendKind, XfrmDirection, XfrmId,
        XfrmInstallOwnership, XfrmLookupMark, XfrmMode, XfrmRequestId, XfrmSelector,
        XfrmStagedInstall, XfrmTemplate,
    };

    #[cfg(unix)]
    use crate::XfrmObjectRosterMemberRequest;
    #[cfg(unix)]
    use crate::XfrmSaRelocationDurablePhase;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ExecutionRecord {
        operation: &'static str,
        thread: ThreadId,
        binding: NetworkNamespaceBinding,
    }

    #[derive(Debug, Clone, Default)]
    struct RecordingUnavailableTransport {
        records: Arc<Mutex<Vec<ExecutionRecord>>>,
    }

    impl RecordingUnavailableTransport {
        fn record(&self, operation: &'static str) {
            let record = ExecutionRecord {
                operation,
                thread: std::thread::current().id(),
                binding: NetworkNamespaceBinding::capture().unwrap_or(NetworkNamespaceBinding {
                    device: 0,
                    inode: 0,
                    cookie: None,
                    boot_id: None,
                }),
            };
            self.records
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(record);
        }

        fn records(&self) -> Vec<ExecutionRecord> {
            self.records
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl LinuxXfrmTransport for RecordingUnavailableTransport {
        fn transact(
            &self,
            operation: &'static str,
            _operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.record(operation);
            Err(XfrmError::Unavailable)
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            self.record("probe");
            XfrmProbe {
                kind: XfrmBackendKind::LinuxKernel,
                platform_supported: true,
                kernel_reachable: true,
                net_admin_capable: false,
                algorithms: XfrmCapability::PermissionDenied,
                egress_dscp_marking: XfrmCapability::Missing,
                details: Some("namespace actor test transport"),
            }
        }
    }

    #[cfg(unix)]
    #[derive(Debug, Clone, Default)]
    struct RecordingSuccessTransport {
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    #[cfg(unix)]
    impl RecordingSuccessTransport {
        fn operations(&self) -> Vec<&'static str> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[cfg(unix)]
    impl LinuxXfrmTransport for RecordingSuccessTransport {
        fn transact(
            &self,
            operation: &'static str,
            operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
            // Read-only exact queries model an absent identity so pre-effect
            // readback witnesses `Absent`; mutations succeed with an ACK.
            match operation_class {
                crate::linux::NetlinkOperationClass::ReadOnly => Err(XfrmError::NotFound),
                crate::linux::NetlinkOperationClass::Mutation => Ok(None),
            }
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[cfg(unix)]
    struct DurableTestRoot(PathBuf);

    #[cfg(unix)]
    impl DurableTestRoot {
        fn new() -> Self {
            let operation = XfrmObjectInstallOperationId::generate().unwrap();
            let encoded = operation
                .to_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = std::env::temp_dir().join(format!("opc-xfrm-namespace-test-{encoded}"));
            assert!(path.is_absolute());
            assert!(!path.exists());
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    #[cfg(unix)]
    impl Drop for DurableTestRoot {
        fn drop(&mut self) {
            if self.0.is_dir() {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn selector() -> XfrmSelector {
        XfrmSelector::new(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 17)
    }

    fn sa_parameters() -> SaParameters {
        SaParameters {
            selector: selector(),
            id: XfrmId {
                destination: ipv4(192, 0, 2, 2),
                spi: 0x1020_3040,
                protocol: 50,
            },
            source_address: ipv4(192, 0, 2, 1),
            request_id: XfrmRequestId::new(7),
            auth: Some((
                AuthAlgorithm::hmac_sha256(128),
                KeyMaterial::new(vec![0x11; 32]),
            )),
            crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0x22; 16]))),
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

    fn policy_parameters() -> PolicyParameters {
        let sa = sa_parameters();
        PolicyParameters {
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
            mark: None,
            if_id: None,
        }
    }

    #[cfg(unix)]
    fn durable_object_requests() -> [XfrmObjectInstallRequest; 2] {
        [
            XfrmObjectInstallRequest::Sa(InstallSaRequest {
                parameters: sa_parameters(),
            }),
            XfrmObjectInstallRequest::Policy(InstallPolicyRequest {
                parameters: policy_parameters(),
            }),
        ]
    }

    #[cfg(unix)]
    fn durable_object_readback_body(request: &XfrmObjectInstallRequest) -> SensitiveBuffer {
        match request {
            XfrmObjectInstallRequest::Sa(request) => {
                crate::linux::test_sa_readback_body(&request.parameters).unwrap()
            }
            XfrmObjectInstallRequest::Policy(request) => {
                crate::linux::test_policy_readback_body(&request.parameters).unwrap()
            }
        }
    }

    #[cfg(unix)]
    fn duplicate_admission(
        authority: &XfrmObjectInstallAdmissionAuthority,
    ) -> XfrmObjectInstallAdmissionAuthority {
        XfrmObjectInstallAdmissionAuthority {
            operation: DurableObjectOperation {
                store: authority.operation.store.clone(),
                operation_id: authority.operation.operation_id,
                operation_generation: authority.operation.operation_generation,
                request: authority.operation.request.clone(),
            },
            prepared: authority.prepared.clone(),
            actor_binding: authority.actor_binding.clone(),
            seal: authority.seal.clone(),
        }
    }

    fn outbound_install_request() -> XfrmCompositeInstallRequest {
        XfrmCompositeInstallRequest {
            sa: InstallSaRequest {
                parameters: sa_parameters(),
            },
            policy: InstallPolicyRequest {
                parameters: policy_parameters(),
            },
        }
    }

    fn outbound_readback_at(
        request: &XfrmCompositeInstallRequest,
        last_assigned: u64,
    ) -> (SensitiveBuffer, SensitiveBuffer) {
        let mut observed = request.clone();
        let replay_state = if observed.sa.parameters.replay_window > 32 {
            let mut state = SaReplayState::fresh(observed.sa.parameters.replay_window);
            state.outbound_sequence = last_assigned as u32;
            state.outbound_sequence_hi = (last_assigned >> 32) as u32;
            state
        } else {
            SaReplayState::legacy(last_assigned as u32, 0, 0)
        };
        observed.sa.parameters.replay_state = Some(replay_state);
        crate::linux::test_outbound_binding_readback_bodies(&observed).unwrap()
    }

    fn counter_binding(
        backend: &NamespaceBoundLinuxXfrmBackend,
        request: &XfrmCompositeInstallRequest,
    ) -> InstalledOutboundSaBinding {
        InstalledOutboundSaBinding::new(
            backend.namespace_actor_binding(),
            validate_outbound_request(request).unwrap(),
        )
    }

    fn counter_request(
        binding: &InstalledOutboundSaBinding,
        request: &XfrmCompositeInstallRequest,
        operation: u128,
        generation: u64,
        requested_next: u64,
    ) -> EspCounterResumeApplyRequest {
        EspCounterResumeApplyRequest::new(
            EspCounterResumeBinding::new(operation, generation, binding.id(), requested_next)
                .unwrap(),
            request.sa.parameters.clone(),
        )
    }

    fn counter_recovery_request(
        binding: EspCounterResumeBinding,
        request: &XfrmCompositeInstallRequest,
    ) -> EspCounterResumeRecoveryRequest {
        EspCounterResumeRecoveryRequest::new(binding, request.sa.parameters.clone())
    }

    fn relocation_request() -> RelocateSaRequest {
        let sa = sa_parameters();
        RelocateSaRequest {
            current: SaRelocationIdentity {
                selector: SaRelocationSelector::from_selector(&sa.selector),
                id: sa.id,
                source_address: sa.source_address,
                request_id: sa.request_id,
                mode: sa.mode,
                encap: sa.encap,
                mark: sa.mark,
                if_id: sa.if_id,
                output_mark: sa.output_mark,
            },
            new_source_address: ipv4(198, 51, 100, 1),
            new_destination: ipv4(198, 51, 100, 2),
            encap: SaRelocationEncap::Preserve,
            direction: SaRelocationDirection::Inbound,
        }
    }

    fn allocate_request() -> AllocateSpiRequest {
        AllocateSpiRequest {
            destination: ipv4(192, 0, 2, 2),
            protocol: 50,
            min_spi: 0x100,
            max_spi: u32::MAX,
        }
    }

    fn query_request() -> QuerySaRequest {
        let sa = sa_parameters();
        QuerySaRequest::new(sa.id.destination, sa.id.protocol, sa.id.spi)
    }

    fn remove_request() -> RemoveSaRequest {
        let sa = sa_parameters();
        RemoveSaRequest::new(sa.id.destination, sa.id.protocol, sa.id.spi)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_backend_command_runs_on_the_captured_namespace_actor() {
        let expected_binding = NetworkNamespaceBinding::capture().unwrap();
        let invocation_thread = std::thread::current().id();
        let transport = RecordingUnavailableTransport::default();
        let backend = LinuxXfrmBackend::with_transport(transport.clone());
        let backend = backend.bind_current_network_namespace().unwrap();

        let sa = sa_parameters();
        let policy = policy_parameters();
        let _ = backend.allocate_spi(allocate_request()).await;
        let _ = backend
            .install_sa(InstallSaRequest {
                parameters: sa.clone(),
            })
            .await;
        let _ = backend.query_sa(query_request()).await;
        let _ = backend.query_sa_relocation_identity(query_request()).await;
        let _ = backend
            .rekey_sa(RekeySaRequest {
                parameters: sa.clone(),
            })
            .await;
        let _ = backend.relocate_sa(relocation_request()).await;
        let _ = backend.remove_sa(remove_request()).await;
        let _ = backend
            .install_policy(InstallPolicyRequest {
                parameters: policy.clone(),
            })
            .await;
        let _ = backend
            .rekey_policy(RekeyPolicyRequest {
                parameters: policy.clone(),
            })
            .await;
        let _ = backend
            .remove_policy(RemovePolicyRequest::new(
                policy.selector.clone(),
                policy.direction,
            ))
            .await;
        let _ = backend
            .remove_policy_exact(
                ExactRemovePolicyRequest::new(RemovePolicyRequest::new(
                    policy.selector,
                    policy.direction,
                ))
                .with_if_id(7),
            )
            .await;
        let _ = backend.probe().await;
        let _ = backend.sa_relocation_capability().await;

        let records = transport.records();
        assert_eq!(records.len(), 13);
        assert!(records
            .iter()
            .all(|record| record.binding == expected_binding));
        let actor_thread = records[0].thread;
        assert_ne!(actor_thread, invocation_thread);
        assert!(records.iter().all(|record| record.thread == actor_thread));
        assert_eq!(
            records
                .iter()
                .map(|record| record.operation)
                .collect::<Vec<_>>(),
            vec![
                "allocspi",
                "install_sa",
                "query_sa",
                "query_sa_relocation_identity",
                "rekey_sa",
                "relocate_sa_preflight",
                "remove_sa",
                "install_policy",
                "rekey_policy",
                "remove_policy",
                "remove_policy_exact_preflight",
                "probe",
                "probe",
            ]
        );
    }

    #[tokio::test]
    async fn exact_policy_removal_rejects_zero_before_namespace_dispatch() {
        let transport = RecordingUnavailableTransport::default();
        let backend = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace()
            .unwrap();
        let policy = policy_parameters();

        let error = backend
            .remove_policy_exact(
                ExactRemovePolicyRequest::new(RemovePolicyRequest::new(
                    policy.selector,
                    policy.direction,
                ))
                .with_if_id(0),
            )
            .await
            .expect_err("zero interface scope must fail before actor admission");

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "policy.if_id",
                ..
            }
        ));
        assert!(transport.records().is_empty());
    }

    #[tokio::test]
    async fn exact_policy_removal_rejects_narrow_mark_before_namespace_dispatch() {
        let transport = RecordingUnavailableTransport::default();
        let backend = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace()
            .unwrap();
        let policy = policy_parameters();
        let narrow = XfrmLookupMark::new(0x10, 0xf0).unwrap();

        let error = backend
            .remove_policy_exact(ExactRemovePolicyRequest::new(
                RemovePolicyRequest::new(policy.selector, policy.direction).with_mark(narrow),
            ))
            .await
            .expect_err("narrow lookup mark must fail before actor admission");

        assert!(matches!(
            error,
            XfrmError::InvalidConfig {
                field: "policy.mark",
                ..
            }
        ));
        assert!(transport.records().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn durable_store_is_atomically_attached_before_backend_is_returned() {
        let root = DurableTestRoot::new();
        let (backend, store) =
            LinuxXfrmBackend::with_transport(RecordingUnavailableTransport::default())
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x61; 32]).unwrap(),
                )
                .unwrap();
        assert!(store.advance_writer_epoch().is_ok());

        let error = LinuxXfrmBackend::with_transport(RecordingUnavailableTransport::default())
            .bind_current_network_namespace_with_object_recovery(
                root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x61; 32]).unwrap(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            XfrmObjectRecoveryBindError::Store {
                source: XfrmObjectInstallDurableError::StoreBusy
            }
        ));
        drop(store);
        drop(backend);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn acquired_authority_blocks_public_sa_and_policy_commands_before_transport() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace_with_object_recovery(
                root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x62; 32]).unwrap(),
            )
            .unwrap();
        let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
        let operation_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let request = XfrmObjectInstallRequest::Sa(InstallSaRequest {
            parameters: sa_parameters(),
        });

        let authority = backend
            .prepare_durable_object_install(&store, operation_id, operation_generation, request)
            .await
            .unwrap();
        assert!(transport.operations().is_empty());
        let outcome = backend.run_durable_object_install(authority).await.unwrap();
        assert_eq!(outcome.as_str(), "acquired");
        assert_eq!(transport.operations(), vec!["query_sa", "install_sa"]);

        assert!(matches!(
            backend.remove_sa(remove_request()).await,
            Err(XfrmError::Unavailable)
        ));
        assert!(matches!(
            backend
                .install_policy(InstallPolicyRequest {
                    parameters: policy_parameters(),
                })
                .await,
            Err(XfrmError::Unavailable)
        ));
        assert_eq!(transport.operations(), vec!["query_sa", "install_sa"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn normal_run_conflict_proof_admits_no_effect_for_preexisting_sa_and_policy() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let state = Arc::new(BlockingState::new());
            let readback = durable_object_readback_body(&request);
            let transport =
                BlockingBindingTransport::new_at_call(state, usize::MAX, [Ok(Some(readback))]);
            let capture = transport.clone();
            let (backend, store) = LinuxXfrmBackend::with_transport(transport)
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x63; 32]).unwrap(),
                )
                .unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(2).unwrap();
            let authority = backend
                .prepare_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();

            let outcome = backend.run_durable_object_install(authority).await.unwrap();
            assert!(matches!(
                outcome,
                XfrmObjectInstallDurableOutcome::NoMutation(_)
            ));
            let fingerprints = store.fingerprints_for_request(&request).unwrap();
            let record = store
                .restore(operation_id, generation, request.object(), fingerprints)
                .unwrap();
            assert_eq!(record.phase, XfrmObjectInstallDurablePhase::NoMutation);
            assert_eq!(
                record.pre_effect_proof,
                Some(XfrmObjectInstallPreEffectProof::Conflict)
            );
            let expected_readback = match &request {
                XfrmObjectInstallRequest::Sa(_) => "query_sa",
                XfrmObjectInstallRequest::Policy(_) => "query_policy",
            };
            assert_eq!(
                capture.operations(),
                vec![expected_readback],
                "a witnessed conflict must never admit an install effect"
            );
            assert!(matches!(
                backend
                    .recover_durable_object_install(&store, operation_id, generation, request,)
                    .await
                    .unwrap(),
                XfrmObjectInstallRestartOutcome::NoMutation
            ));
            assert_eq!(capture.operations(), vec![expected_readback]);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_sa_and_policy_are_durable_before_effect_and_recover_as_no_mutation() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let transport = RecordingSuccessTransport::default();
            let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x64; 32]).unwrap(),
                )
                .unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let operation_generation = XfrmObjectInstallOperationGeneration::new(2).unwrap();

            let authority = backend
                .prepare_durable_object_install(
                    &store,
                    operation_id,
                    operation_generation,
                    request.clone(),
                )
                .await
                .unwrap();
            assert_eq!(
                store.inspect(&authority.prepared),
                Ok(XfrmObjectInstallDurablePhase::Prepared)
            );
            assert!(transport.operations().is_empty());

            assert_eq!(
                backend
                    .prepare_durable_object_install(
                        &store,
                        operation_id,
                        operation_generation,
                        request.clone(),
                    )
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::Duplicate
            );

            let live_error = backend
                .recover_durable_object_install(
                    &store,
                    operation_id,
                    operation_generation,
                    request.clone(),
                )
                .await
                .unwrap_err();
            assert_eq!(live_error, XfrmObjectInstallDurableError::InvalidTransition);
            assert!(transport.operations().is_empty());

            drop(authority);
            let recovered = backend
                .recover_durable_object_install(&store, operation_id, operation_generation, request)
                .await
                .unwrap();
            assert!(matches!(
                recovered,
                XfrmObjectInstallRestartOutcome::NoMutation
            ));
            assert!(transport.operations().is_empty());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unpolled_sa_and_policy_issue_futures_admit_no_effect() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let transport = RecordingSuccessTransport::default();
            let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x65; 32]).unwrap(),
                )
                .unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let operation_generation = XfrmObjectInstallOperationGeneration::new(3).unwrap();
            let authority = backend
                .prepare_durable_object_install(
                    &store,
                    operation_id,
                    operation_generation,
                    request.clone(),
                )
                .await
                .unwrap();

            let issue = backend.run_durable_object_install(authority);
            drop(issue);
            assert!(transport.operations().is_empty());
            assert!(matches!(
                backend
                    .recover_durable_object_install(
                        &store,
                        operation_id,
                        operation_generation,
                        request,
                    )
                    .await
                    .unwrap(),
                XfrmObjectInstallRestartOutcome::NoMutation
            ));
            assert!(transport.operations().is_empty());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lost_prepare_reply_leaves_recoverable_prepared_truth() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let transport = RecordingSuccessTransport::default();
            let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x6d; 32]).unwrap(),
                )
                .unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(10).unwrap();
            let operation = DurableObjectOperation {
                store: store.clone(),
                operation_id,
                operation_generation: generation,
                request: request.clone(),
            };
            let (reply, lost_observer) = oneshot::channel();
            let permit = backend.inner.sender.reserve().await.unwrap();
            permit.send(NamespaceCommand::PrepareDurableObjectInstall(
                Box::new(operation),
                reply,
            ));
            drop(lost_observer);

            assert!(matches!(
                backend
                    .recover_durable_object_install(&store, operation_id, generation, request,)
                    .await
                    .unwrap(),
                XfrmObjectInstallRestartOutcome::NoMutation
            ));
            assert!(transport.operations().is_empty());
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lost_recover_reply_leaves_reconciliation_retryable_without_overlap() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let blocking = Arc::new(BlockingState::new());
            let (backend, store, _, _) = bind_with_capacity_and_recovery(
                LinuxXfrmBackend::with_transport(BlockingTransport {
                    state: Arc::clone(&blocking),
                }),
                1,
                Some((
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x6e; 32]).unwrap(),
                )),
                None,
                None,
            )
            .unwrap();
            let store = store.unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(11).unwrap();
            let authority = backend
                .prepare_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();
            // Cut the durable record at `Issuing` without any backend effect;
            // the scripted readback witnessed absence, so reconciliation must
            // converge as no-mutation without any kernel mutation.
            backend
                .detector_cut_prepared_issuing(authority, false)
                .await
                .unwrap();
            assert_eq!(
                durable_object_install_phase(&store, operation_id, generation, &request),
                Ok(XfrmObjectInstallDurablePhase::Issuing)
            );

            // Admit one reconciliation and lose its reply. The actor still
            // owns completion of the admitted work.
            let operation = DurableObjectOperation {
                store: store.clone(),
                operation_id,
                operation_generation: generation,
                request: request.clone(),
            };
            let (reply, lost_observer) = oneshot::channel();
            let permit = backend.inner.sender.reserve().await.unwrap();
            permit.send(NamespaceCommand::RecoverDurableObjectInstall(
                Box::new(operation),
                reply,
            ));
            drop(lost_observer);

            // The retry is serialized behind the lost admission and observes
            // its converged terminal state; no overlapping work or deletion.
            assert!(matches!(
                backend
                    .recover_durable_object_install(&store, operation_id, generation, request,)
                    .await
                    .unwrap(),
                XfrmObjectInstallRestartOutcome::Retired
            ));
            assert_eq!(blocking.mutation_calls.load(Ordering::Acquire), 0);
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lost_recover_reply_during_owned_removal_completes_once_and_retry_is_idempotent() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let blocking = Arc::new(BlockingState::new());
            let readback = durable_object_readback_body(&request);
            let transport = BlockingBindingTransport::new_at_call(
                Arc::clone(&blocking),
                3,
                [
                    Err(XfrmError::NotFound),
                    Ok(None),
                    Ok(Some(readback)),
                    Ok(None),
                ],
            );
            let capture = transport.clone();
            let (backend, store) = LinuxXfrmBackend::with_transport(transport)
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x6f; 32]).unwrap(),
                )
                .unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(12).unwrap();
            let authority = backend
                .prepare_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();
            backend
                .detector_cut_prepared_issuing(authority, true)
                .await
                .unwrap();

            let operation = DurableObjectOperation {
                store: store.clone(),
                operation_id,
                operation_generation: generation,
                request: request.clone(),
            };
            let (reply, lost_observer) = oneshot::channel();
            let permit = backend.inner.sender.reserve().await.unwrap();
            permit.send(NamespaceCommand::RecoverDurableObjectInstall(
                Box::new(operation),
                reply,
            ));
            drop(lost_observer);

            wait_until(|| blocking.calls.load(Ordering::Acquire) == 4).await;
            assert_eq!(
                durable_object_install_phase(&store, operation_id, generation, &request),
                Ok(XfrmObjectInstallDurablePhase::RemovalAdmitted),
                "deletion authority must be durable before the blocked remove"
            );

            let mut retry = tokio::spawn({
                let backend = backend.clone();
                let store = store.clone();
                let request = request.clone();
                async move {
                    backend
                        .recover_durable_object_install(&store, operation_id, generation, request)
                        .await
                }
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut retry)
                    .await
                    .is_err(),
                "retry must serialize behind the still-live admitted removal"
            );

            blocking.release();
            assert!(matches!(
                retry.await.unwrap().unwrap(),
                XfrmObjectInstallRestartOutcome::Retired
            ));
            let operations = capture.operations();
            assert_eq!(
                operations
                    .iter()
                    .filter(|operation| matches!(
                        **operation,
                        "remove_sa" | "remove_policy" | "remove_policy_exact"
                    ))
                    .count(),
                1,
                "lost completion observer must not duplicate the removal"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delete_ack_loss_retains_removal_authority_and_not_found_retry_retires_it() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let readback = durable_object_readback_body(&request);
            let transport = BlockingBindingTransport::new_at_call(
                Arc::new(BlockingState::new()),
                usize::MAX,
                [
                    Err(XfrmError::NotFound),
                    Ok(None),
                    Ok(Some(readback)),
                    Err(XfrmError::StateIndeterminate {
                        operation: "test_remove_ack_loss",
                    }),
                    Err(XfrmError::NotFound),
                ],
            );
            let capture = transport.clone();
            let (backend, store) = LinuxXfrmBackend::with_transport(transport)
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x70; 32]).unwrap(),
                )
                .unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(13).unwrap();
            let authority = backend
                .prepare_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();
            backend
                .detector_cut_prepared_issuing(authority, true)
                .await
                .unwrap();

            let first = backend
                .recover_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();
            assert!(matches!(
                first,
                XfrmObjectInstallRestartOutcome::RemovalPending {
                    source: XfrmError::StateIndeterminate {
                        operation: "test_remove_ack_loss"
                    }
                }
            ));
            assert_eq!(
                durable_object_install_phase(&store, operation_id, generation, &request),
                Ok(XfrmObjectInstallDurablePhase::RemovalAdmitted)
            );

            assert!(matches!(
                backend
                    .recover_durable_object_install(&store, operation_id, generation, request,)
                    .await
                    .unwrap(),
                XfrmObjectInstallRestartOutcome::OwnedResidueRetired
            ));
            let operations = capture.operations();
            assert_eq!(
                operations
                    .iter()
                    .filter(|operation| matches!(
                        **operation,
                        "remove_sa" | "remove_policy" | "remove_policy_exact"
                    ))
                    .count(),
                2,
                "the exact admitted removal is retried once after ACK loss"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_durable_issue_finishes_after_observer_cancellation() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let blocking = Arc::new(BlockingState::new());
            let (backend, store, _, _) = bind_with_capacity_and_recovery(
                LinuxXfrmBackend::with_transport(BlockingTransport {
                    state: Arc::clone(&blocking),
                }),
                1,
                Some((
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x6b; 32]).unwrap(),
                )),
                None,
                None,
            )
            .unwrap();
            let store = store.unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(8).unwrap();
            let authority = backend
                .prepare_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();
            let observer = tokio::spawn({
                let backend = backend.clone();
                async move { backend.run_durable_object_install(authority).await }
            });
            // The pre-effect readback resolves without blocking; the install
            // mutation is the call held at the barrier, and it runs only after
            // the durable `Issuing` publication.
            wait_until(|| blocking.mutation_calls.load(Ordering::Acquire) == 1).await;
            assert_eq!(
                durable_object_install_phase(&store, operation_id, generation, &request),
                Ok(XfrmObjectInstallDurablePhase::Issuing)
            );

            observer.abort();
            let _ = observer.await;
            blocking.release();
            assert_eq!(
                backend
                    .finalize_durable_object_install(&store, operation_id, generation, request,)
                    .await
                    .unwrap(),
                XfrmObjectInstallDurablePhase::Committed
            );
            assert_eq!(blocking.mutation_calls.load(Ordering::Acquire), 1);
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn durable_issue_cancelled_before_queue_admission_performs_no_effect() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let blocking = Arc::new(BlockingState::new());
            let (backend, store, _, _) = bind_with_capacity_and_recovery(
                LinuxXfrmBackend::with_transport(BlockingTransport {
                    state: Arc::clone(&blocking),
                }),
                1,
                Some((
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x6c; 32]).unwrap(),
                )),
                None,
                None,
            )
            .unwrap();
            let store = store.unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(9).unwrap();
            let authority = backend
                .prepare_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();

            let first = tokio::spawn({
                let backend = backend.clone();
                async move { backend.remove_sa(remove_request()).await }
            });
            wait_until(|| blocking.mutation_calls.load(Ordering::Acquire) == 1).await;
            let second = tokio::spawn({
                let backend = backend.clone();
                async move { backend.remove_sa(remove_request()).await }
            });
            wait_until(|| backend.inner.sender.capacity() == 0).await;

            let mut issue = Box::pin(backend.run_durable_object_install(authority));
            assert!(tokio::time::timeout(Duration::from_millis(10), &mut issue)
                .await
                .is_err());
            drop(issue);
            blocking.release();
            let _ = first.await;
            let _ = second.await;
            assert_eq!(blocking.mutation_calls.load(Ordering::Acquire), 2);
            assert!(matches!(
                backend
                    .recover_durable_object_install(&store, operation_id, generation, request,)
                    .await
                    .unwrap(),
                XfrmObjectInstallRestartOutcome::NoMutation
            ));
            assert_eq!(blocking.mutation_calls.load(Ordering::Acquire), 2);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn admission_validation_precedes_backend_and_wrong_seals_do_not_consume_it() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let transport = RecordingSuccessTransport::default();
            let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x66; 32]).unwrap(),
                )
                .unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let operation_generation = XfrmObjectInstallOperationGeneration::new(4).unwrap();
            let authority = backend
                .prepare_durable_object_install(
                    &store,
                    operation_id,
                    operation_generation,
                    request.clone(),
                )
                .await
                .unwrap();
            assert_eq!(
                format!("{authority:?}"),
                "XfrmObjectInstallAdmissionAuthority(<redacted>)"
            );

            let mut wrong_request = duplicate_admission(&authority);
            match &mut wrong_request.operation.request {
                XfrmObjectInstallRequest::Sa(request) => request.parameters.replay_window += 1,
                XfrmObjectInstallRequest::Policy(request) => request.parameters.priority += 1,
            }
            assert_eq!(
                backend
                    .run_durable_object_install(wrong_request)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::WrongBinding
            );

            let mut wrong_correlation = duplicate_admission(&authority);
            wrong_correlation.operation.operation_id =
                XfrmObjectInstallOperationId::generate().unwrap();
            assert_eq!(
                backend
                    .run_durable_object_install(wrong_correlation)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::Stale
            );

            let mut wrong_generation = duplicate_admission(&authority);
            wrong_generation.operation.operation_generation =
                XfrmObjectInstallOperationGeneration::new(44).unwrap();
            assert_eq!(
                backend
                    .run_durable_object_install(wrong_generation)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::Stale
            );

            let mut malformed = duplicate_admission(&authority);
            let mut encoded = malformed.prepared.to_bytes();
            let last = encoded.len() - 1;
            encoded[last] ^= 1;
            malformed.prepared = XfrmObjectInstallRecoveryHandle::from_bytes(encoded);
            assert_eq!(
                backend
                    .run_durable_object_install(malformed)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::AuthenticationFailed
            );

            let mut wrong_seal = duplicate_admission(&authority);
            wrong_seal.seal = Arc::new(());
            assert_eq!(
                backend
                    .run_durable_object_install(wrong_seal)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::Stale
            );
            assert!(transport.operations().is_empty());

            let duplicate = duplicate_admission(&authority);
            let outcome = backend.run_durable_object_install(duplicate).await.unwrap();
            assert!(matches!(
                outcome,
                XfrmObjectInstallDurableOutcome::Acquired(_)
            ));
            assert_eq!(transport.operations().len(), 2);
            assert_eq!(
                backend
                    .run_durable_object_install(authority)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::Stale
            );
            assert_eq!(transport.operations().len(), 2);
            assert_eq!(
                backend
                    .finalize_durable_object_install(
                        &store,
                        operation_id,
                        operation_generation,
                        request,
                    )
                    .await
                    .unwrap(),
                XfrmObjectInstallDurablePhase::Committed
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn another_actor_cannot_consume_admission_but_the_bound_actor_can() {
        let root = DurableTestRoot::new();
        let wrong_store_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace_with_object_recovery(
                root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x67; 32]).unwrap(),
            )
            .unwrap();
        let foreign_transport = RecordingSuccessTransport::default();
        let foreign = LinuxXfrmBackend::with_transport(foreign_transport.clone())
            .bind_current_network_namespace()
            .unwrap();
        let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
        let operation_generation = XfrmObjectInstallOperationGeneration::new(5).unwrap();
        let request = durable_object_requests()[0].clone();
        let authority = backend
            .prepare_durable_object_install(
                &store,
                operation_id,
                operation_generation,
                request.clone(),
            )
            .await
            .unwrap();

        let wrong_store = XfrmObjectInstallRecoveryStore::open_bound(
            wrong_store_root.path(),
            XfrmObjectRecoveryProofKey::new([0x6a; 32]).unwrap(),
            backend.network_namespace_binding().durable_bytes().unwrap(),
        )
        .unwrap();
        let mut wrong_store_attempt = duplicate_admission(&authority);
        wrong_store_attempt.operation.store = wrong_store;
        assert_eq!(
            backend
                .run_durable_object_install(wrong_store_attempt)
                .await
                .unwrap_err(),
            XfrmObjectInstallDurableError::WrongBinding
        );

        let foreign_attempt = duplicate_admission(&authority);

        assert_eq!(
            foreign
                .run_durable_object_install(foreign_attempt)
                .await
                .unwrap_err(),
            XfrmObjectInstallDurableError::WrongBinding
        );
        assert!(foreign_transport.operations().is_empty());
        assert!(transport.operations().is_empty());

        assert!(matches!(
            backend.run_durable_object_install(authority).await.unwrap(),
            XfrmObjectInstallDurableOutcome::Acquired(_)
        ));
        assert_eq!(transport.operations(), vec!["query_sa", "install_sa"]);
        assert_eq!(
            backend
                .finalize_durable_object_install(
                    &store,
                    operation_id,
                    operation_generation,
                    request,
                )
                .await
                .unwrap(),
            XfrmObjectInstallDurablePhase::Committed
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn same_identity_actor_replacement_invalidates_prepared_authority_before_backend() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let transport = RecordingSuccessTransport::default();
            let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x69; 32]).unwrap(),
                )
                .unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(7).unwrap();
            let authority = backend
                .prepare_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();

            match &request {
                XfrmObjectInstallRequest::Sa(request) => {
                    backend.install_sa(request.clone()).await.unwrap();
                }
                XfrmObjectInstallRequest::Policy(request) => {
                    backend.install_policy(request.clone()).await.unwrap();
                }
            }
            assert_eq!(transport.operations().len(), 1);
            assert_eq!(
                backend
                    .run_durable_object_install(authority)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::Stale
            );
            assert_eq!(transport.operations().len(), 1);
            assert!(matches!(
                backend
                    .recover_durable_object_install(&store, operation_id, generation, request,)
                    .await
                    .unwrap(),
                XfrmObjectInstallRestartOutcome::NoMutation
            ));
            assert_eq!(transport.operations().len(), 1);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fresh_seal_rejects_same_correlation_authority_after_reprepare() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let transport = RecordingSuccessTransport::default();
            let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x6e; 32]).unwrap(),
                )
                .unwrap();
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(11).unwrap();
            let old_authority = backend
                .prepare_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();

            match &request {
                XfrmObjectInstallRequest::Sa(request) => {
                    backend.install_sa(request.clone()).await.unwrap();
                }
                XfrmObjectInstallRequest::Policy(request) => {
                    backend.install_policy(request.clone()).await.unwrap();
                }
            }
            assert_eq!(transport.operations().len(), 1);
            assert!(matches!(
                backend
                    .recover_durable_object_install(
                        &store,
                        operation_id,
                        generation,
                        request.clone(),
                    )
                    .await
                    .unwrap(),
                XfrmObjectInstallRestartOutcome::NoMutation
            ));

            let replacement = backend
                .prepare_durable_object_install(&store, operation_id, generation, request.clone())
                .await
                .unwrap();
            let mut forged_current_handle = duplicate_admission(&old_authority);
            forged_current_handle.prepared = replacement.prepared.clone();
            assert_eq!(
                backend
                    .run_durable_object_install(forged_current_handle)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::Stale
            );
            assert_eq!(
                backend
                    .run_durable_object_install(old_authority)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::Stale
            );
            assert_eq!(transport.operations().len(), 1);

            assert!(matches!(
                backend
                    .run_durable_object_install(replacement)
                    .await
                    .unwrap(),
                XfrmObjectInstallDurableOutcome::Acquired(_)
            ));
            assert_eq!(transport.operations().len(), 3);
            assert_eq!(
                backend
                    .finalize_durable_object_install(&store, operation_id, generation, request,)
                    .await
                    .unwrap(),
                XfrmObjectInstallDurablePhase::Committed
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn distinct_prepared_authorities_survive_each_other_until_sequential_issue() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace_with_object_recovery(
                root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x68; 32]).unwrap(),
            )
            .unwrap();
        let [request_a, request_b] = durable_object_requests();
        let operation_a = XfrmObjectInstallOperationId::generate().unwrap();
        let operation_b = XfrmObjectInstallOperationId::generate().unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(6).unwrap();
        let authority_a = backend
            .prepare_durable_object_install(&store, operation_a, generation, request_a.clone())
            .await
            .unwrap();
        let authority_b = backend
            .prepare_durable_object_install(&store, operation_b, generation, request_b.clone())
            .await
            .unwrap();
        assert!(transport.operations().is_empty());

        assert!(matches!(
            backend
                .run_durable_object_install(authority_a)
                .await
                .unwrap(),
            XfrmObjectInstallDurableOutcome::Acquired(_)
        ));
        assert_eq!(
            backend
                .finalize_durable_object_install(&store, operation_a, generation, request_a,)
                .await
                .unwrap(),
            XfrmObjectInstallDurablePhase::Committed
        );
        assert!(matches!(
            backend
                .run_durable_object_install(authority_b)
                .await
                .unwrap(),
            XfrmObjectInstallDurableOutcome::Acquired(_)
        ));
        assert_eq!(
            backend
                .finalize_durable_object_install(&store, operation_b, generation, request_b,)
                .await
                .unwrap(),
            XfrmObjectInstallDurablePhase::Committed
        );
        assert_eq!(
            transport.operations(),
            vec!["query_sa", "install_sa", "query_policy", "install_policy"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn acquired_durable_authority_blocks_actor_mutation_admission() {
        let root = DurableTestRoot::new();
        let binding = NetworkNamespaceBinding::capture().unwrap();
        let mut state = NamespaceActorState::new(NamespaceActorBinding::new(binding));
        let store = XfrmObjectInstallRecoveryStore::open_bound(
            root.path(),
            XfrmObjectRecoveryProofKey::new([0x63; 32]).unwrap(),
            binding.durable_bytes().unwrap(),
        )
        .unwrap();
        state.object_recovery_store = Some(store.clone());
        let operation = XfrmObjectInstallOperationId::generate().unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let prepared = store
            .prepare(
                operation,
                generation,
                crate::XfrmInstallObject::Sa,
                crate::durable_object::DurableObjectFingerprints::repeated(0x64),
            )
            .unwrap();
        let issuing = store
            .transition(
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                Some(crate::durable_object::XfrmObjectInstallPreEffectProof::Absent),
            )
            .unwrap();
        let issuing = store.handle_for_record(&issuing).unwrap();
        store
            .transition(
                &issuing,
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::Acquired,
                None,
            )
            .unwrap();

        assert!(matches!(
            state.admit_xfrm_mutation(),
            Err(XfrmError::Unavailable)
        ));
    }

    fn backend_from_sender(
        sender: mpsc::Sender<NamespaceCommand>,
    ) -> NamespaceBoundLinuxXfrmBackend {
        NamespaceBoundLinuxXfrmBackend {
            inner: Arc::new(NamespaceBoundLinuxXfrmBackendInner {
                sender,
                actor_binding: NamespaceActorBinding::new(
                    NetworkNamespaceBinding::capture().unwrap(),
                ),
                #[cfg(unix)]
                retained_finish_runtime: None,
                retained_finish_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }),
        }
    }

    #[tokio::test]
    async fn closed_channel_before_admission_is_unavailable() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let backend = backend_from_sender(sender);
        assert!(matches!(backend.probe().await, Err(XfrmError::Unavailable)));
    }

    #[tokio::test]
    async fn lost_admitted_replies_distinguish_mutation_from_read() {
        let (mutation_sender, mut mutation_receiver) = mpsc::channel(1);
        let mutation_backend = backend_from_sender(mutation_sender);
        let mutation_worker = tokio::spawn(async move {
            drop(mutation_receiver.recv().await);
        });
        let mutation = mutation_backend.allocate_spi(allocate_request()).await;
        assert!(matches!(
            mutation,
            Err(XfrmError::StateIndeterminate {
                operation: "allocspi"
            })
        ));
        mutation_worker.await.unwrap();

        let (read_sender, mut read_receiver) = mpsc::channel(1);
        let read_backend = backend_from_sender(read_sender);
        let read_worker = tokio::spawn(async move {
            drop(read_receiver.recv().await);
        });
        assert!(matches!(
            read_backend.query_sa(query_request()).await,
            Err(XfrmError::Unavailable)
        ));
        read_worker.await.unwrap();
    }

    type RecoveryResponse = Result<Option<SensitiveBuffer>, XfrmError>;

    #[derive(Debug, Clone)]
    struct RecoveryTransport {
        responses: Arc<Mutex<VecDeque<RecoveryResponse>>>,
        calls: Arc<AtomicUsize>,
    }

    impl RecoveryTransport {
        fn new() -> Self {
            Self {
                responses: Arc::new(Mutex::new(VecDeque::from([
                    Err(XfrmError::StateIndeterminate {
                        operation: "query_sa",
                    }),
                    Ok(Some(Zeroizing::new(vec![0]))),
                    Ok(None),
                ]))),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl LinuxXfrmTransport for RecoveryTransport {
        fn transact(
            &self,
            _operation: &'static str,
            _operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or(Err(XfrmError::Unavailable))
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[tokio::test]
    async fn timeout_and_truncation_do_not_poison_the_next_transaction() {
        let transport = RecoveryTransport::new();
        let backend = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace()
            .unwrap();

        assert!(matches!(
            backend.query_sa(query_request()).await,
            Err(XfrmError::StateIndeterminate { .. })
        ));
        assert!(matches!(
            backend.query_sa(query_request()).await,
            Err(XfrmError::Io { .. })
        ));
        assert!(backend.remove_sa(remove_request()).await.is_ok());
        assert_eq!(transport.calls.load(Ordering::Acquire), 3);
    }

    #[derive(Debug)]
    struct BlockingState {
        calls: AtomicUsize,
        mutation_calls: AtomicUsize,
        released: AtomicBool,
        lock: Mutex<()>,
        wake: Condvar,
    }

    impl BlockingState {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                mutation_calls: AtomicUsize::new(0),
                released: AtomicBool::new(false),
                lock: Mutex::new(()),
                wake: Condvar::new(),
            }
        }

        fn release(&self) {
            self.released.store(true, Ordering::Release);
            self.wake.notify_all();
        }
    }

    #[derive(Debug, Clone)]
    struct BlockingTransport {
        state: Arc<BlockingState>,
    }

    impl LinuxXfrmTransport for BlockingTransport {
        fn transact(
            &self,
            _operation: &'static str,
            operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.state.calls.fetch_add(1, Ordering::AcqRel);
            match operation_class {
                // Pre-effect and recovery readback resolve immediately as an
                // absent identity; only mutations are held by the barrier.
                crate::linux::NetlinkOperationClass::ReadOnly => Err(XfrmError::NotFound),
                crate::linux::NetlinkOperationClass::Mutation => {
                    let mutation = self.state.mutation_calls.fetch_add(1, Ordering::AcqRel);
                    if mutation == 0 {
                        let mut guard = self
                            .state
                            .lock
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        while !self.state.released.load(Ordering::Acquire) {
                            guard = self
                                .state
                                .wake
                                .wait(guard)
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                        }
                    }
                    Ok(None)
                }
            }
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    async fn wait_until(mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !predicate() {
            assert!(Instant::now() < deadline, "condition did not become true");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_before_queue_admission_does_not_submit() {
        let state = Arc::new(BlockingState::new());
        let backend = bind_with_capacity(
            LinuxXfrmBackend::with_transport(BlockingTransport {
                state: Arc::clone(&state),
            }),
            1,
        )
        .unwrap();

        let first = tokio::spawn({
            let backend = backend.clone();
            async move { backend.remove_sa(remove_request()).await }
        });
        wait_until(|| state.calls.load(Ordering::Acquire) == 1).await;

        let second = tokio::spawn({
            let backend = backend.clone();
            async move { backend.remove_sa(remove_request()).await }
        });
        wait_until(|| backend.inner.sender.capacity() == 0).await;

        let mut cancelled = Box::pin(backend.remove_sa(remove_request()));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut cancelled)
                .await
                .is_err(),
            "full admission queue unexpectedly accepted a third command"
        );
        drop(cancelled);

        state.release();
        assert!(first.await.unwrap().is_ok());
        assert!(second.await.unwrap().is_ok());
        assert_eq!(state.calls.load(Ordering::Acquire), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_work_drains_after_caller_and_final_sender_drop() {
        let state = Arc::new(BlockingState::new());
        let backend = bind_with_capacity(
            LinuxXfrmBackend::with_transport(BlockingTransport {
                state: Arc::clone(&state),
            }),
            1,
        )
        .unwrap();

        let first = tokio::spawn({
            let backend = backend.clone();
            async move { backend.remove_sa(remove_request()).await }
        });
        wait_until(|| state.calls.load(Ordering::Acquire) == 1).await;
        let second = tokio::spawn({
            let backend = backend.clone();
            async move { backend.remove_sa(remove_request()).await }
        });
        wait_until(|| backend.inner.sender.capacity() == 0).await;

        first.abort();
        second.abort();
        let _ = first.await;
        let _ = second.await;
        drop(backend);
        state.release();

        wait_until(|| state.calls.load(Ordering::Acquire) == 2).await;
    }

    type BindingResponse = Result<Option<SensitiveBuffer>, XfrmError>;

    #[derive(Debug, Clone)]
    struct BindingTransport {
        responses: Arc<Mutex<VecDeque<BindingResponse>>>,
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    impl BindingTransport {
        fn new(responses: impl IntoIterator<Item = BindingResponse>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn operations(&self) -> Vec<&'static str> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl LinuxXfrmTransport for BindingTransport {
        fn transact(
            &self,
            operation: &'static str,
            _operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
            // The durable pre-effect/recovery exact readback models an absent
            // identity without consuming a scripted mutation response. The
            // outbound-binding readback queries keep their scripted bodies.
            if matches!(operation, "query_sa" | "query_policy") {
                return Err(XfrmError::NotFound);
            }
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or(Err(XfrmError::Unavailable))
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[derive(Debug, Clone)]
    struct BlockingBindingTransport {
        state: Arc<BlockingState>,
        block_call: usize,
        responses: Arc<Mutex<VecDeque<BindingResponse>>>,
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    impl BlockingBindingTransport {
        fn new_at_call(
            state: Arc<BlockingState>,
            block_call: usize,
            responses: impl IntoIterator<Item = BindingResponse>,
        ) -> Self {
            Self {
                state,
                block_call,
                responses: Arc::new(Mutex::new(responses.into_iter().collect())),
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn operations(&self) -> Vec<&'static str> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl LinuxXfrmTransport for BlockingBindingTransport {
        fn transact(
            &self,
            operation: &'static str,
            _operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
            let call = self.state.calls.fetch_add(1, Ordering::AcqRel);
            if call == self.block_call {
                let mut guard = self
                    .state
                    .lock
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                while !self.state.released.load(Ordering::Acquire) {
                    guard = self
                        .state
                        .wake
                        .wait(guard)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or(Err(XfrmError::Unavailable))
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[tokio::test]
    async fn applied_counter_survives_post_update_transport_faults_without_reapply() {
        let request = outbound_install_request();
        let (pre_policy, pre_sa) = outbound_readback_at(&request, 7);
        let (applied_policy, applied_sa) = outbound_readback_at(&request, 99);

        for fail_after_policy in [false, true] {
            let mut responses = vec![
                Ok(Some(pre_policy.clone())),
                Ok(Some(pre_sa.clone())),
                Ok(None),
            ];
            if fail_after_policy {
                responses.push(Ok(Some(applied_policy.clone())));
            }
            responses.push(Err(XfrmError::Unavailable));
            // Exact retry preflight/final readback, applied-receipt proof,
            // committed recovery, and committed-recovery proof.
            for _ in 0..5 {
                responses.push(Ok(Some(applied_policy.clone())));
                responses.push(Ok(Some(applied_sa.clone())));
            }

            let transport = BindingTransport::new(responses);
            let capture = transport.clone();
            let backend = LinuxXfrmBackend::with_transport(transport)
                .bind_current_network_namespace()
                .unwrap();
            let authority = counter_binding(&backend, &request);
            let target = authority.outbound_esp_counter_target();
            let apply = counter_request(&authority, &request, 1, 2, 100);
            let binding = apply.binding();

            let error = backend
                .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply.clone())
                .await
                .unwrap_err();
            assert_eq!(error.code(), "xfrm_outbound_sa_binding_readback_failed");

            let receipt = backend
                .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply)
                .await
                .unwrap();
            EspCounterResumeProofSet::single(receipt)
                .validate_counter_proof(
                    &target,
                    binding,
                    EspCounterProofRequirement::BeforeOwnershipCommit,
                )
                .await
                .unwrap();

            let recovered = backend
                .recover_committed_outbound_esp_counter(
                    &authority,
                    authority.id(),
                    counter_recovery_request(binding, &request),
                )
                .await
                .unwrap();
            let recovered = EspCounterResumeProofSet::single(recovered);
            recovered
                .validate_counter_proof(
                    &target,
                    binding,
                    EspCounterProofRequirement::CommittedRecovery,
                )
                .await
                .unwrap();
            let error = recovered
                .validate_counter_proof(
                    &target,
                    binding,
                    EspCounterProofRequirement::BeforeFirstPublication,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), "esp_counter_recovered_receipt_cannot_fence");
            assert_eq!(
                capture
                    .operations()
                    .iter()
                    .filter(|operation| **operation == "update_outbound_sa_replay_state")
                    .count(),
                1,
                "readback retry and committed recovery must remain read-only"
            );
        }
    }

    #[tokio::test]
    async fn counter_actor_advances_once_then_recovers_exact_retry_without_update() {
        let request = outbound_install_request();
        let (pre_policy, pre_sa) = outbound_readback_at(&request, 7);
        let (applied_policy, applied_sa) = outbound_readback_at(&request, 99);
        let transport = BindingTransport::new([
            // First preflight, one NEWAE ACK, and exact post-readback.
            Ok(Some(pre_policy)),
            Ok(Some(pre_sa)),
            Ok(None),
            Ok(Some(applied_policy.clone())),
            Ok(Some(applied_sa.clone())),
            // Receipt revalidation.
            Ok(Some(applied_policy.clone())),
            Ok(Some(applied_sa.clone())),
            // Exact retry preflight and mandatory final readback; no NEWAE.
            Ok(Some(applied_policy.clone())),
            Ok(Some(applied_sa.clone())),
            Ok(Some(applied_policy)),
            Ok(Some(applied_sa)),
        ]);
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace()
            .unwrap();
        let authority = counter_binding(&backend, &request);
        let apply = counter_request(&authority, &request, 1, 2, 100);
        let proof_binding = apply.binding();
        let target = authority.outbound_esp_counter_target();

        let receipt = backend
            .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply.clone())
            .await
            .unwrap();
        EspCounterResumeProofSet::single(receipt)
            .validate_counter_proof(
                &target,
                proof_binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap();
        backend
            .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply)
            .await
            .unwrap();

        assert_eq!(
            capture.operations(),
            vec![
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
                "update_outbound_sa_replay_state",
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_after_counter_update_cannot_reapply_on_exact_retry() {
        let request = outbound_install_request();
        let (pre_policy, pre_sa) = outbound_readback_at(&request, 7);
        let (applied_policy, applied_sa) = outbound_readback_at(&request, 99);
        let state = Arc::new(BlockingState::new());
        let transport = BlockingBindingTransport::new_at_call(
            Arc::clone(&state),
            3,
            [
                Ok(Some(pre_policy)),
                Ok(Some(pre_sa)),
                Ok(None),
                Ok(Some(applied_policy.clone())),
                Ok(Some(applied_sa.clone())),
                // Exact retry preflight/final readback.
                Ok(Some(applied_policy.clone())),
                Ok(Some(applied_sa.clone())),
                Ok(Some(applied_policy.clone())),
                Ok(Some(applied_sa.clone())),
                // Exact receipt validation after the retry.
                Ok(Some(applied_policy)),
                Ok(Some(applied_sa)),
            ],
        );
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace()
            .unwrap();
        let authority = counter_binding(&backend, &request);
        let apply = counter_request(&authority, &request, 1, 2, 100);
        let binding = apply.binding();
        let target = authority.outbound_esp_counter_target();
        let observer = tokio::spawn({
            let backend = backend.clone();
            let authority = authority.clone();
            let apply = apply.clone();
            async move {
                backend
                    .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply)
                    .await
            }
        });
        wait_until(|| state.calls.load(Ordering::Acquire) == 4).await;
        assert_eq!(
            capture
                .operations()
                .iter()
                .filter(|operation| **operation == "update_outbound_sa_replay_state")
                .count(),
            1,
            "the observer is cancelled only after the NEWAE update completed"
        );
        observer.abort();
        let _ = observer.await;
        state.release();
        wait_until(|| state.calls.load(Ordering::Acquire) == 5).await;

        let receipt = backend
            .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply)
            .await
            .unwrap();
        EspCounterResumeProofSet::single(receipt)
            .validate_counter_proof(
                &target,
                binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap();
        assert_eq!(
            capture
                .operations()
                .iter()
                .filter(|operation| **operation == "update_outbound_sa_replay_state")
                .count(),
            1,
            "retry after lost receipt must not apply the counter a second time"
        );
    }

    #[tokio::test]
    async fn counter_actor_never_rolls_an_already_advanced_sa_backward() {
        let request = outbound_install_request();
        let (policy, sa) = outbound_readback_at(&request, 100);
        let transport = BindingTransport::new([Ok(Some(policy)), Ok(Some(sa))]);
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace()
            .unwrap();
        let authority = counter_binding(&backend, &request);

        let error = backend
            .apply_and_read_back_outbound_esp_counter(
                &authority,
                authority.id(),
                counter_request(&authority, &request, 1, 2, 50),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_already_advanced");
        assert_eq!(
            capture.operations(),
            vec!["query_outbound_policy_binding", "query_outbound_sa_binding"]
        );
    }

    #[tokio::test]
    async fn receipt_from_identical_second_actor_cannot_prove_the_intended_target() {
        let request = outbound_install_request();
        let backend_a = LinuxXfrmBackend::with_transport(BindingTransport::new([]))
            .bind_current_network_namespace()
            .unwrap();
        let authority_a = counter_binding(&backend_a, &request);
        let target_a = authority_a.outbound_esp_counter_target();
        assert_eq!(
            format!("{target_a:?}"),
            "OutboundEspCounterTarget(<redacted>)"
        );

        let (policy, sa) = outbound_readback_at(&request, 49);
        let transport_b = BindingTransport::new([
            Ok(Some(policy.clone())),
            Ok(Some(sa.clone())),
            Ok(Some(policy)),
            Ok(Some(sa)),
        ]);
        let capture_b = transport_b.clone();
        let backend_b = LinuxXfrmBackend::with_transport(transport_b)
            .bind_current_network_namespace()
            .unwrap();
        let authority_b = counter_binding(&backend_b, &request);
        assert_eq!(authority_a.id(), authority_b.id());

        let apply = counter_request(&authority_b, &request, 7, 8, 50);
        let proof_binding = apply.binding();
        let receipt_b = backend_b
            .apply_and_read_back_outbound_esp_counter(&authority_b, authority_b.id(), apply)
            .await
            .unwrap();
        let error = EspCounterResumeProofSet::single(receipt_b)
            .validate_counter_proof(
                &target_a,
                proof_binding,
                EspCounterProofRequirement::BeforeOwnershipCommit,
            )
            .await
            .unwrap_err();

        assert_eq!(error.code(), "esp_counter_receipt_target_mismatch");
        assert_eq!(
            capture_b.operations(),
            vec![
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
            ],
            "target rejection must not validate through the receipt's foreign actor"
        );
    }

    #[tokio::test]
    async fn committed_counter_recovery_accepts_advanced_state_but_cannot_fence() {
        let request = outbound_install_request();
        let (policy, sa) = outbound_readback_at(&request, 100);
        let transport = BindingTransport::new([
            Ok(Some(policy.clone())),
            Ok(Some(sa.clone())),
            Ok(Some(policy.clone())),
            Ok(Some(sa.clone())),
            Ok(Some(policy)),
            Ok(Some(sa)),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace()
            .unwrap();
        let authority = counter_binding(&backend, &request);
        let target = authority.outbound_esp_counter_target();
        let binding = EspCounterResumeBinding::new(11, 12, authority.id(), 50).unwrap();
        let receipt = backend
            .recover_committed_outbound_esp_counter(
                &authority,
                authority.id(),
                counter_recovery_request(binding, &request),
            )
            .await
            .unwrap();
        let proofs = EspCounterResumeProofSet::single(receipt);
        proofs
            .validate_counter_proof(
                &target,
                binding,
                EspCounterProofRequirement::CommittedRecovery,
            )
            .await
            .unwrap();
        for requirement in [
            EspCounterProofRequirement::BeforeOwnershipCommit,
            EspCounterProofRequirement::BeforeFirstPublication,
        ] {
            let error = proofs
                .validate_counter_proof(&target, binding, requirement)
                .await
                .unwrap_err();
            assert_eq!(error.code(), "esp_counter_recovered_receipt_cannot_fence");
        }
        for mismatched in [
            EspCounterResumeBinding::new(13, 12, authority.id(), 50).unwrap(),
            EspCounterResumeBinding::new(11, 13, authority.id(), 50).unwrap(),
        ] {
            let error = proofs
                .validate_counter_proof(
                    &target,
                    mismatched,
                    EspCounterProofRequirement::CommittedRecovery,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), "esp_counter_receipt_absent_or_stale");
        }

        let below_floor = EspCounterResumeBinding::new(14, 15, authority.id(), 200).unwrap();
        let error = backend
            .recover_committed_outbound_esp_counter(
                &authority,
                authority.id(),
                counter_recovery_request(below_floor, &request),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_committed_recovery_below_floor");
    }

    #[tokio::test]
    async fn committed_counter_recovery_never_regresses_below_issuance_watermark() {
        for (current_last, expected_error) in [
            (50, Some("esp_counter_receipt_below_issuance_watermark")),
            (101, None),
        ] {
            let request = outbound_install_request();
            let (recovery_policy, recovery_sa) = outbound_readback_at(&request, 100);
            let (current_policy, current_sa) = outbound_readback_at(&request, current_last);
            let transport = BindingTransport::new([
                Ok(Some(recovery_policy)),
                Ok(Some(recovery_sa)),
                Ok(Some(current_policy)),
                Ok(Some(current_sa)),
            ]);
            let backend = LinuxXfrmBackend::with_transport(transport)
                .bind_current_network_namespace()
                .unwrap();
            let authority = counter_binding(&backend, &request);
            let target = authority.outbound_esp_counter_target();
            let binding = EspCounterResumeBinding::new(21, 22, authority.id(), 50).unwrap();
            let receipt = backend
                .recover_committed_outbound_esp_counter(
                    &authority,
                    authority.id(),
                    counter_recovery_request(binding, &request),
                )
                .await
                .unwrap();
            let result = EspCounterResumeProofSet::single(receipt)
                .validate_counter_proof(
                    &target,
                    binding,
                    EspCounterProofRequirement::CommittedRecovery,
                )
                .await;
            match expected_error {
                Some(code) => assert_eq!(result.unwrap_err().code(), code),
                None => result.expect("state above the issuance watermark remains valid"),
            }
        }
    }

    #[tokio::test]
    async fn counter_actor_rejects_wrong_namespace_id_and_sa_before_netlink() {
        let request = outbound_install_request();
        let transport = BindingTransport::new([]);
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace()
            .unwrap();
        let authority = counter_binding(&backend, &request);

        let current = backend.network_namespace_binding();
        let foreign = InstalledOutboundSaBinding::new(
            NamespaceActorBinding::new(NetworkNamespaceBinding {
                device: current.device.wrapping_add(1),
                inode: current.inode.wrapping_add(1),
                ..current
            }),
            validate_outbound_request(&request).unwrap(),
        );
        let error = backend
            .apply_and_read_back_outbound_esp_counter(
                &foreign,
                foreign.id(),
                counter_request(&foreign, &request, 1, 2, 50),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "xfrm_outbound_sa_binding_namespace_mismatch");
        let recovery_binding = EspCounterResumeBinding::new(9, 10, foreign.id(), 50).unwrap();
        let error = backend
            .recover_committed_outbound_esp_counter(
                &foreign,
                foreign.id(),
                counter_recovery_request(recovery_binding, &request),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "xfrm_outbound_sa_binding_namespace_mismatch");

        let wrong_id = OutboundSaBindingId::from_bytes([0x5a; 32]);
        let error = backend
            .apply_and_read_back_outbound_esp_counter(
                &authority,
                wrong_id,
                counter_request(&authority, &request, 2, 3, 50),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_binding_id_mismatch");

        let mut wrong_sa = request.sa.parameters.clone();
        wrong_sa.id.spi = wrong_sa.id.spi.wrapping_add(1);
        let binding = EspCounterResumeBinding::new(3, 4, authority.id(), 50).unwrap();
        let error = backend
            .apply_and_read_back_outbound_esp_counter(
                &authority,
                authority.id(),
                EspCounterResumeApplyRequest::new(binding, wrong_sa),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            "xfrm_outbound_sa_binding_sa_identity_mismatch"
        );
        let mut wrong_recovery_sa = request.sa.parameters.clone();
        wrong_recovery_sa.mark = Some(crate::XfrmLookupMark::full(1));
        let recovery_binding = EspCounterResumeBinding::new(5, 6, authority.id(), 50).unwrap();
        let error = backend
            .recover_committed_outbound_esp_counter(
                &authority,
                authority.id(),
                EspCounterResumeRecoveryRequest::new(recovery_binding, wrong_recovery_sa),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            "xfrm_outbound_sa_binding_sa_identity_mismatch"
        );
        assert!(capture.operations().is_empty());
    }

    #[tokio::test]
    async fn failed_unrelated_actor_mutation_still_invalidates_counter_receipt() {
        let request = outbound_install_request();
        let (policy, sa) = outbound_readback_at(&request, 49);
        let transport = BindingTransport::new([
            Ok(Some(policy.clone())),
            Ok(Some(sa.clone())),
            Ok(Some(policy)),
            Ok(Some(sa)),
            // Even a failed generic mutation invalidates before execution.
            Err(XfrmError::Unavailable),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace()
            .unwrap();
        let authority = counter_binding(&backend, &request);
        let target = authority.outbound_esp_counter_target();
        let apply = counter_request(&authority, &request, 1, 2, 50);
        let proof_binding = apply.binding();
        let receipt = backend
            .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply)
            .await
            .unwrap();

        backend
            .install_sa(InstallSaRequest {
                parameters: request.sa.parameters,
            })
            .await
            .unwrap_err();
        let error = EspCounterResumeProofSet::single(receipt)
            .validate_counter_proof(
                &target,
                proof_binding,
                EspCounterProofRequirement::BeforeFirstPublication,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_receipt_absent_or_stale");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publication_guard_queues_invalidating_mutation_until_drop() {
        let request = outbound_install_request();
        let (policy, sa) = outbound_readback_at(&request, 49);
        let transport = BindingTransport::new([
            Ok(Some(policy.clone())),
            Ok(Some(sa.clone())),
            Ok(Some(policy.clone())),
            Ok(Some(sa.clone())),
            // Guard acquisition performs final exact policy/SA readback.
            Ok(Some(policy)),
            Ok(Some(sa)),
            // The queued mutation runs only after guard release.
            Err(XfrmError::Unavailable),
        ]);
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace()
            .unwrap();
        let authority = counter_binding(&backend, &request);
        let target = authority.outbound_esp_counter_target();
        let apply = counter_request(&authority, &request, 1, 2, 50);
        let binding = apply.binding();
        let receipt = backend
            .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply)
            .await
            .unwrap();
        let proofs = EspCounterResumeProofSet::single(receipt);
        let guard = proofs
            .acquire_publication_guard(
                &target,
                binding,
                EspCounterProofRequirement::BeforeFirstPublication,
            )
            .await
            .unwrap();

        let mutation = tokio::spawn({
            let backend = backend.clone();
            let parameters = request.sa.parameters.clone();
            async move { backend.install_sa(InstallSaRequest { parameters }).await }
        });
        tokio::task::yield_now().await;
        assert!(!mutation.is_finished());
        assert_eq!(capture.operations().len(), 6);

        drop(guard);
        mutation
            .await
            .expect("queued mutation task")
            .expect_err("injected mutation failure");
        assert_eq!(capture.operations().len(), 7);
        let error = proofs
            .validate_counter_proof(
                &target,
                binding,
                EspCounterProofRequirement::BeforeFirstPublication,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_receipt_absent_or_stale");
    }

    #[tokio::test]
    async fn first_publication_guard_rejects_counter_advance_after_exact_apply() {
        let request = outbound_install_request();
        let (policy_49, sa_49) = outbound_readback_at(&request, 49);
        let (policy_50, sa_50) = outbound_readback_at(&request, 50);
        let transport = BindingTransport::new([
            Ok(Some(policy_49.clone())),
            Ok(Some(sa_49.clone())),
            Ok(Some(policy_49)),
            Ok(Some(sa_49)),
            // Final guard acquisition observes a packet assigned after the
            // exact receipt check and must not mint a publication lease.
            Ok(Some(policy_50)),
            Ok(Some(sa_50)),
        ]);
        let backend = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace()
            .unwrap();
        let authority = counter_binding(&backend, &request);
        let target = authority.outbound_esp_counter_target();
        let apply = counter_request(&authority, &request, 1, 2, 50);
        let binding = apply.binding();
        let receipt = backend
            .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply)
            .await
            .unwrap();
        let error = EspCounterResumeProofSet::single(receipt)
            .acquire_publication_guard(
                &target,
                binding,
                EspCounterProofRequirement::BeforeFirstPublication,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_receipt_exact_state_changed");
    }

    #[tokio::test]
    async fn staged_commit_is_the_only_fresh_outbound_binding_issuance_path() {
        let request = outbound_install_request();
        let expected_id = validate_outbound_request(&request).unwrap().id();
        let (policy, sa) = test_outbound_binding_readback_bodies(&request).unwrap();
        let transport = BindingTransport::new([Ok(None), Ok(None), Ok(Some(policy)), Ok(Some(sa))]);
        let capture = transport.clone();
        let backend = Arc::new(
            LinuxXfrmBackend::with_transport(transport)
                .bind_current_network_namespace()
                .unwrap(),
        );

        let binding = XfrmStagedInstall::new(request)
            .run_and_commit_outbound_sa_policy(Arc::clone(&backend))
            .await
            .unwrap();

        assert_eq!(binding.id(), expected_id);
        assert_eq!(binding.namespace(), backend.network_namespace_binding());
        assert_eq!(
            capture.operations(),
            vec![
                "install_sa",
                "install_policy",
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
            ]
        );
    }

    #[tokio::test]
    async fn acknowledged_install_without_exact_readback_never_mints_a_binding() {
        let transport = BindingTransport::new([Ok(None), Ok(None), Ok(None)]);
        let capture = transport.clone();
        let backend = Arc::new(
            LinuxXfrmBackend::with_transport(transport)
                .bind_current_network_namespace()
                .unwrap(),
        );
        let staged = XfrmStagedInstall::new(outbound_install_request());
        let journal = staged.journal();

        let error = staged
            .run_and_commit_outbound_sa_policy(backend)
            .await
            .unwrap_err();

        assert!(matches!(error, OutboundSaBindingError::Readback { .. }));
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Complete);
        assert_eq!(
            capture.operations(),
            vec![
                "install_sa",
                "install_policy",
                "query_outbound_policy_binding",
            ]
        );
    }

    #[tokio::test]
    async fn ambiguous_all_zero_key_readback_fails_closed_before_fresh_mint() {
        let mut request = outbound_install_request();
        request.sa.parameters.auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0; 32]);
        request.sa.parameters.crypt.as_mut().unwrap().1 = KeyMaterial::new(vec![0; 16]);
        let (policy, sa) = test_outbound_binding_readback_bodies(&request).unwrap();
        let transport = BindingTransport::new([Ok(None), Ok(None), Ok(Some(policy)), Ok(Some(sa))]);
        let backend = Arc::new(
            LinuxXfrmBackend::with_transport(transport)
                .bind_current_network_namespace()
                .unwrap(),
        );
        let staged = XfrmStagedInstall::new(request);
        let journal = staged.journal();

        let error = staged
            .run_and_commit_outbound_sa_policy(backend)
            .await
            .unwrap_err();

        assert_eq!(
            error.code(),
            "xfrm_outbound_sa_binding_key_readback_unavailable"
        );
        assert_eq!(
            format!("{error:?}"),
            "OutboundSaBindingError { code: \"xfrm_outbound_sa_binding_key_readback_unavailable\" }"
        );
        assert_eq!(journal.ownership(), XfrmInstallOwnership::Complete);
    }

    #[tokio::test]
    async fn partial_staged_install_never_returns_an_outbound_binding() {
        let transport = BindingTransport::new([
            Ok(None),
            Err(XfrmError::io(
                "install_policy",
                std::io::Error::other("test failure"),
            )),
            Ok(None),
        ]);
        let capture = transport.clone();
        let backend = Arc::new(
            LinuxXfrmBackend::with_transport(transport)
                .bind_current_network_namespace()
                .unwrap(),
        );

        let error = XfrmStagedInstall::new(outbound_install_request())
            .run_and_commit_outbound_sa_policy(backend)
            .await
            .unwrap_err();

        assert!(matches!(error, OutboundSaBindingError::Install { .. }));
        assert_eq!(
            capture.operations(),
            vec!["install_sa", "install_policy", "remove_sa"]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_binding_observer_never_commits_or_returns_authority() {
        let state = Arc::new(BlockingState::new());
        let backend = Arc::new(
            LinuxXfrmBackend::with_transport(BlockingTransport {
                state: Arc::clone(&state),
            })
            .bind_current_network_namespace()
            .unwrap(),
        );
        let staged = XfrmStagedInstall::new(outbound_install_request());
        let journal = staged.journal();
        let observer = tokio::spawn(staged.run_and_commit_outbound_sa_policy(backend));
        wait_until(|| state.calls.load(Ordering::Acquire) == 1).await;

        observer.abort();
        let _ = observer.await;
        state.release();
        wait_until(|| state.calls.load(Ordering::Acquire) == 2).await;
        wait_until(|| journal.ownership() == XfrmInstallOwnership::Complete).await;

        assert_ne!(journal.ownership(), XfrmInstallOwnership::Committed);
    }

    #[tokio::test]
    async fn process_loss_recovery_reproduces_id_only_after_actor_readback() {
        let request = outbound_install_request();
        let expected_id = validate_outbound_request(&request).unwrap().id();
        let (policy, sa) = test_outbound_binding_readback_bodies(&request).unwrap();
        let transport = BindingTransport::new([
            Ok(Some(policy.clone())),
            Ok(Some(sa.clone())),
            Ok(Some(policy)),
            Ok(Some(sa)),
        ]);
        let capture = transport.clone();
        let backend = LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace()
            .unwrap();

        let binding = backend
            .recover_installed_outbound_sa_binding(request.clone())
            .await
            .unwrap();
        assert_eq!(binding.id(), expected_id);
        binding
            .validate_current(&backend, &request.sa.parameters, expected_id)
            .await
            .unwrap();
        assert_eq!(
            capture.operations(),
            vec![
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
                "query_outbound_policy_binding",
                "query_outbound_sa_binding",
            ]
        );
    }

    #[derive(Debug, Clone)]
    struct DscpRecordingRuntime {
        records: Arc<Mutex<Vec<(ThreadId, NetworkNamespaceBinding)>>>,
    }

    impl XfrmDscpRuntime for DscpRecordingRuntime {
        fn fresh_namespace_runtime(&self) -> Arc<dyn XfrmDscpRuntime> {
            Arc::new(self.clone())
        }

        fn ensure_ready(&self, _config: &LinuxXfrmDscpMarkingConfig) -> Result<(), XfrmError> {
            self.records
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((
                    std::thread::current().id(),
                    NetworkNamespaceBinding::capture()?,
                ));
            Ok(())
        }

        fn capability(&self, _config: &LinuxXfrmDscpMarkingConfig) -> XfrmCapability {
            XfrmCapability::Available
        }
    }

    #[derive(Debug)]
    struct DeferredDscpRuntimeState {
        records: Mutex<Vec<(ThreadId, NetworkNamespaceBinding)>>,
        outcomes: Mutex<VecDeque<Result<(), XfrmError>>>,
        blocker: Option<Arc<BlockingState>>,
        capability_calls: AtomicUsize,
    }

    #[derive(Debug, Clone)]
    struct DeferredDscpRuntime {
        state: Arc<DeferredDscpRuntimeState>,
    }

    impl DeferredDscpRuntime {
        fn with_outcomes(outcomes: impl IntoIterator<Item = Result<(), XfrmError>>) -> Self {
            Self {
                state: Arc::new(DeferredDscpRuntimeState {
                    records: Mutex::new(Vec::new()),
                    outcomes: Mutex::new(outcomes.into_iter().collect()),
                    blocker: None,
                    capability_calls: AtomicUsize::new(0),
                }),
            }
        }

        fn blocking(blocker: Arc<BlockingState>) -> Self {
            Self {
                state: Arc::new(DeferredDscpRuntimeState {
                    records: Mutex::new(Vec::new()),
                    outcomes: Mutex::new(VecDeque::new()),
                    blocker: Some(blocker),
                    capability_calls: AtomicUsize::new(0),
                }),
            }
        }

        fn records(&self) -> Vec<(ThreadId, NetworkNamespaceBinding)> {
            self.state
                .records
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn capability_calls(&self) -> usize {
            self.state.capability_calls.load(Ordering::Acquire)
        }
    }

    impl XfrmDscpRuntime for DeferredDscpRuntime {
        fn fresh_namespace_runtime(&self) -> Arc<dyn XfrmDscpRuntime> {
            Arc::new(self.clone())
        }

        fn ensure_ready(&self, _config: &LinuxXfrmDscpMarkingConfig) -> Result<(), XfrmError> {
            self.state
                .records
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((
                    std::thread::current().id(),
                    NetworkNamespaceBinding::capture()?,
                ));
            if let Some(blocker) = &self.state.blocker {
                let call = blocker.calls.fetch_add(1, Ordering::AcqRel);
                if call == 0 {
                    let mut guard = blocker
                        .lock
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    while !blocker.released.load(Ordering::Acquire) {
                        guard = blocker
                            .wake
                            .wait(guard)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
            }
            self.state
                .outcomes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or(Ok(()))
        }

        fn capability(&self, _config: &LinuxXfrmDscpMarkingConfig) -> XfrmCapability {
            self.state.capability_calls.fetch_add(1, Ordering::AcqRel);
            XfrmCapability::Available
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct SuccessfulTransport;

    impl LinuxXfrmTransport for SuccessfulTransport {
        fn transact(
            &self,
            _operation: &'static str,
            _operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            Ok(None)
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[tokio::test]
    async fn dscp_readiness_moves_to_and_stays_on_the_namespace_actor() {
        let records = Arc::new(Mutex::new(Vec::new()));
        let runtime = DscpRecordingRuntime {
            records: Arc::clone(&records),
        };
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
        let backend =
            LinuxXfrmBackend::with_transport_and_dscp_runtime(SuccessfulTransport, config, runtime)
                .unwrap();
        let caller_thread = std::thread::current().id();
        let binding = NetworkNamespaceBinding::capture().unwrap();
        let backend = backend.bind_current_network_namespace().unwrap();

        let mut sa = sa_parameters();
        sa.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let _ = backend
            .install_sa(InstallSaRequest { parameters: sa })
            .await;

        let records = records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].0, caller_thread);
        assert_ne!(records[1].0, caller_thread);
        assert_eq!(records[1].0, records[2].0);
        assert!(records
            .iter()
            .all(|(_, observed_binding)| *observed_binding == binding));
    }

    #[tokio::test]
    async fn deferred_dscp_activation_is_actor_local_idempotent_and_capability_gated() {
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let readback = crate::linux::test_dscp_sa_readback_body(&marked, &config).unwrap();
        let transport = BindingTransport::new([Ok(None), Ok(Some(readback))]);
        let runtime = DeferredDscpRuntime::with_outcomes([]);
        let backend = LinuxXfrmBackend::with_transport_and_deferred_dscp_runtime(
            transport.clone(),
            config.clone(),
            runtime.clone(),
        )
        .unwrap();

        assert!(
            runtime.records().is_empty(),
            "construction must be effect-free"
        );
        let caller_thread = std::thread::current().id();
        let binding = NetworkNamespaceBinding::capture().unwrap();
        let backend = backend.bind_current_network_namespace().unwrap();
        assert!(runtime.records().is_empty(), "binding must be effect-free");
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Unknown
        );
        assert_eq!(runtime.capability_calls(), 0);

        assert!(matches!(
            backend
                .install_sa(InstallSaRequest {
                    parameters: marked.clone(),
                })
                .await,
            Err(XfrmError::Unavailable)
        ));
        assert!(transport.operations().is_empty());
        assert!(runtime.records().is_empty());

        let mut relocation = relocation_request();
        let profile = config.profile().unwrap();
        relocation.current.output_mark = Some(crate::XfrmMark {
            value: profile.encode_token(46).unwrap(),
            mask: profile.mask,
        });
        assert!(matches!(
            backend.relocate_sa(relocation).await,
            Err(XfrmError::Unavailable)
        ));

        let mut counter_install = outbound_install_request();
        counter_install.sa.parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let counter_authority = counter_binding(&backend, &counter_install);
        let counter_apply = counter_request(&counter_authority, &counter_install, 0x624, 1, 100);
        let counter_error = backend
            .apply_and_read_back_outbound_esp_counter(
                &counter_authority,
                counter_authority.id(),
                counter_apply,
            )
            .await
            .unwrap_err();
        assert_eq!(counter_error.code(), "esp_counter_backend_unavailable");
        assert!(transport.operations().is_empty());
        assert!(runtime.records().is_empty());

        backend.activate_dscp_marking().await.unwrap();
        backend.activate_dscp_marking().await.unwrap();
        let activation_records = runtime.records();
        assert_eq!(activation_records.len(), 1);
        assert_ne!(activation_records[0].0, caller_thread);
        assert_eq!(activation_records[0].1, binding);
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Unknown,
            "runtime readiness alone is not XFRM attribute proof"
        );

        backend
            .install_sa(InstallSaRequest { parameters: marked })
            .await
            .unwrap();
        let records = runtime.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].0, records[1].0);
        assert!(records
            .iter()
            .all(|(_, observed_binding)| *observed_binding == binding));
        assert_eq!(
            transport.operations(),
            vec!["install_sa", "install_sa_dscp_readback"]
        );
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Available
        );
    }

    #[tokio::test]
    async fn clean_deferred_dscp_activation_failure_is_closed_and_retryable() {
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
        let runtime = DeferredDscpRuntime::with_outcomes([Err(XfrmError::Unavailable), Ok(())]);
        let backend = LinuxXfrmBackend::with_transport_and_deferred_dscp_runtime(
            SuccessfulTransport,
            config,
            runtime.clone(),
        )
        .unwrap()
        .bind_current_network_namespace()
        .unwrap();

        assert!(matches!(
            backend.activate_dscp_marking().await,
            Err(XfrmError::Unavailable)
        ));
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Unknown
        );
        assert_eq!(runtime.capability_calls(), 0);
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        assert!(matches!(
            backend
                .install_sa(InstallSaRequest { parameters: marked })
                .await,
            Err(XfrmError::Unavailable)
        ));

        backend.activate_dscp_marking().await.unwrap();
        backend.activate_dscp_marking().await.unwrap();
        let records = runtime.records();
        assert_eq!(records.len(), 2, "successful activation is published once");
        assert_eq!(records[0].0, records[1].0, "retry stays on the same actor");
        assert_eq!(records[0].1, records[1].1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_deferred_dscp_activation_cannot_publish_readiness() {
        let blocker = Arc::new(BlockingState::new());
        let runtime = DeferredDscpRuntime::blocking(Arc::clone(&blocker));
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
        let transport = BindingTransport::new(std::iter::empty::<BindingResponse>());
        let backend = LinuxXfrmBackend::with_transport_and_deferred_dscp_runtime(
            transport.clone(),
            config,
            runtime.clone(),
        )
        .unwrap()
        .bind_current_network_namespace()
        .unwrap();

        let observer = tokio::spawn({
            let backend = backend.clone();
            async move { backend.activate_dscp_marking().await }
        });
        wait_until(|| blocker.calls.load(Ordering::Acquire) == 1).await;
        observer.abort();
        let _ = observer.await;
        blocker.release();

        // Probe is actor-serialized behind the cancelled activation and thus
        // also proves that its runtime call has returned.
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Unknown
        );
        assert_eq!(runtime.capability_calls(), 0);
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        assert!(matches!(
            backend
                .install_sa(InstallSaRequest { parameters: marked })
                .await,
            Err(XfrmError::Unavailable)
        ));
        assert!(transport.operations().is_empty());

        backend.activate_dscp_marking().await.unwrap();
        assert_eq!(runtime.records().len(), 2);
    }

    #[tokio::test]
    async fn unobserved_successful_activation_reply_cannot_publish_readiness() {
        let runtime = DeferredDscpRuntime::with_outcomes([]);
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
        let transport = BindingTransport::new(std::iter::empty::<BindingResponse>());
        let backend = LinuxXfrmBackend::with_transport_and_deferred_dscp_runtime(
            transport.clone(),
            config,
            runtime.clone(),
        )
        .unwrap()
        .bind_current_network_namespace()
        .unwrap();

        let permit = backend.inner.sender.reserve().await.unwrap();
        let (reply_sender, reply_receiver) = oneshot::channel();
        let (observed_sender, observed_receiver) = oneshot::channel();
        permit.send(NamespaceCommand::ActivateDscpMarking {
            reply: reply_sender,
            observed: observed_receiver,
        });
        assert!(reply_receiver.await.unwrap().is_ok());
        // This is the protocol cut reached when the public observer is
        // cancelled after delivery but before it can acknowledge observation.
        drop(observed_sender);

        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Unknown
        );
        let mut marked = sa_parameters();
        marked.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        assert!(matches!(
            backend
                .install_sa(InstallSaRequest { parameters: marked })
                .await,
            Err(XfrmError::Unavailable)
        ));
        assert!(transport.operations().is_empty());
        assert_eq!(runtime.records().len(), 1);

        backend.activate_dscp_marking().await.unwrap();
        assert_eq!(runtime.records().len(), 2);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deferred_binding_keeps_durable_recovery_available_without_dscp_effects() {
        let root = DurableTestRoot::new();
        let runtime = DeferredDscpRuntime::with_outcomes([]);
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
        let mut parameters = sa_parameters();
        parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let readback = crate::linux::test_dscp_sa_readback_body(&parameters, &config).unwrap();
        let transport = BindingTransport::new([Ok(None), Ok(Some(readback))]);
        let (backend, store) = LinuxXfrmBackend::with_transport_and_deferred_dscp_runtime(
            transport.clone(),
            config,
            runtime.clone(),
        )
        .unwrap()
        .bind_current_network_namespace_with_object_recovery(
            root.path().to_path_buf(),
            XfrmObjectRecoveryProofKey::new([0x75; 32]).unwrap(),
        )
        .unwrap();
        assert!(runtime.records().is_empty());

        let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let request = XfrmObjectInstallRequest::Sa(InstallSaRequest { parameters });
        let authority = backend
            .prepare_durable_object_install(&store, operation_id, generation, request.clone())
            .await
            .unwrap();
        drop(authority);
        assert!(matches!(
            backend
                .recover_durable_object_install(&store, operation_id, generation, request)
                .await
                .unwrap(),
            XfrmObjectInstallRestartOutcome::NoMutation
        ));

        let mut parameters = sa_parameters();
        parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
        let request = XfrmObjectInstallRequest::Sa(InstallSaRequest { parameters });
        let authority = backend
            .prepare_durable_object_install(&store, operation_id, generation, request.clone())
            .await
            .unwrap();
        let mut invalid_unmarked = sa_parameters();
        invalid_unmarked.id.spi = 0;
        assert!(matches!(
            backend
                .install_sa(InstallSaRequest {
                    parameters: invalid_unmarked,
                })
                .await,
            Err(XfrmError::InvalidConfig { .. })
        ));
        let stale = backend
            .run_durable_object_install(authority)
            .await
            .unwrap_err();
        assert_eq!(
            stale.durable_error(),
            Some(XfrmObjectInstallDurableError::Stale)
        );
        assert!(stale.into_retry_authority().is_none());
        assert!(matches!(
            backend
                .recover_durable_object_install(&store, operation_id, generation, request.clone(),)
                .await
                .unwrap(),
            XfrmObjectInstallRestartOutcome::NoMutation
        ));
        assert!(transport.operations().is_empty());

        let authority = backend
            .prepare_durable_object_install(&store, operation_id, generation, request.clone())
            .await
            .unwrap();
        let error = backend
            .run_durable_object_install(authority)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_str(),
            "xfrm_object_install_dscp_activation_required"
        );
        assert_eq!(
            format!("{error:?}"),
            "XfrmObjectInstallRunError { code: \"xfrm_object_install_dscp_activation_required\", .. }"
        );
        assert_eq!(
            durable_object_install_phase(&store, operation_id, generation, &request).unwrap(),
            XfrmObjectInstallDurablePhase::Prepared
        );
        let authority = error
            .into_retry_authority()
            .expect("clean activation gate returns exact retry authority");
        assert!(runtime.records().is_empty());
        assert!(transport.operations().is_empty());
        assert_eq!(
            backend.probe().await.unwrap().egress_dscp_marking,
            XfrmCapability::Unknown
        );
        assert_eq!(runtime.capability_calls(), 0);

        backend.activate_dscp_marking().await.unwrap();
        assert!(matches!(
            backend.run_durable_object_install(authority).await.unwrap(),
            XfrmObjectInstallDurableOutcome::Acquired(_)
        ));
        assert_eq!(
            transport.operations(),
            vec!["query_sa", "install_sa", "install_sa_dscp_readback"]
        );
        assert_eq!(
            backend
                .finalize_durable_object_install(&store, operation_id, generation, request)
                .await
                .unwrap(),
            XfrmObjectInstallDurablePhase::Committed
        );
    }

    #[test]
    fn namespace_binding_and_backend_debug_are_redacted() {
        let binding = NetworkNamespaceBinding {
            device: 1_234_567_890,
            inode: 9_876_543_210,
            cookie: Some(8_765_432_109),
            boot_id: Some([0x67; 16]),
        };
        let binding_debug = format!("{binding:?}");
        assert!(!binding_debug.contains("1234567890"));
        assert!(!binding_debug.contains("9876543210"));

        let (sender, _receiver) = mpsc::channel(1);
        let actor_binding = NamespaceActorBinding::new(binding);
        let backend = NamespaceBoundLinuxXfrmBackend {
            inner: Arc::new(NamespaceBoundLinuxXfrmBackendInner {
                sender,
                actor_binding,
                #[cfg(unix)]
                retained_finish_runtime: None,
                retained_finish_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }),
        };
        let debug = format!("{backend:?}");
        assert!(!debug.contains("1234567890"));
        assert!(!debug.contains("9876543210"));
    }

    #[test]
    fn namespace_mismatch_error_has_no_identity_material() {
        let current = NetworkNamespaceBinding::capture().unwrap();
        let mismatched = NetworkNamespaceBinding {
            device: current.device.wrapping_add(1),
            inode: current.inode.wrapping_add(1),
            ..current
        };
        let error = mismatched.ensure_current().unwrap_err();
        let debug = format!("{error:?}");
        let display = error.to_string();
        for identity in [mismatched.device, mismatched.inode] {
            assert!(!debug.contains(&identity.to_string()));
            assert!(!display.contains(&identity.to_string()));
        }
    }

    #[test]
    fn namespace_backend_is_send_sync_clone() {
        fn assert_traits<T: Send + Sync + Clone>() {}
        assert_traits::<NamespaceBoundLinuxXfrmBackend>();
        assert_eq!(LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY, 64);
    }

    #[cfg(unix)]
    fn durable_relocation_old_body() -> Vec<u8> {
        crate::linux::test_sa_relocation_readback(&sa_parameters())
            .unwrap()
            .0
    }

    #[cfg(unix)]
    fn durable_relocation_new_body() -> Vec<u8> {
        let mut parameters = sa_parameters();
        parameters.id.destination = ipv4(198, 51, 100, 2);
        parameters.source_address = ipv4(198, 51, 100, 1);
        crate::linux::test_sa_relocation_readback(&parameters)
            .unwrap()
            .0
    }

    #[cfg(unix)]
    type RelocationScriptedResponse = Result<Option<Vec<u8>>, XfrmError>;

    /// Scripted GETSA readbacks with ack-success mutations, used to drive the
    /// durable relocation pre-effect proofs through the real Linux backend.
    #[cfg(unix)]
    #[derive(Debug, Clone)]
    struct RelocationReadbackTransport {
        responses: Arc<Mutex<VecDeque<RelocationScriptedResponse>>>,
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    #[cfg(unix)]
    impl RelocationReadbackTransport {
        fn new(responses: Vec<RelocationScriptedResponse>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into())),
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn operations(&self) -> Vec<&'static str> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[cfg(unix)]
    impl LinuxXfrmTransport for RelocationReadbackTransport {
        fn transact(
            &self,
            operation: &'static str,
            _operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
            self.responses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .map(|response| response.map(|body| body.map(Zeroizing::new)))
                .unwrap_or(Err(XfrmError::Unavailable))
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    /// Like [`RelocationReadbackTransport`], but the sole MIGRATE mutation is
    /// held at the barrier so observer-cancellation detectors can observe the
    /// durable `Issuing` publication in flight.
    #[cfg(unix)]
    #[derive(Debug, Clone)]
    struct RelocationBarrierTransport {
        state: Arc<BlockingState>,
        responses: Arc<Mutex<VecDeque<RelocationScriptedResponse>>>,
    }

    #[cfg(unix)]
    impl LinuxXfrmTransport for RelocationBarrierTransport {
        fn transact(
            &self,
            _operation: &'static str,
            operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            match operation_class {
                // Pre-effect and reconciliation readbacks resolve from the
                // script; only the MIGRATE mutation is held at the barrier.
                crate::linux::NetlinkOperationClass::ReadOnly => self
                    .responses
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .pop_front()
                    .map(|response| response.map(|body| body.map(Zeroizing::new)))
                    .unwrap_or(Err(XfrmError::Unavailable)),
                crate::linux::NetlinkOperationClass::Mutation => {
                    self.state.calls.fetch_add(1, Ordering::AcqRel);
                    let mut guard = self
                        .state
                        .lock
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    while !self.state.released.load(Ordering::Acquire) {
                        guard = self
                            .state
                            .wake
                            .wait(guard)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                    Ok(None)
                }
            }
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[cfg(unix)]
    fn bind_with_relocation_recovery(
        transport: impl crate::linux::LinuxXfrmTransport + 'static,
        root: &DurableTestRoot,
    ) -> (
        NamespaceBoundLinuxXfrmBackend,
        XfrmSaRelocationRecoveryStore,
    ) {
        let (backend, _, store, _) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport),
            LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
            None,
            Some((
                root.path().to_path_buf(),
                XfrmSaRelocationRecoveryProofKey::new([0x71; 32]).unwrap(),
            )),
            None,
        )
        .unwrap();
        (backend, store.unwrap())
    }

    #[cfg(unix)]
    fn duplicate_sa_relocation_admission(
        authority: &XfrmSaRelocationAdmissionAuthority,
    ) -> XfrmSaRelocationAdmissionAuthority {
        XfrmSaRelocationAdmissionAuthority {
            operation: DurableSaRelocationOperation {
                store: authority.operation.store.clone(),
                operation_id: authority.operation.operation_id,
                operation_generation: authority.operation.operation_generation,
                request: authority.operation.request.clone(),
            },
            prepared: authority.prepared.clone(),
            actor_binding: authority.actor_binding.clone(),
            seal: authority.seal.clone(),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relocation_admission_validation_precedes_backend_and_wrong_seals_do_not_consume_it() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let operation_generation = XfrmSaRelocationOperationGeneration::new(4).unwrap();
        let request = relocation_request();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, operation_generation, request.clone())
            .await
            .unwrap();
        assert_eq!(
            format!("{authority:?}"),
            "XfrmSaRelocationAdmissionAuthority(<redacted>)"
        );

        let mut wrong_request = duplicate_sa_relocation_admission(&authority);
        wrong_request.operation.request.new_source_address = ipv4(203, 0, 113, 9);
        assert_eq!(
            backend
                .run_durable_sa_relocation(wrong_request)
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::WrongBinding
        );

        let mut wrong_correlation = duplicate_sa_relocation_admission(&authority);
        wrong_correlation.operation.operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        assert_eq!(
            backend
                .run_durable_sa_relocation(wrong_correlation)
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::Stale
        );

        let mut wrong_generation = duplicate_sa_relocation_admission(&authority);
        wrong_generation.operation.operation_generation =
            XfrmSaRelocationOperationGeneration::new(44).unwrap();
        assert_eq!(
            backend
                .run_durable_sa_relocation(wrong_generation)
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::Stale
        );

        let mut malformed = duplicate_sa_relocation_admission(&authority);
        let mut encoded = malformed.prepared.to_bytes();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        malformed.prepared = XfrmSaRelocationRecoveryHandle::from_bytes(encoded);
        assert_eq!(
            backend
                .run_durable_sa_relocation(malformed)
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::AuthenticationFailed
        );

        let mut wrong_seal = duplicate_sa_relocation_admission(&authority);
        wrong_seal.seal = Arc::new(());
        assert_eq!(
            backend
                .run_durable_sa_relocation(wrong_seal)
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::Stale
        );
        // No netlink mutation was admitted by any rejected attempt.
        assert!(transport
            .operations()
            .iter()
            .all(|operation| *operation == "query_sa_relocation_identity"));

        // Dropping the authority leaves recoverable Prepared truth.
        drop(authority);
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, operation_generation, request,)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_durable_sa_relocation_consumes_authority_exactly_once() {
        let root = DurableTestRoot::new();
        let old_body = durable_relocation_old_body();
        let transport = RelocationReadbackTransport::new(vec![
            Ok(Some(old_body.clone())),
            Err(XfrmError::NotFound),
            Ok(Some(old_body)),
            Err(XfrmError::NotFound),
            Ok(None),
            Ok(Some(durable_relocation_new_body())),
            Err(XfrmError::NotFound),
        ]);
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let operation_generation = XfrmSaRelocationOperationGeneration::new(5).unwrap();
        let request = relocation_request();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, operation_generation, request.clone())
            .await
            .unwrap();

        let outcome = backend.run_durable_sa_relocation(authority).await.unwrap();
        assert_eq!(outcome.as_str(), "relocated");
        assert_eq!(
            transport.operations(),
            vec![
                "query_sa_relocation_identity",
                "query_sa_relocation_identity",
                "relocate_sa_preflight",
                "relocate_sa_destination_preflight",
                "relocate_sa",
                "relocate_sa_readback",
                "relocate_sa_reconcile",
            ]
        );
        // The consumed authority cannot drive a second admission.
        let replay = duplicate_sa_relocation_admission(&XfrmSaRelocationAdmissionAuthority {
            operation: DurableSaRelocationOperation {
                store: store.clone(),
                operation_id,
                operation_generation,
                request: request.clone(),
            },
            prepared: outcome.handle().clone(),
            actor_binding: backend.namespace_actor_binding(),
            seal: Arc::new(()),
        });
        drop(replay);
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, operation_generation, request,)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::Relocated
        ));
        // Recovery performed no additional netlink work.
        assert_eq!(transport.operations().len(), 7);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn durable_relocation_fences_an_older_prepared_object_authority() {
        let object_root = DurableTestRoot::new();
        let relocation_root = DurableTestRoot::new();
        let old_body = durable_relocation_old_body();
        let transport = RelocationReadbackTransport::new(vec![
            Ok(Some(old_body.clone())),
            Err(XfrmError::NotFound),
            Ok(Some(old_body)),
            Err(XfrmError::NotFound),
            Ok(None),
            Ok(Some(durable_relocation_new_body())),
            Err(XfrmError::NotFound),
            // A stale object authority would consume these responses and
            // perform NEWSA if the relocation failed to cross-fence it.
            Err(XfrmError::NotFound),
            Ok(None),
        ]);
        let (backend, object_store, relocation_store, _) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport.clone()),
            LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
            Some((
                object_root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x83; 32]).unwrap(),
            )),
            Some((
                relocation_root.path().to_path_buf(),
                XfrmSaRelocationRecoveryProofKey::new([0x84; 32]).unwrap(),
            )),
            None,
        )
        .unwrap();
        let object_store = object_store.unwrap();
        let relocation_store = relocation_store.unwrap();

        // Object Prepared is intentionally not a writer gate, so a durable
        // relocation can be admitted behind it. The relocation must burn the
        // object epoch before its own backend effect.
        let object_operation = XfrmObjectInstallOperationId::generate().unwrap();
        let object_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let object_request = durable_object_requests()[0].clone();
        let object_authority = backend
            .prepare_durable_object_install(
                &object_store,
                object_operation,
                object_generation,
                object_request.clone(),
            )
            .await
            .unwrap();

        let relocation_operation = XfrmSaRelocationOperationId::generate().unwrap();
        let relocation_generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let relocation_request = relocation_request();
        let relocation_authority = backend
            .prepare_sa_relocation(
                &relocation_store,
                relocation_operation,
                relocation_generation,
                relocation_request.clone(),
            )
            .await
            .unwrap();
        assert!(matches!(
            backend
                .run_durable_sa_relocation(relocation_authority)
                .await
                .unwrap(),
            XfrmSaRelocationDurableOutcome::Relocated(_)
        ));

        let stale = backend
            .run_durable_object_install(object_authority)
            .await
            .unwrap_err();
        assert_eq!(
            stale.durable_error(),
            Some(XfrmObjectInstallDurableError::Stale)
        );
        assert_eq!(transport.operations().len(), 7);

        // The fenced Prepared record remains recoverable by correlation and
        // is retired without touching kernel state.
        assert!(matches!(
            backend
                .recover_durable_object_install(
                    &object_store,
                    object_operation,
                    object_generation,
                    object_request,
                )
                .await
                .unwrap(),
            XfrmObjectInstallRestartOutcome::NoMutation
        ));
        assert_eq!(transport.operations().len(), 7);
    }

    #[cfg(unix)]
    #[derive(Debug, Clone, Default)]
    struct UntrustedReadbackTransport {
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    #[cfg(unix)]
    impl LinuxXfrmTransport for UntrustedReadbackTransport {
        fn transact(
            &self,
            operation: &'static str,
            _operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
            // An empty response for every operation: unlike a decisive
            // NotFound, it cannot be parsed into an exact identity, so every
            // readback is untrustworthy.
            Ok(None)
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn untrusted_pre_effect_readback_returns_relocation_authority() {
        let root = DurableTestRoot::new();
        let transport = UntrustedReadbackTransport::default();
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let operation_generation = XfrmSaRelocationOperationGeneration::new(6).unwrap();
        let request = relocation_request();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, operation_generation, request.clone())
            .await
            .unwrap();

        // An empty GETSA response cannot be parsed into an exact identity, so
        // the readback is untrustworthy and the authority is returned with
        // the record still Prepared.
        let error = backend
            .run_durable_sa_relocation(authority)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_str(),
            "xfrm_sa_relocation_pre_effect_readback_failed"
        );
        assert!(error.readback_source().is_some());
        assert!(error.durable_error().is_none());
        let authority = error.into_retry_authority().expect("retry authority");
        assert_eq!(
            store.inspect(&authority.prepared),
            Ok(XfrmSaRelocationDurablePhase::Prepared)
        );

        // The exact retry is admitted and reaches the same proved rejection.
        let error = backend
            .run_durable_sa_relocation(authority)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_str(),
            "xfrm_sa_relocation_pre_effect_readback_failed"
        );
        drop(error);
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, operation_generation, request,)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn current_state_mismatch_consumes_relocation_authority_without_readback_retry() {
        let root = DurableTestRoot::new();
        let transport = RelocationReadbackTransport::new(vec![Err(XfrmError::NotFound)]);
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let operation_generation = XfrmSaRelocationOperationGeneration::new(7).unwrap();
        let request = relocation_request();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, operation_generation, request.clone())
            .await
            .unwrap();

        let error = backend
            .run_durable_sa_relocation(authority)
            .await
            .unwrap_err();
        assert_eq!(error.as_str(), "xfrm_sa_relocation_current_state_mismatch");
        assert!(error.into_retry_authority().is_none());
        // The retained Prepared record recovers as authoritative no-mutation.
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, operation_generation, request,)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn target_conflict_returns_relocation_authority_and_retains_prepared() {
        let root = DurableTestRoot::new();
        let old_body = durable_relocation_old_body();
        let mut foreign_parameters = sa_parameters();
        foreign_parameters.id.destination = ipv4(198, 51, 100, 2);
        foreign_parameters.source_address = ipv4(203, 0, 113, 9);
        let foreign_body = crate::linux::test_sa_relocation_readback(&foreign_parameters)
            .unwrap()
            .0;
        let transport =
            RelocationReadbackTransport::new(vec![Ok(Some(old_body)), Ok(Some(foreign_body))]);
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let operation_generation = XfrmSaRelocationOperationGeneration::new(8).unwrap();
        let request = relocation_request();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, operation_generation, request.clone())
            .await
            .unwrap();

        let error = backend
            .run_durable_sa_relocation(authority)
            .await
            .unwrap_err();
        assert_eq!(error.as_str(), "xfrm_sa_relocation_target_conflict");
        let authority = error.into_retry_authority().expect("retry authority");
        assert_eq!(
            store.inspect(&authority.prepared),
            Ok(XfrmSaRelocationDurablePhase::Prepared)
        );
        // No MIGRATE was admitted.
        assert!(transport
            .operations()
            .iter()
            .all(|operation| *operation == "query_sa_relocation_identity"));
        drop(authority);
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, operation_generation, request,)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_durable_sa_relocation_issue_finishes_after_observer_cancellation() {
        let root = DurableTestRoot::new();
        let old_body = durable_relocation_old_body();
        let blocking = Arc::new(BlockingState::new());
        let (backend, _, store, _) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(RelocationBarrierTransport {
                state: Arc::clone(&blocking),
                responses: Arc::new(Mutex::new(VecDeque::from(vec![
                    Ok(Some(old_body.clone())),
                    Err(XfrmError::NotFound),
                    Ok(Some(old_body)),
                    Err(XfrmError::NotFound),
                    Ok(Some(durable_relocation_new_body())),
                    Err(XfrmError::NotFound),
                ]))),
            }),
            LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
            None,
            Some((
                root.path().to_path_buf(),
                XfrmSaRelocationRecoveryProofKey::new([0x72; 32]).unwrap(),
            )),
            None,
        )
        .unwrap();
        let store = store.unwrap();
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(9).unwrap();
        let request = relocation_request();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, generation, request.clone())
            .await
            .unwrap();
        let observer = tokio::spawn({
            let backend = backend.clone();
            async move { backend.run_durable_sa_relocation(authority).await }
        });
        // The pre-effect readbacks resolve without blocking; the MIGRATE
        // mutation is the call held at the barrier, and it runs only after
        // the durable `Issuing` publication.
        wait_until(|| blocking.calls.load(Ordering::Acquire) == 1).await;
        assert_eq!(
            durable_sa_relocation_phase(&store, operation_id, generation, &request),
            Ok(XfrmSaRelocationDurablePhase::Issuing)
        );

        observer.abort();
        let _ = observer.await;
        blocking.release();
        // The admitted run drains before any later actor command; recovery
        // serialized behind it observes the terminal proof without racing
        // the store lock.
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, generation, request.clone(),)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::Relocated
        ));
        assert_eq!(blocking.calls.load(Ordering::Acquire), 1);
        assert_eq!(
            durable_sa_relocation_phase(&store, operation_id, generation, &request),
            Ok(XfrmSaRelocationDurablePhase::Relocated)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lost_prepare_reply_leaves_recoverable_prepared_relocation_truth() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(10).unwrap();
        let request = relocation_request();
        let operation = DurableSaRelocationOperation {
            store: store.clone(),
            operation_id,
            operation_generation: generation,
            request: request.clone(),
        };
        let (reply, lost_observer) = oneshot::channel();
        let permit = backend.inner.sender.reserve().await.unwrap();
        permit.send(NamespaceCommand::PrepareSaRelocation(
            Box::new(operation),
            reply,
        ));
        drop(lost_observer);

        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, generation, request)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lost_recover_reply_leaves_relocation_reconciliation_retryable_without_overlap() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(11).unwrap();
        let request = relocation_request();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, generation, request.clone())
            .await
            .unwrap();
        // Dropping the authority leaves the Prepared record recoverable and
        // its registered seal dead, so recovery can reconcile it.
        drop(authority);

        // Admit one reconciliation and lose its reply. Retiring a Prepared
        // record performs no backend work, so the actor's completion is
        // fully durable.
        let operation = DurableSaRelocationOperation {
            store: store.clone(),
            operation_id,
            operation_generation: generation,
            request: request.clone(),
        };
        let (reply, lost_observer) = oneshot::channel();
        let permit = backend.inner.sender.reserve().await.unwrap();
        permit.send(NamespaceCommand::RecoverSaRelocation(
            Box::new(operation),
            reply,
        ));
        drop(lost_observer);

        // The retry is serialized behind the lost admission and observes its
        // converged terminal state; no overlapping work or deletion.
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, generation, request)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::Retired
        ));
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unresolved_relocation_gates_install_family_and_ordinary_mutations() {
        let root = DurableTestRoot::new();
        let object_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, object_store, relocation_store, _) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport.clone()),
            LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
            Some((
                object_root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x73; 32]).unwrap(),
            )),
            Some((
                root.path().to_path_buf(),
                XfrmSaRelocationRecoveryProofKey::new([0x74; 32]).unwrap(),
            )),
            None,
        )
        .unwrap();
        let object_store = object_store.unwrap();
        let relocation_store = relocation_store.unwrap();

        // A prepared relocation alone fences every cooperating mutation.
        let relocation_operation = XfrmSaRelocationOperationId::generate().unwrap();
        let relocation_generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let authority = backend
            .prepare_sa_relocation(
                &relocation_store,
                relocation_operation,
                relocation_generation,
                relocation_request(),
            )
            .await
            .unwrap();
        assert!(matches!(
            backend
                .install_sa(InstallSaRequest {
                    parameters: sa_parameters(),
                })
                .await,
            Err(XfrmError::Unavailable)
        ));
        assert!(matches!(
            backend.remove_sa(remove_request()).await,
            Err(XfrmError::Unavailable)
        ));
        assert!(matches!(
            backend
                .prepare_durable_object_install(
                    &object_store,
                    XfrmObjectInstallOperationId::generate().unwrap(),
                    XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                    durable_object_requests()[0].clone(),
                )
                .await,
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        ));
        assert!(transport.operations().is_empty());

        // Dropping the authority leaves the Prepared record recoverable; a
        // live authority would keep same-process recovery fail-closed.
        drop(authority);
        // Recovery retires the prepared relocation and reopens the gate.
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(
                    &relocation_store,
                    relocation_operation,
                    relocation_generation,
                    relocation_request(),
                )
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
        backend
            .install_sa(InstallSaRequest {
                parameters: sa_parameters(),
            })
            .await
            .unwrap();
        assert!(backend
            .prepare_durable_object_install(
                &object_store,
                XfrmObjectInstallOperationId::generate().unwrap(),
                XfrmObjectInstallOperationGeneration::new(2).unwrap(),
                durable_object_requests()[0].clone(),
            )
            .await
            .is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unresolved_install_authority_gates_relocation_preparation() {
        let root = DurableTestRoot::new();
        let object_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, object_store, relocation_store, _) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport.clone()),
            LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
            Some((
                object_root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x75; 32]).unwrap(),
            )),
            Some((
                root.path().to_path_buf(),
                XfrmSaRelocationRecoveryProofKey::new([0x76; 32]).unwrap(),
            )),
            None,
        )
        .unwrap();
        let object_store = object_store.unwrap();
        let relocation_store = relocation_store.unwrap();
        let install_operation = XfrmObjectInstallOperationId::generate().unwrap();
        let install_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let install_request = durable_object_requests()[0].clone();

        // Drive the install record to unresolved `Issuing` through the store.
        let authority = backend
            .prepare_durable_object_install(
                &object_store,
                install_operation,
                install_generation,
                install_request.clone(),
            )
            .await
            .unwrap();
        drop(authority);
        let fingerprints = object_store
            .fingerprints_for_request(&install_request)
            .unwrap();
        let prepared = object_store
            .restore(
                install_operation,
                install_generation,
                install_request.object(),
                fingerprints,
            )
            .unwrap();
        let issuing = object_store
            .transition(
                &object_store.handle_for_record(&prepared).unwrap(),
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                Some(XfrmObjectInstallPreEffectProof::Absent),
            )
            .unwrap();

        // The unresolved install record fences relocation preparation.
        assert!(matches!(
            backend
                .prepare_sa_relocation(
                    &relocation_store,
                    XfrmSaRelocationOperationId::generate().unwrap(),
                    XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                    relocation_request(),
                )
                .await,
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        ));

        // Retire the install record and the relocation gate reopens.
        let no_mutation = object_store
            .transition(
                &object_store.handle_for_record(&issuing).unwrap(),
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::NoMutation,
                None,
            )
            .unwrap();
        object_store
            .transition(
                &object_store.handle_for_record(&no_mutation).unwrap(),
                XfrmObjectInstallDurablePhase::NoMutation,
                XfrmObjectInstallDurablePhase::Retired,
                None,
            )
            .unwrap();
        assert!(backend
            .prepare_sa_relocation(
                &relocation_store,
                XfrmSaRelocationOperationId::generate().unwrap(),
                XfrmSaRelocationOperationGeneration::new(2).unwrap(),
                relocation_request(),
            )
            .await
            .is_ok());
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unresolved_install_acquired_gates_ordinary_mutations_and_relocation() {
        let root = DurableTestRoot::new();
        let object_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, object_store, relocation_store, _) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport.clone()),
            LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
            Some((
                object_root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x77; 32]).unwrap(),
            )),
            Some((
                root.path().to_path_buf(),
                XfrmSaRelocationRecoveryProofKey::new([0x78; 32]).unwrap(),
            )),
            None,
        )
        .unwrap();
        let object_store = object_store.unwrap();
        let relocation_store = relocation_store.unwrap();
        let install_operation = XfrmObjectInstallOperationId::generate().unwrap();
        let install_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let install_request = durable_object_requests()[0].clone();

        let authority = backend
            .prepare_durable_object_install(
                &object_store,
                install_operation,
                install_generation,
                install_request.clone(),
            )
            .await
            .unwrap();
        drop(authority);
        let fingerprints = object_store
            .fingerprints_for_request(&install_request)
            .unwrap();
        let prepared = object_store
            .restore(
                install_operation,
                install_generation,
                install_request.object(),
                fingerprints,
            )
            .unwrap();
        let issuing = object_store
            .transition(
                &object_store.handle_for_record(&prepared).unwrap(),
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                Some(XfrmObjectInstallPreEffectProof::Absent),
            )
            .unwrap();
        let acquired = object_store
            .transition(
                &object_store.handle_for_record(&issuing).unwrap(),
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::Acquired,
                None,
            )
            .unwrap();

        // Acquired install authority fences ordinary mutations and relocation
        // preparation alike.
        assert!(matches!(
            backend.remove_sa(remove_request()).await,
            Err(XfrmError::Unavailable)
        ));
        assert!(matches!(
            backend
                .prepare_sa_relocation(
                    &relocation_store,
                    XfrmSaRelocationOperationId::generate().unwrap(),
                    XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                    relocation_request(),
                )
                .await,
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        ));

        // Finalize surrenders the cleanup authority and reopens the gates.
        object_store
            .transition(
                &object_store.handle_for_record(&acquired).unwrap(),
                XfrmObjectInstallDurablePhase::Acquired,
                XfrmObjectInstallDurablePhase::Committed,
                None,
            )
            .unwrap();
        backend.remove_sa(remove_request()).await.unwrap();
        assert!(backend
            .prepare_sa_relocation(
                &relocation_store,
                XfrmSaRelocationOperationId::generate().unwrap(),
                XfrmSaRelocationOperationGeneration::new(2).unwrap(),
                relocation_request(),
            )
            .await
            .is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relocation_wrong_store_instance_is_rejected_before_any_transport() {
        let root = DurableTestRoot::new();
        let wrong_store_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        let wrong_store = XfrmSaRelocationRecoveryStore::open_bound(
            wrong_store_root.path(),
            XfrmSaRelocationRecoveryProofKey::new([0x7a; 32]).unwrap(),
            backend.network_namespace_binding().durable_bytes().unwrap(),
        )
        .unwrap();
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let operation_generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let request = relocation_request();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, operation_generation, request.clone())
            .await
            .unwrap();

        // A run attempt presenting a different same-shape store instance
        // fails at the actor's store binding check.
        let mut wrong_store_attempt = duplicate_sa_relocation_admission(&authority);
        wrong_store_attempt.operation.store = wrong_store.clone();
        assert_eq!(
            backend
                .run_durable_sa_relocation(wrong_store_attempt)
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::WrongBinding
        );

        // Recovery through the wrong store is rejected the same way.
        assert_eq!(
            backend
                .recover_durable_sa_relocation(
                    &wrong_store,
                    operation_id,
                    operation_generation,
                    request.clone(),
                )
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::WrongBinding
        );

        // Preparation against the wrong store is rejected too.
        assert_eq!(
            backend
                .prepare_sa_relocation(
                    &wrong_store,
                    XfrmSaRelocationOperationId::generate().unwrap(),
                    XfrmSaRelocationOperationGeneration::new(2).unwrap(),
                    request.clone(),
                )
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::WrongBinding
        );

        // Zero transport operations; the original authority remains valid on
        // the bound store and its record stays recoverable.
        assert!(transport.operations().is_empty());
        drop(authority);
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, operation_generation, request,)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_relocation_authority_blocks_same_process_recovery_until_dropped() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let operation_generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let request = relocation_request();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, operation_generation, request.clone())
            .await
            .unwrap();
        assert_eq!(
            store.inspect(&authority.prepared),
            Ok(XfrmSaRelocationDurablePhase::Prepared)
        );
        assert!(transport.operations().is_empty());

        // A live registered authority keeps same-process recovery fail-closed.
        assert_eq!(
            backend
                .recover_durable_sa_relocation(
                    &store,
                    operation_id,
                    operation_generation,
                    request.clone(),
                )
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::InvalidTransition
        );
        assert!(transport.operations().is_empty());

        // Dropping the authority lets recovery retire the prepared record as
        // authoritative no-mutation.
        drop(authority);
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, operation_generation, request)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deferred_dscp_gate_returns_relocation_authority_and_retains_prepared() {
        let root = DurableTestRoot::new();
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
        let runtime = DeferredDscpRuntime::with_outcomes([]);
        let transport = RecordingSuccessTransport::default();
        let profile = config.profile().unwrap();
        let mut request = relocation_request();
        request.current.output_mark = Some(crate::XfrmMark {
            value: profile.encode_token(46).unwrap(),
            mask: profile.mask,
        });
        let (backend, store) = LinuxXfrmBackend::with_transport_and_deferred_dscp_runtime(
            transport.clone(),
            config,
            runtime.clone(),
        )
        .unwrap()
        .bind_current_network_namespace_with_sa_relocation_recovery(
            root.path().to_path_buf(),
            XfrmSaRelocationRecoveryProofKey::new([0x79; 32]).unwrap(),
        )
        .unwrap();
        let operation_id = XfrmSaRelocationOperationId::generate().unwrap();
        let operation_generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let authority = backend
            .prepare_sa_relocation(&store, operation_id, operation_generation, request.clone())
            .await
            .unwrap();

        // The deferred DSCP gate is not activated, so the run is rejected
        // before any readback: the exact authority is returned and the record
        // stays Prepared.
        let error = backend
            .run_durable_sa_relocation(authority)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_str(),
            "xfrm_sa_relocation_dscp_activation_required"
        );
        assert!(error.durable_error().is_none());
        let authority = error.into_retry_authority().expect("retry authority");
        assert_eq!(
            store.inspect(&authority.prepared),
            Ok(XfrmSaRelocationDurablePhase::Prepared)
        );
        assert!(transport.operations().is_empty());
        assert!(runtime.records().is_empty());

        // Dropping the retry authority leaves the record recoverable as
        // authoritative no-mutation.
        drop(authority);
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(&store, operation_id, operation_generation, request)
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn combined_binding_constructor_attaches_both_stores_and_cross_gates() {
        let object_root = DurableTestRoot::new();
        let relocation_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, object_store, relocation_store) =
            LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_and_sa_relocation_recovery(
                    object_root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x7b; 32]).unwrap(),
                    relocation_root.path().to_path_buf(),
                    XfrmSaRelocationRecoveryProofKey::new([0x7c; 32]).unwrap(),
                )
                .unwrap();

        // Both stores are attached to the same actor: a prepared relocation
        // gates install preparation through the combined binding.
        let relocation_operation = XfrmSaRelocationOperationId::generate().unwrap();
        let relocation_generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let authority = backend
            .prepare_sa_relocation(
                &relocation_store,
                relocation_operation,
                relocation_generation,
                relocation_request(),
            )
            .await
            .unwrap();
        assert!(matches!(
            backend
                .prepare_durable_object_install(
                    &object_store,
                    XfrmObjectInstallOperationId::generate().unwrap(),
                    XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                    durable_object_requests()[0].clone(),
                )
                .await,
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        ));
        drop(authority);
        assert!(transport.operations().is_empty());

        // Recovery through the relocation store reopens the install gate.
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(
                    &relocation_store,
                    relocation_operation,
                    relocation_generation,
                    relocation_request(),
                )
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
        assert!(backend
            .prepare_durable_object_install(
                &object_store,
                XfrmObjectInstallOperationId::generate().unwrap(),
                XfrmObjectInstallOperationGeneration::new(2).unwrap(),
                durable_object_requests()[0].clone(),
            )
            .await
            .is_ok());
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn install_authority_survives_relocation_gated_mutation_rejection() {
        let object_root = DurableTestRoot::new();
        let relocation_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, object_store, relocation_store, _) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport.clone()),
            LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
            Some((
                object_root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x7d; 32]).unwrap(),
            )),
            Some((
                relocation_root.path().to_path_buf(),
                XfrmSaRelocationRecoveryProofKey::new([0x7e; 32]).unwrap(),
            )),
            None,
        )
        .unwrap();
        let object_store = object_store.unwrap();
        let relocation_store = relocation_store.unwrap();

        // Prepare an install authority and keep it live.
        let install_operation = XfrmObjectInstallOperationId::generate().unwrap();
        let install_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let install_request = durable_object_requests()[0].clone();
        let authority = backend
            .prepare_durable_object_install(
                &object_store,
                install_operation,
                install_generation,
                install_request.clone(),
            )
            .await
            .unwrap();

        // A prepared relocation record gates ordinary mutations.
        let relocation_operation = XfrmSaRelocationOperationId::generate().unwrap();
        let relocation_generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let relocation_authority = backend
            .prepare_sa_relocation(
                &relocation_store,
                relocation_operation,
                relocation_generation,
                relocation_request(),
            )
            .await
            .unwrap();
        drop(relocation_authority);
        assert!(matches!(
            backend
                .install_sa(InstallSaRequest {
                    parameters: sa_parameters(),
                })
                .await,
            Err(XfrmError::Unavailable)
        ));
        assert!(transport.operations().is_empty());

        // The rejected mutation burned the install epoch but must not have
        // cleared the live install authority: its run validation passes the
        // seal check and fails only at the cross-family gate, not Stale.
        let gated_attempt = duplicate_admission(&authority);
        let gated_error = backend
            .run_durable_object_install(gated_attempt)
            .await
            .unwrap_err();
        assert_eq!(
            gated_error.durable_error(),
            Some(XfrmObjectInstallDurableError::InvalidTransition)
        );
        assert!(transport.operations().is_empty());

        // Once the relocation record is recovered, the surviving authority
        // runs to completion.
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(
                    &relocation_store,
                    relocation_operation,
                    relocation_generation,
                    relocation_request(),
                )
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
        assert!(matches!(
            backend.run_durable_object_install(authority).await.unwrap(),
            XfrmObjectInstallDurableOutcome::Acquired(_)
        ));
        // The install run witnesses the deletion identity (query_sa) before
        // admitting the NEWSA effect.
        assert_eq!(transport.operations(), vec!["query_sa", "install_sa"]);
        assert_eq!(
            backend
                .finalize_durable_object_install(
                    &object_store,
                    install_operation,
                    install_generation,
                    install_request,
                )
                .await
                .unwrap(),
            XfrmObjectInstallDurablePhase::Committed
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn relocation_run_error_diagnostics_are_value_free() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_relocation_recovery(transport.clone(), &root);
        // The fixture request carries addresses, a SPI, a lookup mark, and
        // encapsulation ports; none may leak through any run diagnostic.
        let mut request = relocation_request();
        request.current.encap = Some(crate::UdpEncap::esp_in_udp(4500, 4500));
        request.current.mark = Some(XfrmLookupMark::full(0x6290));
        request.encap = SaRelocationEncap::Set(crate::UdpEncap::esp_in_udp(4500, 62_000));
        let authority = backend
            .prepare_sa_relocation(
                &store,
                XfrmSaRelocationOperationId::generate().unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                request,
            )
            .await
            .unwrap();

        for (error, label) in [
            (
                XfrmSaRelocationRunError::current_state_mismatch(),
                "xfrm_sa_relocation_current_state_mismatch",
            ),
            (
                XfrmSaRelocationRunError::from(XfrmSaRelocationDurableError::NotFound),
                "xfrm_sa_relocation_recovery_not_found",
            ),
            (
                XfrmSaRelocationRunError::from(XfrmSaRelocationDurableError::WrongBinding),
                "xfrm_sa_relocation_recovery_wrong_binding",
            ),
            (
                XfrmSaRelocationRunError::dscp_activation_required(Box::new(
                    duplicate_sa_relocation_admission(&authority),
                )),
                "xfrm_sa_relocation_dscp_activation_required",
            ),
            (
                XfrmSaRelocationRunError::target_conflict(Box::new(
                    duplicate_sa_relocation_admission(&authority),
                )),
                "xfrm_sa_relocation_target_conflict",
            ),
            (
                XfrmSaRelocationRunError::pre_effect_readback_failed(
                    Box::new(duplicate_sa_relocation_admission(&authority)),
                    XfrmError::StateIndeterminate {
                        operation: "query_sa_relocation_identity",
                    },
                ),
                "xfrm_sa_relocation_pre_effect_readback_failed",
            ),
        ] {
            assert_eq!(error.as_str(), label);
            assert_eq!(error.to_string(), label);
            let debug = format!("{error:?}");
            assert!(debug.contains(label), "debug must carry only the label");
            for leaked in [
                "192.0", "198.51", "1020", "3040", "0x1020", "6290", "0x6290", "4500", "62000",
            ] {
                assert!(!debug.contains(leaked), "diagnostic leaked {leaked}");
                assert!(!label.contains(leaked), "label leaked {leaked}");
            }
        }
        drop(authority);
        assert!(transport.operations().is_empty());
    }

    // ---------------------------------------------------------------------
    // Durable grouped object roster: altitude-B namespace actor coverage.
    // ---------------------------------------------------------------------

    #[cfg(unix)]
    #[derive(Debug, Clone)]
    struct RecordingBlockingTransport {
        state: Arc<BlockingState>,
        block_mutation: usize,
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    #[cfg(unix)]
    impl RecordingBlockingTransport {
        fn new(state: Arc<BlockingState>, block_mutation: usize) -> Self {
            Self {
                state,
                block_mutation,
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn operations(&self) -> Vec<&'static str> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[cfg(unix)]
    impl LinuxXfrmTransport for RecordingBlockingTransport {
        fn transact(
            &self,
            operation: &'static str,
            operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
            self.state.calls.fetch_add(1, Ordering::AcqRel);
            match operation_class {
                // Exact readbacks model an absent identity so every sweep and
                // adjacent witness proves absence; only mutations are held.
                crate::linux::NetlinkOperationClass::ReadOnly => Err(XfrmError::NotFound),
                crate::linux::NetlinkOperationClass::Mutation => {
                    let mutation = self.state.mutation_calls.fetch_add(1, Ordering::AcqRel);
                    if mutation == self.block_mutation {
                        let mut guard = self
                            .state
                            .lock
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        while !self.state.released.load(Ordering::Acquire) {
                            guard = self
                                .state
                                .wake
                                .wait(guard)
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                        }
                    }
                    Ok(None)
                }
            }
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    /// Holds exactly one read-only actor command. This can saturate queue
    /// admission while an `Issuing` roster correctly rejects ordinary
    /// mutations before they touch the transport.
    #[cfg(unix)]
    #[derive(Debug, Clone)]
    struct QueryBlockingTransport {
        state: Arc<BlockingState>,
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    #[cfg(unix)]
    impl QueryBlockingTransport {
        fn new(state: Arc<BlockingState>) -> Self {
            Self {
                state,
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn operations(&self) -> Vec<&'static str> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[cfg(unix)]
    impl LinuxXfrmTransport for QueryBlockingTransport {
        fn transact(
            &self,
            operation: &'static str,
            operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
            self.state.calls.fetch_add(1, Ordering::AcqRel);
            if matches!(
                operation_class,
                crate::linux::NetlinkOperationClass::ReadOnly
            ) && operation == "query_policy"
                && self.state.mutation_calls.fetch_add(1, Ordering::AcqRel) == 0
            {
                let mut guard = self
                    .state
                    .lock
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                while !self.state.released.load(Ordering::Acquire) {
                    guard = self
                        .state
                        .wake
                        .wait(guard)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            match operation_class {
                crate::linux::NetlinkOperationClass::ReadOnly => Err(XfrmError::NotFound),
                crate::linux::NetlinkOperationClass::Mutation => Ok(None),
            }
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[cfg(unix)]
    fn roster_group(byte: u8) -> XfrmObjectRosterGroupId {
        XfrmObjectRosterGroupId::from_bytes([byte; 16]).unwrap()
    }

    #[cfg(unix)]
    fn roster_generation(value: u64) -> XfrmObjectRosterOperationGeneration {
        XfrmObjectRosterOperationGeneration::new(value).unwrap()
    }

    #[cfg(unix)]
    fn roster_sa_request(index: usize) -> XfrmObjectInstallRequest {
        let mut parameters = sa_parameters();
        parameters.id.spi = 0x2000_0000 + u32::try_from(index).unwrap();
        XfrmObjectInstallRequest::Sa(InstallSaRequest { parameters })
    }

    #[cfg(unix)]
    fn roster_policy_request(index: usize) -> XfrmObjectInstallRequest {
        let mut parameters = policy_parameters();
        let octet = u8::try_from(index).unwrap();
        parameters.selector = XfrmSelector::new(ipv4(10, 1, octet, 1), ipv4(10, 1, octet, 2), 17);
        XfrmObjectInstallRequest::Policy(InstallPolicyRequest { parameters })
    }

    #[cfg(unix)]
    fn sa_roster(arity: usize) -> XfrmObjectRosterRequest {
        XfrmObjectRosterRequest::new(
            (0..arity)
                .map(|index| XfrmObjectRosterMemberRequest::new(roster_sa_request(index)))
                .collect(),
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn policy_roster(arity: usize) -> XfrmObjectRosterRequest {
        XfrmObjectRosterRequest::new(
            (0..arity)
                .map(|index| XfrmObjectRosterMemberRequest::new(roster_policy_request(index)))
                .collect(),
        )
        .unwrap()
    }

    /// The dependency-ordered five-object shape one IKEv2 Child SA needs.
    #[cfg(unix)]
    fn child_sa_roster() -> XfrmObjectRosterRequest {
        XfrmObjectRosterRequest::new(vec![
            XfrmObjectRosterMemberRequest::new(roster_sa_request(0)),
            XfrmObjectRosterMemberRequest::new(roster_policy_request(0)),
            XfrmObjectRosterMemberRequest::new(roster_policy_request(1)),
            XfrmObjectRosterMemberRequest::new(roster_sa_request(1)),
            XfrmObjectRosterMemberRequest::new(roster_policy_request(2)),
        ])
        .unwrap()
    }

    #[cfg(unix)]
    fn bind_with_roster_recovery(
        transport: impl crate::linux::LinuxXfrmTransport + 'static,
        root: &DurableTestRoot,
        key: u8,
    ) -> (
        NamespaceBoundLinuxXfrmBackend,
        XfrmObjectRosterRecoveryStore,
    ) {
        LinuxXfrmBackend::with_transport(transport)
            .bind_current_network_namespace_with_object_roster_recovery(
                root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([key; 32]).unwrap(),
            )
            .unwrap()
    }

    /// Synthesize a second handle on one live admission seal.
    ///
    /// This exists ONLY to build the forged, substituted, and tampered
    /// admissions the negative tests feed to the actor, and to supply a
    /// payload to the `XfrmObjectRunError` constructors in the accessor and
    /// diagnostic unit tests. The public API cannot produce two live handles on
    /// one seal, so this must never be used to claim that the actor gave an
    /// authority back: the tests that assert retryability drive
    /// [`XfrmObjectRosterRunError::into_retry_authority`] on an error the actor
    /// actually returned.
    #[cfg(unix)]
    fn duplicate_roster_admission(
        authority: &XfrmObjectRosterAdmissionAuthority,
    ) -> XfrmObjectRosterAdmissionAuthority {
        XfrmObjectRosterAdmissionAuthority {
            operation: Box::new(DurableObjectRosterOperation {
                store: authority.operation.store.clone(),
                group_id: authority.operation.group_id,
                generation: authority.operation.generation,
                roster: authority.operation.roster.clone(),
            }),
            prepared: authority.prepared.clone(),
            actor_binding: authority.actor_binding.clone(),
            seal: authority.seal.clone(),
        }
    }

    #[cfg(unix)]
    fn duplicate_roster_effect_quiesced(
        effect: &XfrmObjectRosterEffectQuiesced,
    ) -> XfrmObjectRosterEffectQuiesced {
        XfrmObjectRosterEffectQuiesced {
            operation: Box::new(DurableObjectRosterOperation {
                store: effect.operation.store.clone(),
                group_id: effect.operation.group_id,
                generation: effect.operation.generation,
                roster: effect.operation.roster.clone(),
            }),
            issuing: effect.issuing.clone(),
            actor_binding: effect.actor_binding.clone(),
            seal: effect.seal.clone(),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_prepare_is_durable_before_effect_and_duplicate_never_remints_authority() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x80);
        let group = roster_group(0x11);
        let generation = roster_generation(1);
        let roster = sa_roster(5);

        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        // The authority exists only because authenticated `Prepared` truth is
        // already durable, and preparation admits no backend effect at all.
        assert_eq!(
            store.inspect(&authority.prepared),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        assert!(transport.operations().is_empty());
        assert_eq!(authority.operation.roster.arity(), 5);

        assert_eq!(
            backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::Duplicate
        );
        // The duplicate neither reminted authority nor disturbed the record.
        assert_eq!(
            store.inspect(&authority.prepared),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        assert!(transport.operations().is_empty());

        drop(authority);
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "no_mutation"
        );
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_admission_validation_precedes_backend_and_wrong_seals_do_not_consume_it() {
        let root = DurableTestRoot::new();
        let wrong_store_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x81);
        let foreign_transport = RecordingSuccessTransport::default();
        let foreign = LinuxXfrmBackend::with_transport(foreign_transport.clone())
            .bind_current_network_namespace()
            .unwrap();
        let group = roster_group(0x12);
        let generation = roster_generation(1);
        let roster = sa_roster(3);

        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        assert_eq!(
            format!("{authority:?}"),
            "XfrmObjectRosterAdmissionAuthority(<redacted>)"
        );

        // Layer 1: another namespace actor cannot consume this admission, and
        // the rejection happens before the command is ever dispatched.
        assert_eq!(
            foreign
                .run_durable_object_roster(duplicate_roster_admission(&authority))
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );
        assert!(foreign_transport.operations().is_empty());

        // Layer 2: a different same-shape store instance is rejected.
        let wrong_store = XfrmObjectRosterRecoveryStore::open_bound(
            wrong_store_root.path(),
            XfrmObjectRosterRecoveryProofKey::new([0x82; 32]).unwrap(),
            backend.network_namespace_binding().durable_bytes().unwrap(),
        )
        .unwrap();
        let mut wrong_store_attempt = duplicate_roster_admission(&authority);
        wrong_store_attempt.operation.store = wrong_store;
        assert_eq!(
            backend
                .run_durable_object_roster(wrong_store_attempt)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );

        // Layer 3: the registry key is the group identity and generation.
        let mut wrong_group = duplicate_roster_admission(&authority);
        wrong_group.operation.group_id = roster_group(0x13);
        assert_eq!(
            backend
                .run_durable_object_roster(wrong_group)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::Stale
        );
        let mut wrong_generation = duplicate_roster_admission(&authority);
        wrong_generation.operation.generation = roster_generation(44);
        assert_eq!(
            backend
                .run_durable_object_roster(wrong_generation)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::Stale
        );

        // Layer 4: a fresh seal is not the registered live authority.
        let mut wrong_seal = duplicate_roster_admission(&authority);
        wrong_seal.seal = Arc::new(());
        assert_eq!(
            backend
                .run_durable_object_roster(wrong_seal)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::Stale
        );

        // A tampered handle fails authentication, not merely correlation.
        let mut malformed = duplicate_roster_admission(&authority);
        let mut encoded = malformed.prepared.to_bytes();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        malformed.prepared = XfrmObjectRosterRecoveryHandle::from_bytes(encoded);
        assert_eq!(
            backend
                .run_durable_object_roster(malformed)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::AuthenticationFailed
        );

        // Not one rejection reached the backend or consumed the admission.
        assert!(transport.operations().is_empty());
        assert_eq!(
            store.inspect(&authority.prepared),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );

        let outcome = backend.run_durable_object_roster(authority).await.unwrap();
        assert_eq!(outcome.as_str(), "applied");
        assert_eq!(outcome.members().arity(), 3);
        // Three members: three sweeps, member zero's adjacent witness, then a
        // fresh adjacent witness plus an install for every later member.
        assert_eq!(
            transport.operations(),
            vec![
                "query_sa",
                "query_sa",
                "query_sa",
                "query_sa",
                "install_sa",
                "query_sa",
                "install_sa",
                "query_sa",
                "install_sa",
            ]
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_effect_quiesced_token_defers_applied_until_explicit_finish() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x7f);
        let group = roster_group(0x13);
        let generation = roster_generation(1);
        let roster = sa_roster(5);
        store.tests_reset_physical_barriers().unwrap();

        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let effect = backend
            .run_durable_object_roster_effect_quiesced(authority)
            .await
            .unwrap();
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
        assert_eq!(store.tests_physical_barriers().unwrap(), 6);
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            5
        );
        assert_eq!(
            format!("{effect:?}"),
            "XfrmObjectRosterEffectQuiesced(<redacted>)"
        );

        // The live affine token keeps same-process recovery out of the gap
        // while the product activates its response; the durable Issuing state
        // separately fences every cooperating XFRM mutation.
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::InvalidTransition
        );
        assert!(matches!(
            backend.remove_sa(remove_request()).await,
            Err(XfrmError::Unavailable)
        ));

        let outcome = backend
            .finish_durable_object_roster_effect_quiesced(effect)
            .await
            .unwrap();
        assert_eq!(outcome.as_str(), "applied");
        assert_eq!(store.tests_physical_barriers().unwrap(), 7);
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
        assert_eq!(store.tests_physical_barriers().unwrap(), 8);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropped_roster_effect_quiesced_token_reopens_normal_recovery() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x7e);
        let group = roster_group(0x14);
        let generation = roster_generation(1);
        let roster = sa_roster(1);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let effect = backend
            .run_durable_object_roster_effect_quiesced(authority)
            .await
            .unwrap();
        drop(effect);

        // Once the affine token is dropped the actor reconciles the retained
        // Issuing record instead of attempting to finish or replay it.
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "rolled_back"
        );
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            1
        );
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Retired)
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retained_roster_finish_converges_after_pending_observer_cancellation() {
        let root = DurableTestRoot::new();
        let blocking = Arc::new(BlockingState::new());
        // The roster effect completes first. A read-only command can still run
        // while the roster is `Issuing`, so hold one in the actor while a
        // second command occupies the only bounded queue slot.
        let transport = QueryBlockingTransport::new(Arc::clone(&blocking));
        let capture = transport.clone();
        let (backend, _, _, store) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport),
            1,
            None,
            None,
            Some((
                root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0x7d; 32]).unwrap(),
            )),
        )
        .unwrap();
        let store = store.unwrap();
        let group = roster_group(0x15);
        let generation = roster_generation(1);
        let roster = sa_roster(1);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let effect = backend
            .run_durable_object_roster_effect_quiesced(authority)
            .await
            .unwrap();
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );

        let blocker = tokio::spawn({
            let backend = backend.clone();
            async move {
                backend
                    .query_policy(QueryPolicyRequest::new(
                        policy_parameters().selector,
                        XfrmDirection::Out,
                    ))
                    .await
            }
        });
        wait_until(|| blocking.mutation_calls.load(Ordering::Acquire) == 1).await;
        let queued = tokio::spawn({
            let backend = backend.clone();
            async move {
                backend
                    .query_policy(QueryPolicyRequest::new(
                        policy_parameters().selector,
                        XfrmDirection::Out,
                    ))
                    .await
            }
        });
        wait_until(|| backend.inner.sender.capacity() == 0).await;

        let mut finish = Box::pin(backend.finish_durable_object_roster_effect_quiesced(effect));
        // One manual poll executes only the synchronous transfer to the
        // retained actor-runtime task. Its bounded permit wait is pending,
        // so dropping this observer cannot drop the token.
        let first_poll =
            std::future::poll_fn(|context| Poll::Ready(finish.as_mut().poll(context))).await;
        assert!(matches!(first_poll, Poll::Pending));
        drop(finish);

        blocking.release();
        let _ = blocker.await;
        let _ = queued.await;
        wait_until(|| {
            backend
                .inner
                .retained_finish_completed
                .load(Ordering::Acquire)
        })
        .await;
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Applied)
        );
        assert_eq!(
            capture
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            1,
            "the retained finish publishes only; it never replays the effect"
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unpolled_roster_effect_quiesced_finish_leaves_exact_recovery_authority() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x7c);
        let group = roster_group(0x16);
        let generation = roster_generation(1);
        let roster = sa_roster(1);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let effect = backend
            .run_durable_object_roster_effect_quiesced(authority)
            .await
            .unwrap();
        let barriers_before_finish = store.tests_physical_barriers().unwrap();

        // The async body never runs, so no retained task or publication exists.
        let finish = backend.finish_durable_object_roster_effect_quiesced(effect);
        drop(finish);
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
        assert_eq!(
            store.tests_physical_barriers().unwrap(),
            barriers_before_finish
        );

        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "rolled_back"
        );
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            1,
            "exact recovery, not an unpolled finish, owns the one effect"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_effect_quiesced_finish_rejects_wrong_binding_and_duplicate_use() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x7b);
        let foreign = bind_with_capacity(
            LinuxXfrmBackend::with_transport(RecordingSuccessTransport::default()),
            1,
        )
        .unwrap();
        let group = roster_group(0x17);
        let generation = roster_generation(1);
        let roster = sa_roster(1);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let effect = backend
            .run_durable_object_roster_effect_quiesced(authority)
            .await
            .unwrap();

        assert_eq!(
            foreign
                .finish_durable_object_roster_effect_quiesced(duplicate_roster_effect_quiesced(
                    &effect
                ),)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );

        let first = backend
            .finish_durable_object_roster_effect_quiesced(duplicate_roster_effect_quiesced(&effect))
            .await
            .unwrap();
        assert_eq!(first.as_str(), "applied");
        let barriers_after_first_finish = store.tests_physical_barriers().unwrap();
        assert_eq!(
            backend
                .finish_durable_object_roster_effect_quiesced(effect)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::Stale
        );
        assert_eq!(
            store.tests_physical_barriers().unwrap(),
            barriers_after_first_finish,
            "the stale duplicate did not publish another finish"
        );
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            1,
            "a finish never replays the already-quiesced effect"
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roster_group_holds_one_actor_admission_where_single_object_installs_yield_between_members(
    ) {
        // Part 1: the whole five-member group runs inside ONE admitted actor
        // command, so a second caller admitted while it is in flight is served
        // only after the last member.
        let root = DurableTestRoot::new();
        let blocking = Arc::new(BlockingState::new());
        let transport = RecordingBlockingTransport::new(Arc::clone(&blocking), 0);
        let capture = transport.clone();
        let (backend, _, _, store) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport),
            1,
            None,
            None,
            Some((
                root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0x83; 32]).unwrap(),
            )),
        )
        .unwrap();
        let store = store.unwrap();
        let group = roster_group(0x14);
        let generation = roster_generation(1);
        let roster = sa_roster(5);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();

        let observer = tokio::spawn({
            let backend = backend.clone();
            async move { backend.run_durable_object_roster(authority).await }
        });
        wait_until(|| blocking.mutation_calls.load(Ordering::Acquire) == 1).await;
        // The group is mid-flight and durably `Issuing`.
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );

        // A second caller takes the only free queue permit and waits: the
        // roster never needs a second admission for its remaining members.
        let second = tokio::spawn({
            let backend = backend.clone();
            async move {
                backend
                    .query_policy(QueryPolicyRequest::new(
                        policy_parameters().selector,
                        XfrmDirection::Out,
                    ))
                    .await
            }
        });
        wait_until(|| backend.inner.sender.capacity() == 0).await;
        blocking.release();

        assert_eq!(observer.await.unwrap().unwrap().as_str(), "applied");
        let _ = second.await;
        let operations = capture.operations();
        let installs = operations
            .iter()
            .filter(|operation| **operation == "install_sa")
            .count();
        assert_eq!(installs, 5);
        assert_eq!(
            operations.last().copied(),
            Some("query_policy"),
            "the queued caller must be served only after the whole group: {operations:?}"
        );

        // Part 2: five single-object installs are five admissions, so an
        // unrelated caller is served between two of the group's objects.
        let object_root = DurableTestRoot::new();
        let object_blocking = Arc::new(BlockingState::new());
        let object_transport = RecordingBlockingTransport::new(Arc::clone(&object_blocking), 0);
        let object_capture = object_transport.clone();
        let (object_backend, object_store, _, _) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(object_transport),
            1,
            Some((
                object_root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x84; 32]).unwrap(),
            )),
            None,
            None,
        )
        .unwrap();
        let object_store = object_store.unwrap();
        let first_operation = XfrmObjectInstallOperationId::generate().unwrap();
        let object_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let first_request = roster_sa_request(0);
        let first_authority = object_backend
            .prepare_durable_object_install(
                &object_store,
                first_operation,
                object_generation,
                first_request.clone(),
            )
            .await
            .unwrap();
        let first_run = tokio::spawn({
            let backend = object_backend.clone();
            async move { backend.run_durable_object_install(first_authority).await }
        });
        wait_until(|| object_blocking.mutation_calls.load(Ordering::Acquire) == 1).await;
        let interleaved = tokio::spawn({
            let backend = object_backend.clone();
            async move {
                backend
                    .query_policy(QueryPolicyRequest::new(
                        policy_parameters().selector,
                        XfrmDirection::Out,
                    ))
                    .await
            }
        });
        wait_until(|| object_backend.inner.sender.capacity() == 0).await;
        object_blocking.release();
        assert!(first_run.await.unwrap().is_ok());
        let _ = interleaved.await;
        assert_eq!(
            object_backend
                .finalize_durable_object_install(
                    &object_store,
                    first_operation,
                    object_generation,
                    first_request,
                )
                .await
                .unwrap(),
            XfrmObjectInstallDurablePhase::Committed
        );
        // The second object of the same logical group is a separate admission,
        // and the unrelated caller was already served in between.
        let second_authority = object_backend
            .prepare_durable_object_install(
                &object_store,
                XfrmObjectInstallOperationId::generate().unwrap(),
                object_generation,
                roster_sa_request(1),
            )
            .await
            .unwrap();
        assert!(object_backend
            .run_durable_object_install(second_authority)
            .await
            .is_ok());
        let object_operations = object_capture.operations();
        let interleave_index = object_operations
            .iter()
            .position(|operation| *operation == "query_policy")
            .expect("the unrelated caller ran");
        let last_install = object_operations
            .iter()
            .rposition(|operation| *operation == "install_sa")
            .expect("the second object installed");
        assert!(
            interleave_index < last_install,
            "single-object installs must yield the actor between members: {object_operations:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roster_run_cancelled_before_queue_admission_performs_no_effect() {
        let root = DurableTestRoot::new();
        let blocking = Arc::new(BlockingState::new());
        let (backend, _, _, store) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(BlockingTransport {
                state: Arc::clone(&blocking),
            }),
            1,
            None,
            None,
            Some((
                root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0x85; 32]).unwrap(),
            )),
        )
        .unwrap();
        let store = store.unwrap();
        let group = roster_group(0x15);
        let generation = roster_generation(1);
        let roster = sa_roster(3);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();

        let first = tokio::spawn({
            let backend = backend.clone();
            async move { backend.remove_sa(remove_request()).await }
        });
        wait_until(|| blocking.mutation_calls.load(Ordering::Acquire) == 1).await;
        let second = tokio::spawn({
            let backend = backend.clone();
            async move { backend.remove_sa(remove_request()).await }
        });
        wait_until(|| backend.inner.sender.capacity() == 0).await;

        let mut run = Box::pin(backend.run_durable_object_roster(authority));
        assert!(tokio::time::timeout(Duration::from_millis(10), &mut run)
            .await
            .is_err());
        drop(run);
        blocking.release();
        let _ = first.await;
        let _ = second.await;
        assert_eq!(blocking.mutation_calls.load(Ordering::Acquire), 2);

        // The roster never reached the actor: the record is still the prepared
        // truth and recovers as authoritative no-mutation.
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "no_mutation"
        );
        assert_eq!(blocking.mutation_calls.load(Ordering::Acquire), 2);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_roster_run_completes_every_member_after_observer_cancellation() {
        for blocked_ordinal in 0..4 {
            let root = DurableTestRoot::new();
            let blocking = Arc::new(BlockingState::new());
            let (backend, _, _, store) = bind_with_capacity_and_recovery(
                LinuxXfrmBackend::with_transport(RecordingBlockingTransport::new(
                    Arc::clone(&blocking),
                    blocked_ordinal,
                )),
                1,
                None,
                None,
                Some((
                    root.path().to_path_buf(),
                    XfrmObjectRosterRecoveryProofKey::new([0x86; 32]).unwrap(),
                )),
            )
            .unwrap();
            let store = store.unwrap();
            let group = roster_group(0x16 + u8::try_from(blocked_ordinal).unwrap());
            let generation = roster_generation(1);
            let roster = sa_roster(4);
            let authority = backend
                .prepare_durable_object_roster(&store, group, generation, roster.clone())
                .await
                .unwrap();

            let observer = tokio::spawn({
                let backend = backend.clone();
                async move { backend.run_durable_object_roster(authority).await }
            });
            // The configurable barrier holds the requested ordinal's install;
            // all prior members have completed, and `Issuing` is durable.
            wait_until(|| blocking.mutation_calls.load(Ordering::Acquire) == blocked_ordinal + 1)
                .await;
            assert_eq!(
                durable_object_roster_phase(&store, group, generation, &roster),
                Ok(XfrmObjectRosterDurablePhase::Issuing),
                "blocked ordinal {blocked_ordinal}"
            );

            observer.abort();
            let _ = observer.await;
            blocking.release();

            // At every ordinal the admitted command, not its lost observer,
            // owns completion of all roster members.
            assert_eq!(
                backend
                    .finalize_durable_object_roster(&store, group, generation, &roster)
                    .await
                    .unwrap(),
                XfrmObjectRosterDurablePhase::Committed,
                "blocked ordinal {blocked_ordinal}"
            );
            assert_eq!(
                blocking.mutation_calls.load(Ordering::Acquire),
                4,
                "blocked ordinal {blocked_ordinal}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unpolled_roster_run_future_admits_no_effect() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x87);
        let group = roster_group(0x17);
        let generation = roster_generation(1);
        let roster = sa_roster(3);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();

        let run = backend.run_durable_object_roster(authority);
        drop(run);
        assert!(transport.operations().is_empty());
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "no_mutation"
        );
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unresolved_roster_gates_ordinary_mutations_and_both_other_durable_families() {
        let object_root = DurableTestRoot::new();
        let relocation_root = DurableTestRoot::new();
        let roster_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, object_store, relocation_store, roster_store) =
            LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_sa_relocation_and_roster_recovery(
                    object_root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x88; 32]).unwrap(),
                    relocation_root.path().to_path_buf(),
                    XfrmSaRelocationRecoveryProofKey::new([0x89; 32]).unwrap(),
                    roster_root.path().to_path_buf(),
                    XfrmObjectRosterRecoveryProofKey::new([0x8a; 32]).unwrap(),
                )
                .unwrap();
        let group = roster_group(0x18);
        let generation = roster_generation(1);
        let roster = sa_roster(3);

        // A live install authority prepared before the roster is admitted.
        let install_operation = XfrmObjectInstallOperationId::generate().unwrap();
        let install_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let install_request = roster_sa_request(7);
        let install_authority = backend
            .prepare_durable_object_install(
                &object_store,
                install_operation,
                install_generation,
                install_request.clone(),
            )
            .await
            .unwrap();

        let authority = backend
            .prepare_durable_object_roster(&roster_store, group, generation, roster.clone())
            .await
            .unwrap();
        // Leave the group durably `Applied`: unresolved and holding cleanup
        // authority for all three members.
        backend
            .detector_cut_roster_applied(authority)
            .await
            .unwrap();
        assert_eq!(
            durable_object_roster_phase(&roster_store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Applied)
        );

        // Ordinary namespace mutations are fenced.
        assert!(matches!(
            backend
                .install_sa(InstallSaRequest {
                    parameters: sa_parameters(),
                })
                .await,
            Err(XfrmError::Unavailable)
        ));
        assert!(matches!(
            backend
                .remove_policy(RemovePolicyRequest::new(
                    policy_parameters().selector,
                    XfrmDirection::Out,
                ))
                .await,
            Err(XfrmError::Unavailable)
        ));

        // Both other durable families are fenced at preparation.
        assert_eq!(
            backend
                .prepare_durable_object_install(
                    &object_store,
                    XfrmObjectInstallOperationId::generate().unwrap(),
                    XfrmObjectInstallOperationGeneration::new(2).unwrap(),
                    roster_sa_request(8),
                )
                .await
                .unwrap_err(),
            XfrmObjectInstallDurableError::InvalidTransition
        );
        assert_eq!(
            backend
                .prepare_sa_relocation(
                    &relocation_store,
                    XfrmSaRelocationOperationId::generate().unwrap(),
                    XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                    relocation_request(),
                )
                .await
                .unwrap_err(),
            XfrmSaRelocationDurableError::InvalidTransition
        );
        // The roster's own admission fenced the sibling install authority.
        assert_eq!(
            backend
                .run_durable_object_install(install_authority)
                .await
                .unwrap_err(),
            XfrmObjectInstallDurableError::Stale
        );

        // Recovery of the group reopens every gate.
        assert_eq!(
            backend
                .recover_durable_object_roster(&roster_store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "owned_residue_retired"
        );
        backend
            .install_sa(InstallSaRequest {
                parameters: sa_parameters(),
            })
            .await
            .unwrap();
        assert!(backend
            .prepare_sa_relocation(
                &relocation_store,
                XfrmSaRelocationOperationId::generate().unwrap(),
                XfrmSaRelocationOperationGeneration::new(2).unwrap(),
                relocation_request(),
            )
            .await
            .is_ok());
        assert!(matches!(
            backend
                .recover_durable_object_install(
                    &object_store,
                    install_operation,
                    install_generation,
                    install_request,
                )
                .await
                .unwrap(),
            XfrmObjectInstallRestartOutcome::NoMutation
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unresolved_install_and_relocation_gate_roster_preparation_and_run() {
        let object_root = DurableTestRoot::new();
        let relocation_root = DurableTestRoot::new();
        let roster_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, object_store, relocation_store, roster_store) =
            LinuxXfrmBackend::with_transport(transport.clone())
                .bind_current_network_namespace_with_object_sa_relocation_and_roster_recovery(
                    object_root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x8b; 32]).unwrap(),
                    relocation_root.path().to_path_buf(),
                    XfrmSaRelocationRecoveryProofKey::new([0x8c; 32]).unwrap(),
                    roster_root.path().to_path_buf(),
                    XfrmObjectRosterRecoveryProofKey::new([0x8d; 32]).unwrap(),
                )
                .unwrap();
        let group = roster_group(0x19);
        let generation = roster_generation(1);
        let roster = sa_roster(2);

        // The roster authority is prepared while every gate is open.
        let authority = backend
            .prepare_durable_object_roster(&roster_store, group, generation, roster.clone())
            .await
            .unwrap();

        // A prepared SA relocation is itself an unresolved writer authority.
        let relocation_operation = XfrmSaRelocationOperationId::generate().unwrap();
        let relocation_generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let relocation_authority = backend
            .prepare_sa_relocation(
                &relocation_store,
                relocation_operation,
                relocation_generation,
                relocation_request(),
            )
            .await
            .unwrap();
        drop(relocation_authority);

        assert_eq!(
            backend
                .prepare_durable_object_roster(
                    &roster_store,
                    roster_group(0x1a),
                    generation,
                    sa_roster(2),
                )
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::InvalidTransition
        );
        // The roster authority survives the gate through the PUBLIC error: a
        // transient cross-family block returns the exact affine authority the
        // caller passed in, so no second live seal is needed to retry it.
        let gated = backend
            .run_durable_object_roster(authority)
            .await
            .unwrap_err();
        assert_eq!(gated.as_str(), "xfrm_object_roster_gated");
        assert_eq!(
            gated.durable_error(),
            Some(XfrmObjectRosterDurableError::InvalidTransition)
        );
        let authority = gated
            .into_retry_authority()
            .expect("a gate-rejected run must return the exact affine authority");
        assert!(transport.operations().is_empty());

        // Retiring the relocation reopens the roster gate and the SAME
        // authority now runs to completion.
        assert!(matches!(
            backend
                .recover_durable_sa_relocation(
                    &relocation_store,
                    relocation_operation,
                    relocation_generation,
                    relocation_request(),
                )
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
        assert_eq!(
            backend
                .run_durable_object_roster(authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&roster_store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );

        // An unresolved single-object install fences roster preparation too.
        let install_operation = XfrmObjectInstallOperationId::generate().unwrap();
        let install_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let install_request = roster_sa_request(9);
        let install_authority = backend
            .prepare_durable_object_install(
                &object_store,
                install_operation,
                install_generation,
                install_request.clone(),
            )
            .await
            .unwrap();
        assert!(matches!(
            backend
                .run_durable_object_install(install_authority)
                .await
                .unwrap(),
            XfrmObjectInstallDurableOutcome::Acquired(_)
        ));
        assert_eq!(
            backend
                .prepare_durable_object_roster(
                    &roster_store,
                    roster_group(0x1b),
                    generation,
                    sa_roster(2),
                )
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::InvalidTransition
        );
        assert_eq!(
            backend
                .finalize_durable_object_install(
                    &object_store,
                    install_operation,
                    install_generation,
                    install_request,
                )
                .await
                .unwrap(),
            XfrmObjectInstallDurablePhase::Committed
        );
        assert!(backend
            .prepare_durable_object_roster(
                &roster_store,
                roster_group(0x1b),
                generation,
                sa_roster(2)
            )
            .await
            .is_ok());
    }

    /// A run blocked by a SIBLING roster in the same store must consume
    /// nothing and must succeed later with the very same authority.
    ///
    /// `Prepared` deliberately does not gate, so two rosters can legally be
    /// prepared before either runs. If the sibling block were only caught by
    /// the store's own `Prepared -> Issuing` check, admission would already be
    /// gone, both other durable families would already be fenced, and the
    /// second roster's `Prepared` record would be stranded: its authority is
    /// affine and was moved by value, and re-preparing the same members under
    /// a fresh group and generation is refused as a duplicate deletion
    /// identity while that record stays non-terminal.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_sibling_blocked_roster_run_consumes_nothing_and_succeeds_after_the_sibling_resolves()
    {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x93);
        let generation = roster_generation(1);
        let first_group = roster_group(0x2a);
        let second_group = roster_group(0x2b);
        let first = sa_roster(2);
        let second = policy_roster(2);

        let first_authority = backend
            .prepare_durable_object_roster(&store, first_group, generation, first.clone())
            .await
            .unwrap();
        let second_authority = backend
            .prepare_durable_object_roster(&store, second_group, generation, second.clone())
            .await
            .unwrap();

        // Drive the first roster into an unresolved `Issuing` window.
        backend
            .detector_cut_roster_issuing_at_member(first_authority, 1, false)
            .await
            .unwrap();
        assert!(store.has_unresolved_writer_authority().unwrap());
        let after_cut = transport.operations();

        // The second run is refused BEFORE anything is consumed, and the
        // rejection hands the exact affine authority back.
        let gated = backend
            .run_durable_object_roster(second_authority)
            .await
            .unwrap_err();
        assert_eq!(gated.as_str(), "xfrm_object_roster_gated");
        assert_eq!(
            gated.durable_error(),
            Some(XfrmObjectRosterDurableError::InvalidTransition)
        );
        let second_authority = gated
            .into_retry_authority()
            .expect("a sibling-blocked run must return the exact affine authority");
        // The blocked run touched neither the kernel nor the second record.
        assert_eq!(transport.operations(), after_cut);
        assert_eq!(
            store.inspect(&second_authority.prepared),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );

        // Resolving the sibling reopens the gate and the SAME authority runs.
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, first_group, generation, &first)
                .await
                .unwrap()
                .as_str(),
            "rolled_back"
        );
        assert_eq!(
            backend
                .run_durable_object_roster(second_authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&store, second_group, generation, &second)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_roster_does_not_gate_but_is_fenced_by_an_ordinary_mutation() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x8e);
        let group = roster_group(0x1c);
        let generation = roster_generation(1);
        let roster = sa_roster(3);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();

        // A prepared roster has zero effects, so it does not fence ordinary
        // mutations the way a prepared SA relocation does.
        backend
            .install_sa(InstallSaRequest {
                parameters: sa_parameters(),
            })
            .await
            .unwrap();
        assert_eq!(transport.operations(), vec!["install_sa"]);

        // That independently admitted mutation did fence the roster.
        assert_eq!(
            backend
                .run_durable_object_roster(authority)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::Stale
        );
        assert_eq!(transport.operations(), vec!["install_sa"]);
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "no_mutation"
        );
        assert_eq!(transport.operations(), vec!["install_sa"]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_authority_survives_a_relocation_gated_ordinary_mutation_rejection() {
        let relocation_root = DurableTestRoot::new();
        let roster_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, _, relocation_store, roster_store) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport.clone()),
            LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
            None,
            Some((
                relocation_root.path().to_path_buf(),
                XfrmSaRelocationRecoveryProofKey::new([0x8f; 32]).unwrap(),
            )),
            Some((
                roster_root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0x90; 32]).unwrap(),
            )),
        )
        .unwrap();
        let relocation_store = relocation_store.unwrap();
        let roster_store = roster_store.unwrap();
        let group = roster_group(0x1d);
        let generation = roster_generation(1);
        let roster = sa_roster(2);

        let authority = backend
            .prepare_durable_object_roster(&roster_store, group, generation, roster.clone())
            .await
            .unwrap();
        let relocation_operation = XfrmSaRelocationOperationId::generate().unwrap();
        let relocation_generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let relocation_authority = backend
            .prepare_sa_relocation(
                &relocation_store,
                relocation_operation,
                relocation_generation,
                relocation_request(),
            )
            .await
            .unwrap();
        drop(relocation_authority);

        // The ordinary mutation is rejected by the relocation gate, so no
        // kernel effect happened and the roster authority must survive it.
        assert!(matches!(
            backend
                .install_sa(InstallSaRequest {
                    parameters: sa_parameters(),
                })
                .await,
            Err(XfrmError::Unavailable)
        ));
        assert!(transport.operations().is_empty());
        let gated = backend
            .run_durable_object_roster(authority)
            .await
            .unwrap_err();
        assert_eq!(
            gated.as_str(),
            "xfrm_object_roster_gated",
            "a gate-rejected mutation must not turn the surviving authority stale"
        );
        assert_eq!(
            gated.durable_error(),
            Some(XfrmObjectRosterDurableError::InvalidTransition)
        );
        let authority = gated
            .into_retry_authority()
            .expect("a gate-rejected run must return the exact affine authority");

        assert!(matches!(
            backend
                .recover_durable_sa_relocation(
                    &relocation_store,
                    relocation_operation,
                    relocation_generation,
                    relocation_request(),
                )
                .await
                .unwrap(),
            XfrmSaRelocationRestartOutcome::NoMutation
        ));
        assert_eq!(
            backend
                .run_durable_object_roster(authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn half_migrated_consumer_is_serialized_between_roster_and_single_object_sessions() {
        let object_root = DurableTestRoot::new();
        let roster_root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, object_store, _, roster_store) = bind_with_capacity_and_recovery(
            LinuxXfrmBackend::with_transport(transport.clone()),
            LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
            Some((
                object_root.path().to_path_buf(),
                XfrmObjectRecoveryProofKey::new([0x91; 32]).unwrap(),
            )),
            None,
            Some((
                roster_root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0x92; 32]).unwrap(),
            )),
        )
        .unwrap();
        let object_store = object_store.unwrap();
        let roster_store = roster_store.unwrap();
        let group = roster_group(0x1e);
        let generation = roster_generation(1);
        // Session A migrates to one roster; session B still drives five
        // single-object installs.
        let roster = child_sa_roster();
        let session_b = (0..5).map(roster_sa_request).collect::<Vec<_>>();
        let object_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();

        let roster_authority = backend
            .prepare_durable_object_roster(&roster_store, group, generation, roster.clone())
            .await
            .unwrap();
        assert_eq!(
            backend
                .run_durable_object_roster(roster_authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );

        // Session B is now serialized behind session A's unresolved roster:
        // fenced, never corrupted.
        assert_eq!(
            backend
                .prepare_durable_object_install(
                    &object_store,
                    XfrmObjectInstallOperationId::generate().unwrap(),
                    object_generation,
                    session_b[0].clone(),
                )
                .await
                .unwrap_err(),
            XfrmObjectInstallDurableError::InvalidTransition
        );
        assert_eq!(
            backend
                .finalize_durable_object_roster(&roster_store, group, generation, &roster)
                .await
                .unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );

        // With session A resolved, session B completes every object, and each
        // acquired object in turn fences a new roster until it is finalized.
        let mut operations = Vec::new();
        for request in &session_b {
            let operation_id = XfrmObjectInstallOperationId::generate().unwrap();
            let authority = backend
                .prepare_durable_object_install(
                    &object_store,
                    operation_id,
                    object_generation,
                    request.clone(),
                )
                .await
                .unwrap();
            assert!(matches!(
                backend.run_durable_object_install(authority).await.unwrap(),
                XfrmObjectInstallDurableOutcome::Acquired(_)
            ));
            assert_eq!(
                backend
                    .prepare_durable_object_roster(
                        &roster_store,
                        roster_group(0x1f),
                        generation,
                        sa_roster(2),
                    )
                    .await
                    .unwrap_err(),
                XfrmObjectRosterDurableError::InvalidTransition
            );
            assert_eq!(
                backend
                    .finalize_durable_object_install(
                        &object_store,
                        operation_id,
                        object_generation,
                        request.clone(),
                    )
                    .await
                    .unwrap(),
                XfrmObjectInstallDurablePhase::Committed
            );
            operations.push(operation_id);
        }
        assert_eq!(operations.len(), 5);

        // Both families end resolved and a fresh roster is admissible again.
        let authority = backend
            .prepare_durable_object_roster(
                &roster_store,
                roster_group(0x1f),
                generation,
                sa_roster(2),
            )
            .await
            .unwrap();
        assert_eq!(
            backend
                .run_durable_object_roster(authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_mutate_then_recover_reports_repair_required_and_keeps_the_gate_closed() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x93);
        let group = roster_group(0x20);
        let generation = roster_generation(1);
        let roster = sa_roster(3);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        backend
            .detector_cut_roster_applied(authority)
            .await
            .unwrap();

        // Model the forbidden ordering: an out-of-band writer-epoch burn under
        // an unresolved roster. The public gate refuses this, which is why the
        // store exposes it only to tests.
        store.tests_force_advance_writer_epoch().unwrap();
        let before = transport.operations().len();

        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "repair_required"
        );
        // Nothing was deleted, the record is retained, and the gate stays shut.
        assert_eq!(transport.operations().len(), before);
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Applied)
        );
        assert!(matches!(
            backend.remove_sa(remove_request()).await,
            Err(XfrmError::Unavailable)
        ));

        // Recover-first ordering on a fresh store converges instead.
        let clean_root = DurableTestRoot::new();
        let clean_transport = RecordingSuccessTransport::default();
        let (clean_backend, clean_store) =
            bind_with_roster_recovery(clean_transport.clone(), &clean_root, 0x94);
        let clean_authority = clean_backend
            .prepare_durable_object_roster(&clean_store, group, generation, roster.clone())
            .await
            .unwrap();
        clean_backend
            .detector_cut_roster_applied(clean_authority)
            .await
            .unwrap();
        assert_eq!(
            clean_backend
                .recover_durable_object_roster(&clean_store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "owned_residue_retired"
        );
        clean_backend.remove_sa(remove_request()).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deferred_dscp_gate_rejects_the_whole_roster_before_any_durable_step() {
        let root = DurableTestRoot::new();
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
        let runtime = DeferredDscpRuntime::with_outcomes([]);
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = LinuxXfrmBackend::with_transport_and_deferred_dscp_runtime(
            transport.clone(),
            config,
            runtime.clone(),
        )
        .unwrap()
        .bind_current_network_namespace_with_object_roster_recovery(
            root.path().to_path_buf(),
            XfrmObjectRosterRecoveryProofKey::new([0x95; 32]).unwrap(),
        )
        .unwrap();
        let group = roster_group(0x21);
        let generation = roster_generation(1);
        // Only the LAST member carries a DSCP codepoint: the preflight is
        // all-or-nothing, so it must still reject the whole group.
        let roster = XfrmObjectRosterRequest::new(vec![
            XfrmObjectRosterMemberRequest::new(roster_sa_request(0)),
            XfrmObjectRosterMemberRequest::new(roster_policy_request(0)),
            XfrmObjectRosterMemberRequest::new({
                let mut parameters = sa_parameters();
                parameters.id.spi = 0x2000_0002;
                parameters.egress_dscp = Some(DscpCodepoint::new(46).unwrap());
                XfrmObjectInstallRequest::Sa(InstallSaRequest { parameters })
            }),
        ])
        .unwrap();

        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        let error = backend
            .run_durable_object_roster(authority)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_str(),
            "xfrm_object_roster_dscp_activation_required"
        );
        assert!(error.durable_error().is_none());
        assert!(error.readback_source().is_none());
        let authority = error.into_retry_authority().expect("retry authority");
        // Durable state untouched and not one member was swept.
        assert_eq!(
            store.inspect(&authority.prepared),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        assert!(transport.operations().is_empty());
        assert!(runtime.records().is_empty());

        // After activation the same authority is admitted: the group gets past
        // the preflight and reaches the backend.
        backend.activate_dscp_marking().await.unwrap();
        let result = backend.run_durable_object_roster(authority).await;
        let label = result.as_ref().err().map(|error| error.as_str());
        assert_ne!(
            label,
            Some("xfrm_object_roster_dscp_activation_required"),
            "an activated actor must not re-reject the retried authority"
        );
        assert!(
            !transport.operations().is_empty(),
            "the admitted retry must reach the backend"
        );

        // A policy-only roster is unaffected by the deferred DSCP gate.
        let policy_root = DurableTestRoot::new();
        let policy_config = LinuxXfrmDscpMarkingConfig::new([String::from("lo")], 25).unwrap();
        let policy_runtime = DeferredDscpRuntime::with_outcomes([]);
        let policy_transport = RecordingSuccessTransport::default();
        let (policy_backend, policy_store) =
            LinuxXfrmBackend::with_transport_and_deferred_dscp_runtime(
                policy_transport.clone(),
                policy_config,
                policy_runtime.clone(),
            )
            .unwrap()
            .bind_current_network_namespace_with_object_roster_recovery(
                policy_root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0x96; 32]).unwrap(),
            )
            .unwrap();
        let policy_group = roster_group(0x22);
        let policy_only = policy_roster(3);
        let policy_authority = policy_backend
            .prepare_durable_object_roster(
                &policy_store,
                policy_group,
                generation,
                policy_only.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            policy_backend
                .run_durable_object_roster(policy_authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );
        assert!(policy_runtime.records().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_retry_authority_round_trips_only_for_proved_clean_rejections() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x97);
        let group = roster_group(0x23);
        let generation = roster_generation(1);
        let roster = sa_roster(2);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();

        // An untrustworthy pre-effect sweep readback, driven through the real
        // actor: the admission is already consumed by the time the sweep runs,
        // so this exercises the seal re-registration path end to end.
        let untrusted_root = DurableTestRoot::new();
        let untrusted_transport = UntrustedReadbackTransport::default();
        let (untrusted_backend, untrusted_store) =
            bind_with_roster_recovery(untrusted_transport.clone(), &untrusted_root, 0x9c);
        let untrusted_group = roster_group(0x2c);
        let untrusted_roster = sa_roster(2);
        let untrusted_authority = untrusted_backend
            .prepare_durable_object_roster(
                &untrusted_store,
                untrusted_group,
                generation,
                untrusted_roster.clone(),
            )
            .await
            .unwrap();
        let readback = untrusted_backend
            .run_durable_object_roster(untrusted_authority)
            .await
            .unwrap_err();
        assert_eq!(
            readback.as_str(),
            "xfrm_object_roster_pre_effect_readback_failed"
        );
        assert!(readback.durable_error().is_none());
        assert!(readback.readback_source().is_some());
        let recovered = readback.into_retry_authority().expect("retry authority");
        // Durable state is untouched, and the returned authority is still the
        // registered live admission: an unregistered seal would make the retry
        // stale rather than reproduce the same proved-clean rejection.
        assert_eq!(
            untrusted_store.inspect(&recovered.prepared),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        let repeated = untrusted_backend
            .run_durable_object_roster(recovered)
            .await
            .unwrap_err();
        assert_eq!(
            repeated.as_str(),
            "xfrm_object_roster_pre_effect_readback_failed"
        );
        drop(repeated);

        // The other proved-clean rejection is driven end to end by
        // `deferred_dscp_gate_rejects_the_whole_roster_before_any_durable_step`;
        // here only the accessor shape is pinned.
        let dscp = XfrmObjectRosterRunError::dscp_activation_required(Box::new(
            duplicate_roster_admission(&authority),
        ));
        assert!(dscp.durable_error().is_none());
        assert!(dscp.into_retry_authority().is_some());
        let replayed = duplicate_roster_admission(&authority);
        assert_eq!(
            backend
                .run_durable_object_roster(authority)
                .await
                .unwrap()
                .as_str(),
            "applied"
        );

        // Durable-path failures never replay.
        for error in [
            XfrmObjectRosterDurableError::Stale,
            XfrmObjectRosterDurableError::WrongBinding,
            XfrmObjectRosterDurableError::InvalidTransition,
            XfrmObjectRosterDurableError::Storage,
        ] {
            let run_error = XfrmObjectRosterRunError::from(error);
            assert_eq!(run_error.durable_error(), Some(error));
            assert!(run_error.readback_source().is_none());
            assert!(run_error.into_retry_authority().is_none());
        }
        // The consumed authority is not replayable either.
        assert_eq!(
            backend
                .run_durable_object_roster(replayed)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::Stale
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn lost_roster_replies_leave_recoverable_truth_and_a_value_free_label() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x98);
        let group = roster_group(0x24);
        let generation = roster_generation(1);
        let roster = sa_roster(3);

        // An admitted prepare whose observer went away still leaves durable
        // prepared truth behind, and it recovers as authoritative no-mutation.
        let operation = DurableObjectRosterOperation {
            store: store.clone(),
            group_id: group,
            generation,
            roster: roster.clone(),
        };
        let (reply, lost_observer) = oneshot::channel();
        let permit = backend.inner.sender.reserve().await.unwrap();
        permit.send(NamespaceCommand::PrepareDurableObjectRoster(
            Box::new(operation),
            reply,
        ));
        drop(lost_observer);
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "no_mutation"
        );
        assert!(transport.operations().is_empty());

        // A dropped actor classifies every roster dispatch value-free.
        let (sender, mut receiver) = mpsc::channel(1);
        let lost_backend = backend_from_sender(sender);
        let worker = tokio::spawn(async move {
            drop(receiver.recv().await);
        });
        assert_eq!(
            lost_backend
                .prepare_durable_object_roster(&store, roster_group(0x25), generation, roster)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::Storage
        );
        worker.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_roster_authority_blocks_same_process_recovery_until_dropped() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x99);
        let group = roster_group(0x26);
        let generation = roster_generation(1);
        let roster = sa_roster(3);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();

        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::InvalidTransition
        );
        assert_eq!(
            backend
                .adopt_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::InvalidTransition
        );
        assert!(transport.operations().is_empty());

        drop(authority);
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "no_mutation"
        );
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_adopt_refuses_an_unconverged_group_and_recover_reverse_compensates() {
        let adopt_root = DurableTestRoot::new();
        let adopt_transport = RecordingSuccessTransport::default();
        let (adopt_backend, adopt_store) =
            bind_with_roster_recovery(adopt_transport.clone(), &adopt_root, 0x9a);
        let group = roster_group(0x27);
        let generation = roster_generation(1);
        let roster = sa_roster(3);
        let authority = adopt_backend
            .prepare_durable_object_roster(&adopt_store, group, generation, roster.clone())
            .await
            .unwrap();
        adopt_backend
            .detector_cut_roster_applied(authority)
            .await
            .unwrap();

        // The readbacks model absence, so adoption cannot prove convergence and
        // refuses without publishing or deleting anything.
        assert_eq!(
            adopt_backend
                .adopt_durable_object_roster(&adopt_store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "adoption_refused"
        );
        assert_eq!(
            durable_object_roster_phase(&adopt_store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Applied)
        );
        // The consumer may still choose recovery, which reverse-compensates.
        assert_eq!(
            adopt_backend
                .recover_durable_object_roster(&adopt_store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "owned_residue_retired"
        );
        let removals = adopt_transport
            .operations()
            .iter()
            .filter(|operation| {
                matches!(
                    **operation,
                    "remove_sa" | "remove_policy" | "remove_policy_exact"
                )
            })
            .count();
        assert_eq!(removals, 3, "every acquired member is reverse-compensated");
    }

    /// Readbacks answer "absent" until the test publishes a scripted set of
    /// present bodies, so one backend can model both an applying group and the
    /// converged kernel a restart would find.
    #[cfg(unix)]
    #[derive(Debug, Clone)]
    struct RosterConvergenceTransport {
        present: Arc<AtomicBool>,
        bodies: Arc<Mutex<VecDeque<SensitiveBuffer>>>,
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    #[cfg(unix)]
    impl RosterConvergenceTransport {
        fn new() -> Self {
            Self {
                present: Arc::new(AtomicBool::new(false)),
                bodies: Arc::new(Mutex::new(VecDeque::new())),
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn converge(&self, bodies: impl IntoIterator<Item = SensitiveBuffer>) {
            *self
                .bodies
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = bodies.into_iter().collect();
            self.present.store(true, Ordering::Release);
        }

        fn operations(&self) -> Vec<&'static str> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[cfg(unix)]
    impl LinuxXfrmTransport for RosterConvergenceTransport {
        fn transact(
            &self,
            operation: &'static str,
            operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
            match operation_class {
                crate::linux::NetlinkOperationClass::ReadOnly => {
                    if !self.present.load(Ordering::Acquire) {
                        return Err(XfrmError::NotFound);
                    }
                    self.bodies
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .pop_front()
                        .map(Some)
                        .ok_or(XfrmError::NotFound)
                }
                crate::linux::NetlinkOperationClass::Mutation => Ok(None),
            }
        }

        fn probe(&self, _config: LinuxXfrmBackendConfig) -> XfrmProbe {
            XfrmProbe::unsupported()
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_adopt_commits_a_converged_applied_group_without_deleting_anything() {
        let root = DurableTestRoot::new();
        let transport = RosterConvergenceTransport::new();
        let (backend, store) = LinuxXfrmBackend::with_transport(transport.clone())
            .bind_current_network_namespace_with_object_roster_recovery(
                root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0xa0; 32]).unwrap(),
            )
            .unwrap();
        let group = roster_group(0x2a);
        let generation = roster_generation(1);
        let roster = sa_roster(3);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();
        // Stop at the unfinalized `Applied` record: exactly the window in which
        // a consumer whose deadline expired must choose adopt or recover.
        backend
            .detector_cut_roster_applied(authority)
            .await
            .unwrap();
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Applied)
        );

        // The kernel now reads back every acquired member, so adoption proves
        // convergence and commits additively.
        transport
            .converge((0..3).map(|index| durable_object_readback_body(&roster_sa_request(index))));
        let before = transport.operations().len();
        let outcome = backend
            .adopt_durable_object_roster(&store, group, generation, &roster)
            .await
            .unwrap();
        assert_eq!(outcome.as_str(), "adopted");
        assert_eq!(outcome.members().arity(), 3);
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Committed)
        );
        // Adoption is purely additive: three exact readbacks and no deletion.
        let adoption = &transport.operations()[before..];
        assert_eq!(adoption, ["query_sa", "query_sa", "query_sa"]);

        // A committed group reports idempotently and never authorizes cleanup.
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "committed"
        );
        assert!(!transport.operations().iter().any(|operation| matches!(
            *operation,
            "remove_sa" | "remove_policy" | "remove_policy_exact"
        )));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_detector_cuts_leave_the_declared_unresolved_windows() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x9b);
        let group = roster_group(0x28);
        let generation = roster_generation(1);
        let roster = sa_roster(4);
        let authority = backend
            .prepare_durable_object_roster(&store, group, generation, roster.clone())
            .await
            .unwrap();

        // Cut at member two without admitting its effect: two members applied.
        backend
            .detector_cut_roster_issuing_at_member(authority, 2, false)
            .await
            .unwrap();
        assert_eq!(
            durable_object_roster_phase(&store, group, generation, &roster),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
        assert_eq!(
            transport
                .operations()
                .iter()
                .filter(|operation| **operation == "install_sa")
                .count(),
            2
        );
        // The unresolved cut keeps every cooperating mutation fenced.
        assert!(matches!(
            backend.remove_sa(remove_request()).await,
            Err(XfrmError::Unavailable)
        ));
        assert_eq!(
            backend
                .recover_durable_object_roster(&store, group, generation, &roster)
                .await
                .unwrap()
                .as_str(),
            "rolled_back"
        );

        // The compensating cut runs recovery's own validation chain, so a
        // wrong store instance is refused before any delete.
        let wrong_root = DurableTestRoot::new();
        let wrong_store = XfrmObjectRosterRecoveryStore::open_bound(
            wrong_root.path(),
            XfrmObjectRosterRecoveryProofKey::new([0x9c; 32]).unwrap(),
            backend.network_namespace_binding().durable_bytes().unwrap(),
        )
        .unwrap();
        assert_eq!(
            backend
                .detector_cut_roster_compensating_at_member(
                    &wrong_store,
                    group,
                    generation,
                    &roster,
                    0,
                    false,
                )
                .await
                .unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn roster_run_error_and_authority_diagnostics_are_value_free() {
        let root = DurableTestRoot::new();
        let transport = RecordingSuccessTransport::default();
        let (backend, store) = bind_with_roster_recovery(transport.clone(), &root, 0x9d);
        // The fixture members carry addresses, SPIs, and selectors; none may
        // leak through any roster diagnostic.
        let roster = child_sa_roster();
        let authority = backend
            .prepare_durable_object_roster(&store, roster_group(0x29), roster_generation(1), roster)
            .await
            .unwrap();

        assert_eq!(
            format!("{authority:?}"),
            "XfrmObjectRosterAdmissionAuthority(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", authority.prepared),
            "XfrmObjectRosterRecoveryHandle(<redacted>)"
        );

        for (error, label) in [
            (
                XfrmObjectRosterRunError::from(XfrmObjectRosterDurableError::NotFound),
                "xfrm_object_roster_recovery_not_found",
            ),
            (
                XfrmObjectRosterRunError::from(XfrmObjectRosterDurableError::WrongBinding),
                "xfrm_object_roster_recovery_wrong_binding",
            ),
            (
                XfrmObjectRosterRunError::gated(
                    Box::new(duplicate_roster_admission(&authority)),
                    XfrmObjectRosterDurableError::InvalidTransition,
                ),
                "xfrm_object_roster_gated",
            ),
            (
                XfrmObjectRosterRunError::dscp_activation_required(Box::new(
                    duplicate_roster_admission(&authority),
                )),
                "xfrm_object_roster_dscp_activation_required",
            ),
            (
                XfrmObjectRosterRunError::pre_effect_readback_failed(
                    Box::new(duplicate_roster_admission(&authority)),
                    XfrmError::StateIndeterminate {
                        operation: "query_sa",
                    },
                ),
                "xfrm_object_roster_pre_effect_readback_failed",
            ),
        ] {
            assert_eq!(error.as_str(), label);
            assert_eq!(error.to_string(), label);
            let debug = format!("{error:?}");
            assert!(debug.contains(label), "debug must carry only the label");
            for leaked in ["192.0", "10.1", "0x2000", "20000000", "3040", "1020"] {
                assert!(!debug.contains(leaked), "diagnostic leaked {leaked}");
                assert!(!label.contains(leaked), "label leaked {leaked}");
            }
        }
        drop(authority);
        assert!(transport.operations().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn roster_store_is_atomically_attached_and_a_foreign_root_fails_closed_at_bind() {
        let root = DurableTestRoot::new();
        let (backend, store) =
            LinuxXfrmBackend::with_transport(RecordingSuccessTransport::default())
                .bind_current_network_namespace_with_object_roster_recovery(
                    root.path().to_path_buf(),
                    XfrmObjectRosterRecoveryProofKey::new([0x9e; 32]).unwrap(),
                )
                .unwrap();
        // The permanent lease is already held when the handle becomes visible.
        assert!(store.advance_writer_epoch().is_ok());
        let error = LinuxXfrmBackend::with_transport(RecordingSuccessTransport::default())
            .bind_current_network_namespace_with_object_roster_recovery(
                root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0x9e; 32]).unwrap(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            XfrmObjectRecoveryBindError::RosterStore {
                source: XfrmObjectRosterDurableError::StoreBusy
            }
        ));
        assert_eq!(error.as_str(), "xfrm_object_roster_recovery_bind_store");
        assert!(format!("{error:?}").contains("xfrm_object_roster_recovery_bind_store"));
        drop(store);
        drop(backend);

        // A root leased by another durable family is refused at bind time, so
        // no mutation-capable handle is ever returned for it.
        let foreign_root = DurableTestRoot::new();
        let (object_backend, object_store) =
            LinuxXfrmBackend::with_transport(RecordingSuccessTransport::default())
                .bind_current_network_namespace_with_object_recovery(
                    foreign_root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x9f; 32]).unwrap(),
                )
                .unwrap();
        drop(object_store);
        drop(object_backend);
        let error = LinuxXfrmBackend::with_transport(RecordingSuccessTransport::default())
            .bind_current_network_namespace_with_object_roster_recovery(
                foreign_root.path().to_path_buf(),
                XfrmObjectRosterRecoveryProofKey::new([0x9f; 32]).unwrap(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            XfrmObjectRecoveryBindError::RosterStore { .. }
        ));
    }
}
