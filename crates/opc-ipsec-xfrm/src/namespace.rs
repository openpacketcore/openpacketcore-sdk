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
        durable_object_install_phase, finalize_durable_object_install as finalize_object_install,
        issue_durable_object_install as run_object_install,
        prepare_durable_object_install as prepare_object_install,
        recover_durable_object_install as recover_object_install,
        validate_durable_object_install_admission as validate_object_install_admission,
        XfrmObjectInstallDurableOutcome, XfrmObjectInstallRestartOutcome,
    },
    durable_object::{
        XfrmObjectInstallDurableError, XfrmObjectInstallDurablePhase,
        XfrmObjectInstallOperationGeneration, XfrmObjectInstallOperationId,
        XfrmObjectInstallRecoveryHandle, XfrmObjectInstallRecoveryStore,
        XfrmObjectRecoveryProofKey,
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
    LinuxXfrmBackend, QuerySaRequest, RekeyPolicyRequest, RekeySaRequest, RelocateSaRequest,
    RemovePolicyRequest, RemoveSaRequest, SaParameters, SaRelocationIdentity, SaState,
    SpiAllocation, XfrmBackend, XfrmCapability, XfrmCompositeInstallRequest, XfrmError, XfrmProbe,
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
}

#[cfg(unix)]
impl XfrmObjectRecoveryBindError {
    /// Stable, value-free error label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Backend { .. } => "xfrm_object_recovery_bind_backend",
            Self::Store { .. } => "xfrm_object_recovery_bind_store",
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
    for (output, pair) in boot_id.iter_mut().zip(hexadecimal.chunks_exact(2)) {
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
/// closed returns the original affine authority through
/// [`Self::into_retry_authority`]. No durable phase or writer epoch has
/// changed, so the caller may activate the same namespace actor and retry that
/// exact authority. Every other failure consumes the authority under the
/// durable protocol's existing fail-closed recovery contract.
#[cfg(unix)]
pub struct XfrmObjectInstallRunError {
    kind: XfrmObjectInstallRunErrorKind,
}

#[cfg(unix)]
enum XfrmObjectInstallRunErrorKind {
    Durable(XfrmObjectInstallDurableError),
    DscpActivationRequired(Box<XfrmObjectInstallAdmissionAuthority>),
}

#[cfg(unix)]
impl XfrmObjectInstallRunError {
    const DSCP_ACTIVATION_REQUIRED: &'static str = "xfrm_object_install_dscp_activation_required";

    fn dscp_activation_required(authority: Box<XfrmObjectInstallAdmissionAuthority>) -> Self {
        Self {
            kind: XfrmObjectInstallRunErrorKind::DscpActivationRequired(authority),
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
        }
    }

    /// Return the underlying durable-protocol error, when this was not a
    /// clean deferred-activation rejection.
    #[must_use]
    pub const fn durable_error(&self) -> Option<XfrmObjectInstallDurableError> {
        match &self.kind {
            XfrmObjectInstallRunErrorKind::Durable(error) => Some(*error),
            XfrmObjectInstallRunErrorKind::DscpActivationRequired(_) => None,
        }
    }

    /// Recover retry authority from a proved pre-effect DSCP activation gate.
    ///
    /// `None` means the error follows the ordinary durable recovery contract
    /// and no authority may be replayed.
    #[must_use]
    pub fn into_retry_authority(self) -> Option<XfrmObjectInstallAdmissionAuthority> {
        match self.kind {
            XfrmObjectInstallRunErrorKind::DscpActivationRequired(authority) => Some(*authority),
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
/// future cancelled while waiting for capacity has not submitted work. Once a
/// permit is obtained, submission is synchronous and the actor completes the
/// admitted operation even if its response receiver is dropped. If an admitted
/// mutation loses its reply, the caller receives
/// [`XfrmError::StateIndeterminate`]; read-only operations receive
/// [`XfrmError::Unavailable`]. Dropping the final clone closes the sender; the
/// detached actor drains already-admitted commands and exits without blocking
/// the dropping thread.
#[derive(Clone)]
pub struct NamespaceBoundLinuxXfrmBackend {
    inner: Arc<NamespaceBoundLinuxXfrmBackendInner>,
}

struct NamespaceBoundLinuxXfrmBackendInner {
    sender: mpsc::Sender<NamespaceCommand>,
    actor_binding: NamespaceActorBinding,
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
    bind_with_capacity_and_recovery(backend, capacity, None)
        .map(|(backend, _)| backend)
        .map_err(|error| match error {
            XfrmObjectRecoveryBindError::Backend { source } => source,
            // No store was requested, so this variant is unreachable without
            // an internal protocol defect. Keep the legacy API value-free.
            XfrmObjectRecoveryBindError::Store { .. } => XfrmError::Unavailable,
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
    let (backend, store) = bind_with_capacity_and_recovery(
        backend,
        LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY,
        Some((path, proof_key)),
    )?;
    let store = store.ok_or(XfrmObjectRecoveryBindError::Store {
        source: XfrmObjectInstallDurableError::WrongBinding,
    })?;
    Ok((backend, store))
}

#[cfg(unix)]
fn bind_with_capacity_and_recovery(
    backend: LinuxXfrmBackend,
    capacity: usize,
    recovery: Option<(PathBuf, XfrmObjectRecoveryProofKey)>,
) -> Result<
    (
        NamespaceBoundLinuxXfrmBackend,
        Option<XfrmObjectInstallRecoveryStore>,
    ),
    XfrmObjectRecoveryBindError,
> {
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
            move || run_actor(backend, actor_binding, receiver, startup_sender, recovery)
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
    let store = startup?;

    Ok((
        NamespaceBoundLinuxXfrmBackend {
            inner: Arc::new(NamespaceBoundLinuxXfrmBackendInner {
                sender,
                actor_binding,
            }),
        },
        store,
    ))
}

#[cfg(unix)]
fn run_actor(
    backend: LinuxXfrmBackend,
    actor_binding: NamespaceActorBinding,
    mut receiver: mpsc::Receiver<NamespaceCommand>,
    startup: std::sync::mpsc::SyncSender<
        Result<Option<XfrmObjectInstallRecoveryStore>, XfrmObjectRecoveryBindError>,
    >,
    recovery: Option<(PathBuf, XfrmObjectRecoveryProofKey)>,
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

    if let Err(error) = backend.prepare_namespace_actor() {
        let _ = startup.send(Err(XfrmObjectRecoveryBindError::Backend { source: error }));
        return;
    }

    let mut state = NamespaceActorState::new(actor_binding);
    let store = match recovery {
        Some((path, proof_key)) => {
            let namespace_binding = match state.actor_binding.namespace().durable_bytes() {
                Ok(binding) => binding,
                Err(source) => {
                    let _ = startup.send(Err(XfrmObjectRecoveryBindError::Store { source }));
                    return;
                }
            };
            match XfrmObjectInstallRecoveryStore::open_bound(&path, proof_key, namespace_binding) {
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
    if startup.send(Ok(store)).is_err() {
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
    fn consume_object_install_admission(
        &mut self,
        authority: &XfrmObjectInstallAdmissionAuthority,
    ) -> Result<(), XfrmObjectInstallDurableError> {
        self.require_object_install_admission(authority)?;
        self.object_install_admissions.remove(&authority.key());
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

    fn admit_xfrm_mutation(&mut self) -> Result<(), XfrmError> {
        #[cfg(unix)]
        if let Some(store) = &self.object_recovery_store {
            store
                .advance_writer_epoch()
                .map_err(|_| XfrmError::Unavailable)?;
            self.object_install_admissions.clear();
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
    /// Only an authenticated, epoch-current acquired record authorizes exact
    /// deletion. Prepared, explicit no-mutation, indeterminate, stale,
    /// malformed, and mismatched records never authorize deletion.
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
    FinalizeDurableObjectInstall(
        Box<DurableObjectOperation>,
        oneshot::Sender<Result<XfrmObjectInstallDurablePhase, XfrmObjectInstallDurableError>>,
    ),
    #[cfg(unix)]
    RecoverDurableObjectInstall(
        Box<DurableObjectOperation>,
        oneshot::Sender<Result<XfrmObjectInstallRestartOutcome, XfrmObjectInstallDurableError>>,
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
                    Ok(()) => prepare_object_install(
                        &operation.store,
                        operation.operation_id,
                        operation.operation_generation,
                        &operation.request,
                    )
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
                let result = match state.consume_object_install_admission(&authority) {
                    Ok(()) => {
                        state.invalidate_counter_receipts();
                        run_object_install(
                            &authority.operation.store,
                            &authority.prepared,
                            authority.operation.operation_id,
                            authority.operation.operation_generation,
                            &authority.operation.request,
                            backend,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let _ = reply.send(result.map_err(XfrmObjectInstallRunError::from));
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
                    .and_then(|_| {
                        state.reconcile_object_install_admission(
                            operation.operation_id,
                            operation.operation_generation,
                        )
                    });
                let result = match validation {
                    Ok(()) => {
                        state.invalidate_counter_receipts();
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
            Self::FinalizeDurableObjectInstall(_, reply) => {
                let _ = reply.send(Err(XfrmObjectInstallDurableError::WrongBinding));
            }
            #[cfg(unix)]
            Self::RecoverDurableObjectInstall(_, reply) => {
                let _ = reply.send(Err(XfrmObjectInstallDurableError::WrongBinding));
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
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
            _operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
            Ok(None)
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
        assert_eq!(transport.operations(), vec!["install_sa"]);

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
        assert_eq!(transport.operations(), vec!["install_sa"]);
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
    async fn admitted_durable_issue_finishes_after_observer_cancellation() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let blocking = Arc::new(BlockingState::new());
            let (backend, store) = bind_with_capacity_and_recovery(
                LinuxXfrmBackend::with_transport(BlockingTransport {
                    state: Arc::clone(&blocking),
                }),
                1,
                Some((
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x6b; 32]).unwrap(),
                )),
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
            wait_until(|| blocking.calls.load(Ordering::Acquire) == 1).await;
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
            assert_eq!(blocking.calls.load(Ordering::Acquire), 1);
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn durable_issue_cancelled_before_queue_admission_performs_no_effect() {
        for request in durable_object_requests() {
            let root = DurableTestRoot::new();
            let blocking = Arc::new(BlockingState::new());
            let (backend, store) = bind_with_capacity_and_recovery(
                LinuxXfrmBackend::with_transport(BlockingTransport {
                    state: Arc::clone(&blocking),
                }),
                1,
                Some((
                    root.path().to_path_buf(),
                    XfrmObjectRecoveryProofKey::new([0x6c; 32]).unwrap(),
                )),
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
                async move { backend.query_sa(query_request()).await }
            });
            wait_until(|| blocking.calls.load(Ordering::Acquire) == 1).await;
            let second = tokio::spawn({
                let backend = backend.clone();
                async move { backend.query_sa(query_request()).await }
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
            assert_eq!(blocking.calls.load(Ordering::Acquire), 2);
            assert!(matches!(
                backend
                    .recover_durable_object_install(&store, operation_id, generation, request,)
                    .await
                    .unwrap(),
                XfrmObjectInstallRestartOutcome::NoMutation
            ));
            assert_eq!(blocking.calls.load(Ordering::Acquire), 2);
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
            assert_eq!(transport.operations().len(), 1);
            assert_eq!(
                backend
                    .run_durable_object_install(authority)
                    .await
                    .unwrap_err(),
                XfrmObjectInstallDurableError::Stale
            );
            assert_eq!(transport.operations().len(), 1);
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
        assert_eq!(transport.operations(), vec!["install_sa"]);
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
            assert_eq!(transport.operations().len(), 2);
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
        assert_eq!(transport.operations(), vec!["install_sa", "install_policy"]);
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
            )
            .unwrap();
        let issuing = store.handle_for_record(&issuing).unwrap();
        store
            .transition(
                &issuing,
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::Acquired,
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
        released: AtomicBool,
        lock: Mutex<()>,
        wake: Condvar,
    }

    impl BlockingState {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
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
            _operation_class: crate::linux::NetlinkOperationClass,
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            let call = self.state.calls.fetch_add(1, Ordering::AcqRel);
            if call == 0 {
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
            vec!["install_sa", "install_sa_dscp_readback"]
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
}
