//! Namespace-bound Linux XFRM actor.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::{
    counter_resume::{
        map_backend_error, CounterRecoveryActorRequest, CounterResumeActorRequest,
        EspCounterReceiptRegistry,
    },
    outbound_binding::{validate_outbound_request, OutboundSaPolicyExpectation},
    AppliedEspCounterReceipt, EspCounterProofRequirement, EspCounterResumeApplyRequest,
    EspCounterResumeBinding, EspCounterResumeError, EspCounterResumeRecoveryRequest,
    InstalledOutboundSaBinding, OutboundSaBindingError, OutboundSaBindingId,
};
use crate::{
    AllocateSpiRequest, InstallPolicyRequest, InstallSaRequest, LinuxXfrmBackend, QuerySaRequest,
    RekeyPolicyRequest, RekeySaRequest, RelocateSaRequest, RemovePolicyRequest, RemoveSaRequest,
    SaParameters, SaRelocationIdentity, SaState, SpiAllocation, XfrmBackend, XfrmCapability,
    XfrmCompositeInstallRequest, XfrmError, XfrmProbe,
};

/// Maximum number of admitted Linux XFRM operations waiting for the dedicated
/// network-namespace actor.
///
/// Admission is explicitly bounded so callers cannot turn kernel or netlink
/// backpressure into unbounded SDK memory growth.
pub const LINUX_XFRM_NAMESPACE_ACTOR_CAPACITY: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NetworkNamespaceBinding {
    device: u64,
    inode: u64,
}

impl NetworkNamespaceBinding {
    #[cfg(target_os = "linux")]
    pub(crate) fn capture() -> Result<Self, XfrmError> {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata("/proc/thread-self/ns/net")
            .map_err(|error| XfrmError::io("network_namespace_identity", error))?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
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
        Self { device, inode }
    }
}

impl fmt::Debug for NetworkNamespaceBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkNamespaceBinding")
            .finish_non_exhaustive()
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
    binding: NetworkNamespaceBinding,
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

fn bind_with_capacity(
    backend: LinuxXfrmBackend,
    capacity: usize,
) -> Result<NamespaceBoundLinuxXfrmBackend, XfrmError> {
    let binding = NetworkNamespaceBinding::capture()?;
    let backend = backend.for_namespace_actor(binding);
    let (sender, receiver) = mpsc::channel(capacity);
    let (startup_sender, startup_receiver) = std::sync::mpsc::sync_channel(1);

    let worker = std::thread::Builder::new()
        .name(String::from("opc-xfrm-netns"))
        .spawn(move || run_actor(backend, binding, receiver, startup_sender))
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
        inner: Arc::new(NamespaceBoundLinuxXfrmBackendInner { sender, binding }),
    })
}

fn run_actor(
    backend: LinuxXfrmBackend,
    binding: NetworkNamespaceBinding,
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
        let mut state = NamespaceActorState::new(binding);
        while let Some(command) = receiver.recv().await {
            command.execute(&backend, &mut state).await;
        }
    });
}

struct NamespaceActorState {
    binding: NetworkNamespaceBinding,
    counter_receipts: EspCounterReceiptRegistry,
}

impl NamespaceActorState {
    fn new(binding: NetworkNamespaceBinding) -> Self {
        Self {
            binding,
            counter_receipts: EspCounterReceiptRegistry::default(),
        }
    }

    fn invalidate_counter_receipts(&mut self) {
        self.counter_receipts.invalidate_all();
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
        self.inner.binding
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
        let binding =
            InstalledOutboundSaBinding::new(self.network_namespace_binding(), expectation);
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
        Ok(AppliedEspCounterReceipt::new(binding, self.clone()))
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

    /// Rebuild a receipt after an already-committed ownership grant survives
    /// process loss and the live outbound SA may have advanced.
    ///
    /// This method is read-only. It performs exact actor-local OUT-policy, SA,
    /// and transient-key readback and requires the observed sequence to be at
    /// or above the durable requested floor. The returned receipt is
    /// structurally capped to
    /// [`EspCounterProofRequirement::CommittedRecovery`]; it can never
    /// authorize a new fence or first steering publication.
    pub async fn recover_committed_outbound_esp_counter(
        &self,
        authority: &InstalledOutboundSaBinding,
        expected_id: OutboundSaBindingId,
        request: EspCounterResumeRecoveryRequest,
    ) -> Result<AppliedEspCounterReceipt, EspCounterResumeError> {
        let binding = request.binding();
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
        Ok(AppliedEspCounterReceipt::new(binding, self.clone()))
    }
}

enum NamespaceCommand {
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
    RekeySa(RekeySaRequest, oneshot::Sender<Result<(), XfrmError>>),
    RelocateSa(RelocateSaRequest, oneshot::Sender<Result<(), XfrmError>>),
    RemoveSa(RemoveSaRequest, oneshot::Sender<Result<(), XfrmError>>),
    InstallPolicy(InstallPolicyRequest, oneshot::Sender<Result<(), XfrmError>>),
    RekeyPolicy(RekeyPolicyRequest, oneshot::Sender<Result<(), XfrmError>>),
    RemovePolicy(RemovePolicyRequest, oneshot::Sender<Result<(), XfrmError>>),
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
            Self::AllocateSpi(request, reply) => {
                state.invalidate_counter_receipts();
                let _ = reply.send(backend.allocate_spi(request).await);
            }
            Self::InstallSa(request, reply) => {
                state.invalidate_counter_receipts();
                let _ = reply.send(backend.install_sa(request).await);
            }
            Self::QuerySa(request, reply) => {
                let _ = reply.send(backend.query_sa(request).await);
            }
            Self::QuerySaRelocationIdentity(request, reply) => {
                let _ = reply.send(backend.query_sa_relocation_identity(request).await);
            }
            Self::RekeySa(request, reply) => {
                state.invalidate_counter_receipts();
                let _ = reply.send(backend.rekey_sa(request).await);
            }
            Self::RelocateSa(request, reply) => {
                state.invalidate_counter_receipts();
                let _ = reply.send(backend.relocate_sa(request).await);
            }
            Self::RemoveSa(request, reply) => {
                state.invalidate_counter_receipts();
                let _ = reply.send(backend.remove_sa(request).await);
            }
            Self::InstallPolicy(request, reply) => {
                state.invalidate_counter_receipts();
                let _ = reply.send(backend.install_policy(request).await);
            }
            Self::RekeyPolicy(request, reply) => {
                state.invalidate_counter_receipts();
                let _ = reply.send(backend.rekey_policy(request).await);
            }
            Self::RemovePolicy(request, reply) => {
                state.invalidate_counter_receipts();
                let _ = reply.send(backend.remove_policy(request).await);
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
                let _ = reply.send(
                    state
                        .counter_receipts
                        .apply(backend, state.binding, *request)
                        .await,
                );
            }
            Self::RecoverCommittedOutboundEspCounter(request, reply) => {
                let _ = reply.send(
                    state
                        .counter_receipts
                        .recover_committed(backend, state.binding, *request)
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
            Self::AllocateSpi(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::InstallSa(_, reply)
            | Self::RekeySa(_, reply)
            | Self::RelocateSa(_, reply)
            | Self::RemoveSa(_, reply)
            | Self::InstallPolicy(_, reply)
            | Self::RekeyPolicy(_, reply)
            | Self::RemovePolicy(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::QuerySa(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::QuerySaRelocationIdentity(_, reply) => {
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
        XfrmInstallOwnership, XfrmMode, XfrmRequestId, XfrmSelector, XfrmStagedInstall,
        XfrmTemplate,
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
            backend.network_namespace_binding(),
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
            .remove_policy(RemovePolicyRequest::new(policy.selector, policy.direction))
            .await;
        let _ = backend.probe().await;
        let _ = backend.sa_relocation_capability().await;

        let records = transport.records();
        assert_eq!(records.len(), 12);
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
                "probe",
                "probe",
            ]
        );
    }

    fn backend_from_sender(
        sender: mpsc::Sender<NamespaceCommand>,
    ) -> NamespaceBoundLinuxXfrmBackend {
        NamespaceBoundLinuxXfrmBackend {
            inner: Arc::new(NamespaceBoundLinuxXfrmBackendInner {
                sender,
                binding: NetworkNamespaceBinding::capture().unwrap(),
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
        responses: Arc<Mutex<VecDeque<BindingResponse>>>,
        operations: Arc<Mutex<Vec<&'static str>>>,
    }

    impl BlockingBindingTransport {
        fn new(
            state: Arc<BlockingState>,
            responses: impl IntoIterator<Item = BindingResponse>,
        ) -> Self {
            Self {
                state,
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
            _request: &[u8],
            _expected_sequence: u32,
            _config: LinuxXfrmBackendConfig,
        ) -> Result<Option<SensitiveBuffer>, XfrmError> {
            self.operations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(operation);
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

        let receipt = backend
            .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply.clone())
            .await
            .unwrap();
        EspCounterResumeProofSet::single(receipt)
            .validate_counter_proof(
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
    async fn cancelled_counter_observer_cannot_cancel_apply_or_cause_reuse_on_retry() {
        let request = outbound_install_request();
        let (pre_policy, pre_sa) = outbound_readback_at(&request, 7);
        let (applied_policy, applied_sa) = outbound_readback_at(&request, 99);
        let state = Arc::new(BlockingState::new());
        let transport = BlockingBindingTransport::new(
            Arc::clone(&state),
            [
                Ok(Some(pre_policy)),
                Ok(Some(pre_sa)),
                Ok(None),
                Ok(Some(applied_policy.clone())),
                Ok(Some(applied_sa.clone())),
                // Exact retry preflight/final readback.
                Ok(Some(applied_policy.clone())),
                Ok(Some(applied_sa.clone())),
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
        wait_until(|| state.calls.load(Ordering::Acquire) == 1).await;
        observer.abort();
        let _ = observer.await;
        state.release();
        wait_until(|| state.calls.load(Ordering::Acquire) == 5).await;

        backend
            .apply_and_read_back_outbound_esp_counter(&authority, authority.id(), apply)
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
            .validate_counter_proof(binding, EspCounterProofRequirement::CommittedRecovery)
            .await
            .unwrap();
        for requirement in [
            EspCounterProofRequirement::BeforeOwnershipCommit,
            EspCounterProofRequirement::BeforeFirstPublication,
        ] {
            let error = proofs
                .validate_counter_proof(binding, requirement)
                .await
                .unwrap_err();
            assert_eq!(error.code(), "esp_counter_recovered_receipt_cannot_fence");
        }
        for mismatched in [
            EspCounterResumeBinding::new(13, 12, authority.id(), 50).unwrap(),
            EspCounterResumeBinding::new(11, 13, authority.id(), 50).unwrap(),
        ] {
            let error = proofs
                .validate_counter_proof(mismatched, EspCounterProofRequirement::CommittedRecovery)
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
            NetworkNamespaceBinding {
                device: current.device.wrapping_add(1),
                inode: current.inode.wrapping_add(1),
            },
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
        wrong_recovery_sa.mark = Some(crate::XfrmMark {
            value: 1,
            mask: u32::MAX,
        });
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
                proof_binding,
                EspCounterProofRequirement::BeforeFirstPublication,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "esp_counter_receipt_absent_or_stale");
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

    #[derive(Debug, Clone, Copy)]
    struct SuccessfulTransport;

    impl LinuxXfrmTransport for SuccessfulTransport {
        fn transact(
            &self,
            _operation: &'static str,
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

    #[test]
    fn namespace_binding_and_backend_debug_are_redacted() {
        let binding = NetworkNamespaceBinding {
            device: 1_234_567_890,
            inode: 9_876_543_210,
        };
        let binding_debug = format!("{binding:?}");
        assert!(!binding_debug.contains("1234567890"));
        assert!(!binding_debug.contains("9876543210"));

        let (sender, _receiver) = mpsc::channel(1);
        let backend = NamespaceBoundLinuxXfrmBackend {
            inner: Arc::new(NamespaceBoundLinuxXfrmBackendInner { sender, binding }),
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
