//! Namespace-bound Linux XFRM actor.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::{
    AllocateSpiRequest, InstallPolicyRequest, InstallSaRequest, LinuxXfrmBackend, QuerySaRequest,
    RekeyPolicyRequest, RekeySaRequest, RelocateSaRequest, RemovePolicyRequest, RemoveSaRequest,
    SaRelocationIdentity, SaState, SpiAllocation, XfrmBackend, XfrmCapability, XfrmError,
    XfrmProbe,
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
        .spawn(move || run_actor(backend, receiver, startup_sender))
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
        while let Some(command) = receiver.recv().await {
            command.execute(&backend).await;
        }
    });
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
    Probe(oneshot::Sender<Result<XfrmProbe, XfrmError>>),
    SaRelocationCapability(oneshot::Sender<Result<XfrmCapability, XfrmError>>),
}

impl NamespaceCommand {
    async fn execute(self, backend: &LinuxXfrmBackend) {
        if let Err(error) = backend.verify_namespace_actor() {
            self.send_error(error);
            return;
        }

        match self {
            Self::AllocateSpi(request, reply) => {
                let _ = reply.send(backend.allocate_spi(request).await);
            }
            Self::InstallSa(request, reply) => {
                let _ = reply.send(backend.install_sa(request).await);
            }
            Self::QuerySa(request, reply) => {
                let _ = reply.send(backend.query_sa(request).await);
            }
            Self::QuerySaRelocationIdentity(request, reply) => {
                let _ = reply.send(backend.query_sa_relocation_identity(request).await);
            }
            Self::RekeySa(request, reply) => {
                let _ = reply.send(backend.rekey_sa(request).await);
            }
            Self::RelocateSa(request, reply) => {
                let _ = reply.send(backend.relocate_sa(request).await);
            }
            Self::RemoveSa(request, reply) => {
                let _ = reply.send(backend.remove_sa(request).await);
            }
            Self::InstallPolicy(request, reply) => {
                let _ = reply.send(backend.install_policy(request).await);
            }
            Self::RekeyPolicy(request, reply) => {
                let _ = reply.send(backend.rekey_policy(request).await);
            }
            Self::RemovePolicy(request, reply) => {
                let _ = reply.send(backend.remove_policy(request).await);
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
            Self::Probe(reply) => {
                let _ = reply.send(Err(error));
            }
            Self::SaRelocationCapability(reply) => {
                let _ = reply.send(Err(error));
            }
        }
    }
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
    use crate::linux::{LinuxXfrmBackendConfig, LinuxXfrmTransport, SensitiveBuffer};
    use crate::{
        Algorithm, AuthAlgorithm, DscpCodepoint, IpAddress, KeyMaterial, LifetimeConfig,
        PolicyParameters, SaParameters, SaRelocationDirection, SaRelocationEncap,
        SaRelocationSelector, XfrmAction, XfrmBackendKind, XfrmDirection, XfrmId, XfrmMode,
        XfrmRequestId, XfrmSelector, XfrmTemplate,
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
