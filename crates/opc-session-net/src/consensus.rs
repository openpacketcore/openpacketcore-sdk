//! Authenticated, least-authority transport for session consensus RPCs.
//!
//! This module deliberately does not expose [`opc_session_store::SessionBackend`]
//! or any raw replication-log/rebuild operation. A listener constructed here
//! owns only a [`SessionConsensusRpcHandler`], and its dedicated ALPN decodes
//! only the bounded consensus DTOs.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::BoxFuture;
use opc_consensus::{ConsensusRpcFamily, DURABLE_CONSENSUS_TIMING_PROFILE};
use opc_redaction::metrics::METRICS;
use opc_session_store::{
    ReplicaId, SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
};
use opc_types::SpiffeId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, MutexGuard, Notify, Semaphore, SemaphorePermit};

use crate::error::{classify_tls_io_error, ProtocolError};
use crate::identity::{LocalReplicaBinding, RemoteReplicaBinding};
use crate::lifecycle::{
    directed_connection_key, material_status_matches_admission, CertificateExpiryEvidence,
    ConnectionAttemptMetricGuard, ConnectionLifecycle, ConnectionLifecyclePolicy, ReconnectGate,
    RetirementReason, SessionReauthenticationControl,
};
use crate::protocol::{
    checked_frame_size, checked_wire_frame_size, negotiate_response_frame_size,
    read_authenticated_frame_within, read_frame, read_frame_within, write_frame_bounded_until,
    write_frame_bounded_until_cancellable, SessionConsensusBootstrapAck,
    SessionConsensusBootstrapHello, SessionConsensusBootstrapRequest,
    SessionConsensusBootstrapResponse, SessionConsensusTransportRequest,
    SessionConsensusTransportResponse, CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
    MAX_HANDSHAKE_FRAME_SIZE, MAX_NEGOTIATED_FRAME_SIZE, MIN_SESSION_CONSENSUS_FRAME_SIZE,
    SESSION_CONSENSUS_ALPN, SESSION_CONSENSUS_TRANSPORT_REVISION,
};

const DEFAULT_CONSENSUS_IDLE_TIMEOUT: Duration =
    DURABLE_CONSENSUS_TIMING_PROFILE.server_idle_timeout();
const DEFAULT_CONSENSUS_RPC_TIMEOUT: Duration =
    DURABLE_CONSENSUS_TIMING_PROFILE.server_handler_timeout();

#[derive(Clone, Copy, Debug)]
enum ConsensusDeadlinePolicy {
    Profiled,
    Fixed(Duration),
}

impl ConsensusDeadlinePolicy {
    const fn from_override(deadline: Option<Duration>) -> Self {
        match deadline {
            Some(deadline) => Self::Fixed(deadline),
            None => Self::Profiled,
        }
    }

    const fn for_family(self, family: ConsensusRpcFamily) -> Duration {
        match self {
            Self::Profiled => DURABLE_CONSENSUS_TIMING_PROFILE.rpc_timeout(family),
            Self::Fixed(deadline) => deadline,
        }
    }
}

/// Resolver callback used by [`RemoteSessionConsensusPeer::new_with_resolver`]
/// and, when explicitly enabled, the legacy remote-backend compatibility
/// client.
pub type RemoteAddrResolver =
    Arc<dyn Fn() -> BoxFuture<'static, io::Result<SocketAddr>> + Send + Sync>;

#[derive(Clone)]
enum ConsensusTarget {
    #[cfg(feature = "insecure-test")]
    Pinned(SocketAddr),
    Resolved {
        server_name: Option<Arc<str>>,
        resolve: RemoteAddrResolver,
    },
}

impl ConsensusTarget {
    fn configured(binding: &RemoteReplicaBinding) -> Self {
        let endpoint = binding.remote_endpoint();
        let server_name = endpoint.host().to_owned();
        let host = Arc::<str>::from(endpoint.host());
        let port = endpoint.port();
        let resolve: RemoteAddrResolver = Arc::new(move || {
            let host = host.clone();
            Box::pin(async move {
                let mut addresses = tokio::net::lookup_host((host.as_ref(), port)).await?;
                addresses.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "consensus endpoint did not resolve",
                    )
                })
            })
        });
        Self::Resolved {
            server_name: Some(Arc::from(server_name)),
            resolve,
        }
    }

    fn resolved(binding: &RemoteReplicaBinding, resolve: RemoteAddrResolver) -> Self {
        Self::Resolved {
            server_name: Some(Arc::from(binding.remote_endpoint().host())),
            resolve,
        }
    }

    #[cfg(feature = "insecure-test")]
    const fn pinned(addr: SocketAddr) -> Self {
        Self::Pinned(addr)
    }

    async fn resolve(&self) -> io::Result<SocketAddr> {
        match self {
            #[cfg(feature = "insecure-test")]
            Self::Pinned(addr) => Ok(*addr),
            Self::Resolved { resolve, .. } => resolve().await,
        }
    }

    fn tls_server_name(
        &self,
        resolved_addr: SocketAddr,
    ) -> Result<rustls_pki_types::ServerName<'static>, SessionConsensusPeerError> {
        match self {
            #[cfg(feature = "insecure-test")]
            Self::Pinned(_) => Ok(rustls_pki_types::ServerName::IpAddress(
                resolved_addr.ip().into(),
            )),
            Self::Resolved {
                server_name: Some(server_name),
                ..
            } => rustls_pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|_| SessionConsensusPeerError::Authentication),
            Self::Resolved {
                server_name: None, ..
            } => Ok(rustls_pki_types::ServerName::IpAddress(
                resolved_addr.ip().into(),
            )),
        }
    }
}

impl fmt::Debug for ConsensusTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConsensusTarget(<redacted>)")
    }
}

fn consensus_client_tls_config(config: Arc<opc_tls::ClientConfig>) -> Arc<opc_tls::ClientConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols = vec![SESSION_CONSENSUS_ALPN.to_vec()];
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

fn consensus_server_tls_config(config: Arc<opc_tls::ServerConfig>) -> Arc<opc_tls::ServerConfig> {
    let mut config = config.as_ref().clone();
    config.alpn_protocols = vec![SESSION_CONSENSUS_ALPN.to_vec()];
    config.session_storage = Arc::new(tokio_rustls::rustls::server::NoServerSessionStorage {});
    config.ticketer = Arc::new(DisabledSessionTickets);
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Arc::new(config)
}

#[derive(Debug)]
struct DisabledSessionTickets;

impl tokio_rustls::rustls::server::ProducesTickets for DisabledSessionTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

fn map_protocol_error(error: &ProtocolError) -> SessionConsensusPeerError {
    match error {
        ProtocolError::Io(error) if error.kind() == io::ErrorKind::TimedOut => {
            SessionConsensusPeerError::Timeout
        }
        ProtocolError::Io(_) | ProtocolError::BackendUnavailable(_) => {
            SessionConsensusPeerError::Unavailable
        }
        ProtocolError::Authentication => SessionConsensusPeerError::Authentication,
        ProtocolError::FrameTooLarge(_)
        | ProtocolError::VersionMismatch { .. }
        | ProtocolError::ContractMismatch
        | ProtocolError::InvalidWireValue
        | ProtocolError::UnexpectedResponse
        | ProtocolError::Serialization(_) => SessionConsensusPeerError::Protocol,
    }
}

fn record_consensus_server_connection_failure(error: &ProtocolError) {
    match error {
        ProtocolError::Io(error) if error.kind() == io::ErrorKind::TimedOut => {
            &METRICS.session_net_connection_failure_timeout
        }
        ProtocolError::Io(_) => &METRICS.session_net_connection_failure_transport,
        ProtocolError::Authentication => &METRICS.session_net_connection_failure_authentication,
        ProtocolError::BackendUnavailable(_) => &METRICS.session_net_connection_failure_backend,
        _ => &METRICS.session_net_connection_failure_protocol,
    }
    .fetch_add(1, Ordering::Relaxed);
}

fn record_consensus_server_connection_outcome(result: &Result<(), ProtocolError>) {
    match result {
        Ok(()) => {
            METRICS
                .session_net_connection_successes
                .fetch_add(1, Ordering::Relaxed);
        }
        Err(error) => record_consensus_server_connection_failure(error),
    }
}

fn map_tls_connect_error(error: io::Error) -> SessionConsensusPeerError {
    match classify_tls_io_error(error) {
        ProtocolError::Authentication => SessionConsensusPeerError::Authentication,
        ProtocolError::Io(_) => SessionConsensusPeerError::Unavailable,
        _ => SessionConsensusPeerError::Protocol,
    }
}

async fn wait_consensus_material_change(receiver: &mut Option<opc_tls::TlsMaterialStatusReceiver>) {
    loop {
        match receiver.as_mut() {
            Some(status) => {
                if status.changed().await.is_ok() {
                    return;
                }
                *receiver = None;
            }
            None => {
                std::future::pending::<()>().await;
            }
        }
    }
}

async fn wait_consensus_material_epoch_change(
    receiver: &mut Option<opc_tls::TlsMaterialStatusReceiver>,
    admitted_epoch: Option<opc_tls::TlsMaterialEpoch>,
) -> Option<opc_tls::TlsMaterialEpoch> {
    loop {
        let Some(status) = receiver.as_ref() else {
            std::future::pending::<()>().await;
            continue;
        };
        let current_epoch = Some(status.status().epoch());
        if current_epoch != admitted_epoch {
            return current_epoch;
        }
        wait_consensus_material_change(receiver).await;
    }
}

struct ConsensusConnection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    response_frame_size: usize,
    request_frame_size: usize,
    lifecycle: ConnectionLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsensusConnectionLane {
    Primary,
    Overflow,
}

struct ConsensusConnectionLaneState {
    connection: Mutex<Option<ConsensusConnection>>,
    changed: Arc<Notify>,
    reaper_started: AtomicBool,
    in_flight: Semaphore,
}

impl ConsensusConnectionLaneState {
    fn new() -> Self {
        Self {
            connection: Mutex::new(None),
            changed: Arc::new(Notify::new()),
            reaper_started: AtomicBool::new(false),
            in_flight: Semaphore::new(1),
        }
    }
}

struct ConsensusConnectionPool {
    primary: ConsensusConnectionLaneState,
    overflow: ConsensusConnectionLaneState,
    reconnect_gate: Arc<ReconnectGate>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl ConsensusConnectionPool {
    fn new(lifecycle_policy: ConnectionLifecyclePolicy) -> Self {
        let (shutdown, _) = tokio::sync::watch::channel(false);
        Self {
            primary: ConsensusConnectionLaneState::new(),
            overflow: ConsensusConnectionLaneState::new(),
            reconnect_gate: ReconnectGate::new(lifecycle_policy),
            shutdown,
        }
    }

    async fn acquire(&self) -> ConsensusConnectionSlot<'_> {
        if let Ok(permit) = self.primary.in_flight.try_acquire() {
            let connection = self.primary.connection.lock().await;
            return self.slot(ConsensusConnectionLane::Primary, connection, permit);
        }
        if let Ok(permit) = self.overflow.in_flight.try_acquire() {
            let connection = self.overflow.connection.lock().await;
            return self.slot(ConsensusConnectionLane::Overflow, connection, permit);
        }

        let (lane, permit) = tokio::select! {
            biased;
            permit = self.primary.in_flight.acquire() => {
                (
                    ConsensusConnectionLane::Primary,
                    permit.expect("fixed primary lane remains open"),
                )
            },
            permit = self.overflow.in_flight.acquire() => {
                (
                    ConsensusConnectionLane::Overflow,
                    permit.expect("fixed overflow lane remains open"),
                )
            },
        };
        let connection = self.lane(lane).connection.lock().await;
        self.slot(lane, connection, permit)
    }

    fn slot<'a>(
        &'a self,
        lane: ConsensusConnectionLane,
        connection: MutexGuard<'a, Option<ConsensusConnection>>,
        permit: SemaphorePermit<'a>,
    ) -> ConsensusConnectionSlot<'a> {
        ConsensusConnectionSlot {
            lane,
            connection,
            _permit: permit,
        }
    }

    fn lane(&self, lane: ConsensusConnectionLane) -> &ConsensusConnectionLaneState {
        match lane {
            ConsensusConnectionLane::Primary => &self.primary,
            ConsensusConnectionLane::Overflow => &self.overflow,
        }
    }

    fn ensure_cached_connection_reaper(
        self: &Arc<Self>,
        lane: ConsensusConnectionLane,
        tls_config: Option<opc_tls::AuthenticatedClientConfig>,
        reauthentication: SessionReauthenticationControl,
        edge_key: [u8; 32],
    ) {
        let lane_state = self.lane(lane);
        if lane_state
            .reaper_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        tokio::spawn(reap_cached_consensus_connection(
            Arc::downgrade(self),
            lane,
            Arc::clone(&lane_state.changed),
            self.shutdown.subscribe(),
            tls_config,
            reauthentication,
            edge_key,
            Arc::clone(&self.reconnect_gate),
        ));
    }
}

impl Drop for ConsensusConnectionPool {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

struct ConsensusConnectionSlot<'a> {
    lane: ConsensusConnectionLane,
    connection: MutexGuard<'a, Option<ConsensusConnection>>,
    _permit: SemaphorePermit<'a>,
}

impl ConsensusConnectionSlot<'_> {
    fn connection(&mut self) -> &mut Option<ConsensusConnection> {
        &mut self.connection
    }
}

#[allow(clippy::too_many_arguments)]
async fn reap_cached_consensus_connection(
    pool: std::sync::Weak<ConsensusConnectionPool>,
    lane: ConsensusConnectionLane,
    changed: Arc<Notify>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    reauthentication: SessionReauthenticationControl,
    edge_key: [u8; 32],
    reconnect_gate: Arc<ReconnectGate>,
) {
    let mut reauthentication_rx = reauthentication.subscribe();
    let mut material_rx = tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
    loop {
        if *shutdown.borrow() {
            return;
        }
        reconnect_gate.observe_epoch(
            reauthentication.generation(),
            tls_config
                .as_ref()
                .map(|config| config.material_status().epoch()),
        );
        // Register before inspecting the lane so an insertion between the
        // inspection and the select cannot lose its wake-up.
        let lane_changed = changed.notified();
        tokio::pin!(lane_changed);
        let retire_at = {
            let Some(pool) = pool.upgrade() else {
                return;
            };
            let lane_state = pool.lane(lane);
            let mut cached = lane_state.connection.lock().await;
            if let Some(connection) = cached.as_mut() {
                let now = tokio::time::Instant::now();
                connection.lifecycle.observe_rotation(
                    now,
                    reauthentication.generation(),
                    tls_config
                        .as_ref()
                        .map(|config| config.material_status().epoch()),
                    &edge_key,
                );
                if connection.lifecycle.retirement(now).is_some() {
                    let retired = cached.take();
                    drop(cached);
                    drop(retired);
                    continue;
                }
                Some(connection.lifecycle.retire_at())
            } else {
                None
            }
        };

        match retire_at {
            Some(retire_at) => {
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                    _ = &mut lane_changed => {}
                    _ = reauthentication_rx.changed() => {}
                    _ = wait_consensus_material_change(&mut material_rx) => {}
                    _ = tokio::time::sleep_until(retire_at) => {}
                }
            }
            None => {
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                    }
                    _ = &mut lane_changed => {}
                    _ = reauthentication_rx.changed() => {}
                    _ = wait_consensus_material_change(&mut material_rx) => {}
                }
            }
        }
    }
}

/// Authenticated outbound peer implementing only the session consensus port.
#[derive(Clone)]
pub struct RemoteSessionConsensusPeer {
    target: ConsensusTarget,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    binding: RemoteReplicaBinding,
    deadline_policy: ConsensusDeadlinePolicy,
    max_frame_size: usize,
    connection_pool: Arc<ConsensusConnectionPool>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
}

impl fmt::Debug for RemoteSessionConsensusPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSessionConsensusPeer")
            .field("target", &self.target)
            .field("authenticated", &self.tls_config.is_some())
            .field("deadline_policy", &self.deadline_policy)
            .field("max_frame_size", &self.max_frame_size)
            .finish_non_exhaustive()
    }
}

impl RemoteSessionConsensusPeer {
    /// Construct a mutually authenticated consensus-only peer.
    ///
    /// `None` selects the fixed family-specific durable timing profile.
    /// `Some` retains the source-compatible uniform complete-call override for
    /// tests and controlled compatibility only; it cannot enlarge the shared
    /// cold-connection sub-bound and is not the production profile.
    pub fn new(
        binding: RemoteReplicaBinding,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let target = ConsensusTarget::configured(&binding);
        Self::from_transport(target, Some(tls_config), binding, deadline)
    }

    /// Construct a production-profiled mutually authenticated peer.
    pub fn new_profiled(
        binding: RemoteReplicaBinding,
        tls_config: opc_tls::AuthenticatedClientConfig,
    ) -> Self {
        Self::new(binding, tls_config, None)
    }

    /// Construct a mutually authenticated peer with a reconnect-time resolver.
    ///
    /// `None` selects the fixed family-specific durable timing profile.
    /// `Some` is a non-qualifying uniform complete-call test/compatibility
    /// override and cannot enlarge the shared cold-connection sub-bound.
    pub fn new_with_resolver(
        binding: RemoteReplicaBinding,
        resolve: RemoteAddrResolver,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let target = ConsensusTarget::resolved(&binding, resolve);
        Self::from_transport(target, Some(tls_config), binding, deadline)
    }

    /// Construct a production-profiled peer with reconnect-time resolution.
    pub fn new_profiled_with_resolver(
        binding: RemoteReplicaBinding,
        resolve: RemoteAddrResolver,
        tls_config: opc_tls::AuthenticatedClientConfig,
    ) -> Self {
        Self::new_with_resolver(binding, resolve, tls_config, None)
    }

    /// Construct a plaintext consensus peer for transport tests.
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(
        binding: RemoteReplicaBinding,
        addr: SocketAddr,
        deadline: Option<Duration>,
    ) -> Self {
        Self::from_transport(ConsensusTarget::pinned(addr), None, binding, deadline)
    }

    fn from_transport(
        target: ConsensusTarget,
        tls_config: Option<opc_tls::AuthenticatedClientConfig>,
        binding: RemoteReplicaBinding,
        deadline: Option<Duration>,
    ) -> Self {
        let lifecycle_policy = ConnectionLifecyclePolicy::default();
        Self {
            target,
            tls_config,
            binding,
            deadline_policy: ConsensusDeadlinePolicy::from_override(deadline),
            // The bounded inner consensus payload needs the maximum profile
            // frame in its worst-case JSON byte-array expansion.
            max_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            connection_pool: Arc::new(ConsensusConnectionPool::new(lifecycle_policy)),
            lifecycle_policy,
            reauthentication: SessionReauthenticationControl::new(),
        }
    }

    /// Set the negotiated encoded request/response frame budget.
    #[must_use]
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size;
        // A clone-local wire budget cannot reuse a connection negotiated by a
        // differently configured clone.
        self.connection_pool = Arc::new(ConsensusConnectionPool::new(self.lifecycle_policy));
        self
    }

    /// Set the finite authentication and drain policy for consensus calls.
    #[must_use]
    pub fn with_connection_lifecycle(mut self, policy: ConnectionLifecyclePolicy) -> Self {
        self.lifecycle_policy = policy;
        self.connection_pool = Arc::new(ConsensusConnectionPool::new(policy));
        self
    }

    /// Share the graceful reauthentication trigger used by this peer.
    #[must_use]
    pub fn with_reauthentication_control(
        mut self,
        control: SessionReauthenticationControl,
    ) -> Self {
        self.reauthentication = control;
        self.connection_pool = Arc::new(ConsensusConnectionPool::new(self.lifecycle_policy));
        self
    }

    /// Control used by this peer for explicit graceful reauthentication.
    pub fn reauthentication_control(&self) -> SessionReauthenticationControl {
        self.reauthentication.clone()
    }

    async fn call_once(
        &self,
        connection_slot: &mut Option<ConsensusConnection>,
        request: SessionConsensusWireRequest,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        checked_wire_frame_size(self.max_frame_size)
            .map_err(|_| SessionConsensusPeerError::Protocol)?;
        if self.max_frame_size < MIN_SESSION_CONSENSUS_FRAME_SIZE {
            return Err(SessionConsensusPeerError::Protocol);
        }
        request.validate()?;
        if request.identity != self.binding.consensus_identity()
            || request.sender != self.binding.local_consensus_node_id()
        {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }

        // The selected connection lane is owned by this call until a complete response
        // has passed every correlation and payload validation check. If this
        // future is cancelled after any request bytes may have been written,
        // the taken socket is dropped rather than exposing a late response to
        // the next Openraft RPC.
        if let Some(mut connection) = connection_slot.take() {
            if self.connection_is_current(&mut connection, tokio::time::Instant::now()) {
                let result = self
                    .call_negotiated(&mut connection, request, deadline)
                    .await;
                if result
                    .as_ref()
                    .is_ok_and(consensus_response_allows_connection_reuse)
                    && self.connection_is_current(&mut connection, tokio::time::Instant::now())
                {
                    *connection_slot = Some(connection);
                }
                return result;
            }
            METRICS
                .session_net_reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
        }

        let connect_deadline = tokio::time::Instant::now()
            .checked_add(DURABLE_CONSENSUS_TIMING_PROFILE.cold_connect_timeout())
            .ok_or(SessionConsensusPeerError::Protocol)?
            .min(deadline);
        let mut reconnect_reauthentication_rx = self.reauthentication.subscribe();
        let _ = self
            .tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::material_status);
        let mut reconnect_material_rx = self
            .tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
        let mut backoff = self.lifecycle_policy.reconnect_backoff_min();
        let mut connection = loop {
            if tokio::time::Instant::now() >= connect_deadline {
                return Err(SessionConsensusPeerError::Timeout);
            }
            let mut reconnect_generation = self.reauthentication.generation();
            let mut reconnect_material_epoch = self
                .tls_config
                .as_ref()
                .map(|config| config.material_status().epoch());
            let reconnect_attempt = loop {
                let acquire = self.connection_pool.reconnect_gate.acquire(
                    connect_deadline,
                    reconnect_generation,
                    reconnect_material_epoch,
                );
                tokio::pin!(acquire);
                tokio::select! {
                    biased;
                    changed = reconnect_reauthentication_rx.changed() => {
                        if changed.is_err() {
                            return Err(SessionConsensusPeerError::Timeout);
                        }
                        reconnect_generation = self.reauthentication.generation();
                        self.connection_pool.reconnect_gate.observe_epoch(
                            reconnect_generation,
                            reconnect_material_epoch,
                        );
                    },
                    current_material_epoch = wait_consensus_material_epoch_change(
                        &mut reconnect_material_rx,
                        reconnect_material_epoch,
                    ) => {
                        reconnect_material_epoch = current_material_epoch;
                        self.connection_pool.reconnect_gate.observe_epoch(
                            reconnect_generation,
                            reconnect_material_epoch,
                        );
                    },
                    attempt = &mut acquire => {
                        break attempt.ok_or(SessionConsensusPeerError::Timeout)?;
                    },
                }
            };
            let mut reconnect_attempt = Some(reconnect_attempt);
            let mut attempt_metrics = ConnectionAttemptMetricGuard::started();
            let connect = tokio::time::timeout_at(connect_deadline, async {
                let admitted_generation = self.reauthentication.generation();
                let connection = if let Some(tls_config) = &self.tls_config {
                    let outcome = tls_config
                        .run_handshake(|attempt| {
                            let target = self.target.clone();
                            let binding = self.binding.clone();
                            async move {
                                let addr = target
                                    .resolve()
                                    .await
                                    .map_err(|_| SessionConsensusPeerError::Unavailable)?;
                                let tcp = TcpStream::connect(addr)
                                    .await
                                    .map_err(|_| SessionConsensusPeerError::Unavailable)?;
                                let connector = tokio_rustls::TlsConnector::from(
                                    consensus_client_tls_config(attempt.rustls_config()),
                                );
                                let server_name = target.tls_server_name(addr)?;
                                let tls_stream = connector
                                    .connect(server_name, tcp)
                                    .await
                                    .map_err(map_tls_connect_error)?;
                                if tls_stream.get_ref().1.alpn_protocol()
                                    != Some(SESSION_CONSENSUS_ALPN)
                                {
                                    return Err(SessionConsensusPeerError::Protocol);
                                }
                                let peer = opc_tls::peer_tls_identity_from_client_connection(
                                    tls_stream.get_ref().1,
                                )
                                .map_err(|_| SessionConsensusPeerError::Authentication)?;
                                if peer.spiffe_id().as_str() != binding.remote_spiffe_id().as_str()
                                {
                                    return Err(SessionConsensusPeerError::Authentication);
                                }
                                let tls_completed_at = tokio::time::Instant::now();
                                let local_expiry = CertificateExpiryEvidence::capture(
                                    attempt.leaf_expires_at(),
                                    attempt.certificate_chain_expires_at(),
                                    tls_completed_at,
                                );
                                let peer_expiry = CertificateExpiryEvidence::capture(
                                    peer.leaf_expires_at(),
                                    peer.certificate_chain_expires_at(),
                                    tls_completed_at,
                                );
                                let (mut reader, mut writer) = tokio::io::split(tls_stream);
                                let (response_frame_size, request_frame_size) = self
                                    .bootstrap(&mut reader, &mut writer, connect_deadline)
                                    .await?;
                                Ok::<_, SessionConsensusPeerError>((
                                    Box::new(reader) as Box<dyn AsyncRead + Unpin + Send>,
                                    Box::new(writer) as Box<dyn AsyncWrite + Unpin + Send>,
                                    response_frame_size,
                                    request_frame_size,
                                    tls_completed_at,
                                    local_expiry,
                                    peer_expiry,
                                ))
                            }
                        })
                        .await
                        .map_err(|error| match error {
                            opc_tls::TlsHandshakeRunError::Material(_) => {
                                SessionConsensusPeerError::Authentication
                            }
                            opc_tls::TlsHandshakeRunError::Operation(error) => error,
                        })?;
                    let admission = outcome.admission();
                    let (parts, _) = outcome.into_parts();
                    let (
                        reader,
                        writer,
                        response_frame_size,
                        request_frame_size,
                        tls_completed_at,
                        local_expiry,
                        peer_expiry,
                    ) = parts;
                    ConsensusConnection {
                        reader,
                        writer,
                        response_frame_size,
                        request_frame_size,
                        lifecycle: ConnectionLifecycle::new(
                            self.lifecycle_policy,
                            tls_completed_at,
                            Some(local_expiry),
                            Some(peer_expiry),
                            admitted_generation,
                            Some(admission.epoch()),
                        )
                        .map_err(|_| SessionConsensusPeerError::Protocol)?,
                    }
                } else {
                    let addr = self
                        .target
                        .resolve()
                        .await
                        .map_err(|_| SessionConsensusPeerError::Unavailable)?;
                    let tcp = TcpStream::connect(addr)
                        .await
                        .map_err(|_| SessionConsensusPeerError::Unavailable)?;
                    let (mut reader, mut writer) = tokio::io::split(tcp);
                    let established_at = tokio::time::Instant::now();
                    let (response_frame_size, request_frame_size) = self
                        .bootstrap(&mut reader, &mut writer, connect_deadline)
                        .await?;
                    ConsensusConnection {
                        reader: Box::new(reader),
                        writer: Box::new(writer),
                        response_frame_size,
                        request_frame_size,
                        lifecycle: ConnectionLifecycle::new(
                            self.lifecycle_policy,
                            established_at,
                            None,
                            None,
                            admitted_generation,
                            None,
                        )
                        .map_err(|_| SessionConsensusPeerError::Protocol)?,
                    }
                };
                Ok::<_, SessionConsensusPeerError>(connection)
            });
            tokio::pin!(connect);
            let mut connection_superseded = false;
            let connection_result = tokio::select! {
                biased;
                () = reconnect_attempt
                    .as_ref()
                    .expect("reconnect admission remains owned")
                    .superseded() => {
                        connection_superseded = true;
                        Err(SessionConsensusPeerError::Timeout)
                    },
                changed = reconnect_reauthentication_rx.changed() => {
                    if changed.is_ok() {
                        self.connection_pool.reconnect_gate.observe_epoch(
                            self.reauthentication.generation(),
                            self.tls_config
                                .as_ref()
                                .map(|config| config.material_status().epoch()),
                        );
                    }
                    connection_superseded = true;
                    Err(SessionConsensusPeerError::Timeout)
                },
                current_material_epoch = wait_consensus_material_epoch_change(
                    &mut reconnect_material_rx,
                    reconnect_material_epoch,
                ) => {
                    self.connection_pool.reconnect_gate.observe_epoch(
                        self.reauthentication.generation(),
                        current_material_epoch,
                    );
                    connection_superseded = true;
                    Err(SessionConsensusPeerError::Timeout)
                },
                result = &mut connect => {
                    result.unwrap_or(Err(SessionConsensusPeerError::Timeout))
                }
            };
            let mut connection = match connection_result {
                Ok(connection) => {
                    METRICS
                        .session_net_connection_successes
                        .fetch_add(1, Ordering::Relaxed);
                    attempt_metrics.finish();
                    connection
                }
                // `Rejected` is reserved contextually for the authenticated
                // bootstrap-retirement control. The server's ordinary
                // bootstrap rejection helper refuses this value, while a
                // post-bootstrap backend rejection is handled only by
                // `call_negotiated`. Count the completed control exchange as
                // successful transport accounting, then retry before any
                // Openraft request bytes can have been sent.
                Err(SessionConsensusPeerError::Rejected) => {
                    reconnect_attempt
                        .take()
                        .expect("reconnect admission remains owned")
                        .failed();
                    METRICS
                        .session_net_connection_successes
                        .fetch_add(1, Ordering::Relaxed);
                    attempt_metrics.finish();
                    METRICS
                        .session_net_reconnect_attempts
                        .fetch_add(1, Ordering::Relaxed);
                    let now = tokio::time::Instant::now();
                    let retry_at = now
                        .checked_add(backoff)
                        .unwrap_or(connect_deadline)
                        .min(connect_deadline);
                    tokio::time::sleep_until(retry_at).await;
                    backoff = self.lifecycle_policy.next_backoff(backoff);
                    continue;
                }
                Err(error) => {
                    reconnect_attempt
                        .take()
                        .expect("reconnect admission remains owned")
                        .failed();
                    if connection_superseded {
                        attempt_metrics.finish_superseded();
                    } else {
                        match error {
                            SessionConsensusPeerError::Unavailable => {
                                &METRICS.session_net_connection_failure_transport
                            }
                            SessionConsensusPeerError::Timeout => {
                                &METRICS.session_net_connection_failure_timeout
                            }
                            SessionConsensusPeerError::Authentication => {
                                &METRICS.session_net_connection_failure_authentication
                            }
                            SessionConsensusPeerError::Rejected => {
                                &METRICS.session_net_connection_failure_backend
                            }
                            _ => &METRICS.session_net_connection_failure_protocol,
                        }
                        .fetch_add(1, Ordering::Relaxed);
                        attempt_metrics.finish();
                    }
                    if !matches!(
                        error,
                        SessionConsensusPeerError::Unavailable | SessionConsensusPeerError::Timeout
                    ) {
                        return Err(error);
                    }
                    METRICS
                        .session_net_reconnect_attempts
                        .fetch_add(1, Ordering::Relaxed);
                    if connection_superseded {
                        continue;
                    }
                    METRICS
                        .session_net_reconnect_failures
                        .fetch_add(1, Ordering::Relaxed);
                    let now = tokio::time::Instant::now();
                    let retry_at = now
                        .checked_add(backoff)
                        .unwrap_or(connect_deadline)
                        .min(connect_deadline);
                    tokio::time::sleep_until(retry_at).await;
                    backoff = self.lifecycle_policy.next_backoff(backoff);
                    continue;
                }
            };
            let now = tokio::time::Instant::now();
            let current_generation = self.reauthentication.generation();
            let current_material_epoch = self
                .tls_config
                .as_ref()
                .map(|config| config.material_status().epoch());
            connection.lifecycle.observe_rotation(
                now,
                current_generation,
                current_material_epoch,
                &directed_connection_key(
                    b"consensus",
                    self.binding.local_replica_id().as_str(),
                    self.binding.remote_replica_id().as_str(),
                ),
            );
            let mismatch = connection
                .lifecycle
                .evidence_mismatch_reason(current_generation, current_material_epoch);
            if mismatch.is_none() && connection.lifecycle.retirement(now).is_none() {
                reconnect_attempt
                    .take()
                    .expect("reconnect admission remains owned")
                    .succeeded();
                break connection;
            }
            if let Some(reason) = mismatch {
                connection.lifecycle.record_forced_retirement(reason);
            }
            METRICS
                .session_net_reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
            reconnect_attempt
                .take()
                .expect("reconnect admission remains owned")
                .failed();
            let retry_at = now
                .checked_add(backoff)
                .unwrap_or(connect_deadline)
                .min(connect_deadline);
            tokio::time::sleep_until(retry_at).await;
            backoff = self.lifecycle_policy.next_backoff(backoff);
        };
        let result = self
            .call_negotiated(&mut connection, request, deadline)
            .await;
        if result
            .as_ref()
            .is_ok_and(consensus_response_allows_connection_reuse)
            && self.connection_is_current(&mut connection, tokio::time::Instant::now())
        {
            *connection_slot = Some(connection);
        }
        result
    }

    async fn call_with_timeout_inner(
        &self,
        request: SessionConsensusWireRequest,
        call_timeout: Duration,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(call_timeout)
            .ok_or(SessionConsensusPeerError::Protocol)?;
        // Waiting for one of the two fixed per-peer lanes must consume the
        // caller's logical budget, but it does not start a transport attempt.
        // Once a lane is owned, `call_once` is the only deadline authority for
        // the connection attempt and negotiated RPC. It classifies every
        // deadline expiry before returning, so an outer timeout cannot cancel
        // a live attempt guard and misreport it as abandoned.
        let mut slot = tokio::time::timeout_at(deadline, self.connection_pool.acquire())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        let result = self.call_once(slot.connection(), request, deadline).await;
        if slot.connection.is_some() {
            self.connection_pool.ensure_cached_connection_reaper(
                slot.lane,
                self.tls_config.clone(),
                self.reauthentication.clone(),
                directed_connection_key(
                    b"consensus",
                    self.binding.local_replica_id().as_str(),
                    self.binding.remote_replica_id().as_str(),
                ),
            );
        }
        self.connection_pool.lane(slot.lane).changed.notify_one();
        result
    }

    fn connection_is_current(
        &self,
        connection: &mut ConsensusConnection,
        now: tokio::time::Instant,
    ) -> bool {
        let current_generation = self.reauthentication.generation();
        let current_material_epoch = self
            .tls_config
            .as_ref()
            .map(|config| config.material_status().epoch());
        connection.lifecycle.observe_rotation(
            now,
            current_generation,
            current_material_epoch,
            &directed_connection_key(
                b"consensus",
                self.binding.local_replica_id().as_str(),
                self.binding.remote_replica_id().as_str(),
            ),
        );
        // This path checks an already authenticated cached lane. Rotation is
        // intentionally cooperative and remains usable until its stable
        // per-peer jitter deadline. Fresh handshakes take the strict mismatch
        // path in `call_once` and are never admitted with stale evidence.
        let usable = connection.lifecycle.retirement(now).is_none();
        if usable
            && connection
                .lifecycle
                .evidence_mismatch_reason(current_generation, current_material_epoch)
                .is_none()
        {
            self.connection_pool
                .reconnect_gate
                .mark_usable(current_generation, current_material_epoch);
        }
        usable
    }

    async fn bootstrap<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        deadline: tokio::time::Instant,
    ) -> Result<(usize, usize), SessionConsensusPeerError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let nonce = uuid::Uuid::new_v4();
        let requested_frame_size = checked_wire_frame_size(self.max_frame_size)
            .map_err(|_| SessionConsensusPeerError::Protocol)?;
        let hello = SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
            transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
            contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
            sender_replica_id: self.binding.local_replica_id().as_str().to_owned(),
            expected_server_replica_id: self.binding.remote_replica_id().as_str().to_owned(),
            identity: self.binding.consensus_identity(),
            sender_node_id: self.binding.local_consensus_node_id(),
            expected_server_node_id: self.binding.remote_consensus_node_id(),
            handshake_nonce: nonce,
            requested_response_frame_size: requested_frame_size,
        });
        write_frame_bounded_until(writer, &hello, MAX_HANDSHAKE_FRAME_SIZE, deadline)
            .await
            .map_err(|error| map_protocol_error(&error))?;
        let ack: SessionConsensusBootstrapResponse = read_frame(reader, MAX_HANDSHAKE_FRAME_SIZE)
            .await
            .map_err(|error| map_protocol_error(&error))?;
        let ack = match ack {
            SessionConsensusBootstrapResponse::Accepted(ack) => ack,
            SessionConsensusBootstrapResponse::Rejected(error) => return Err(error),
        };
        if ack.transport_revision != SESSION_CONSENSUS_TRANSPORT_REVISION
            || !ack.contract_profile.is_current()
            || ack.identity != self.binding.consensus_identity()
            || ack.server_node_id != self.binding.remote_consensus_node_id()
            || ack.accepted_sender_node_id != self.binding.local_consensus_node_id()
            || ack.handshake_nonce != nonce
        {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        let response_frame_size = checked_frame_size(ack.accepted_response_frame_size)
            .map_err(|_| SessionConsensusPeerError::Protocol)?;
        let request_frame_size = checked_frame_size(ack.server_request_frame_size)
            .map_err(|_| SessionConsensusPeerError::Protocol)?;
        if response_frame_size < MIN_SESSION_CONSENSUS_FRAME_SIZE
            || request_frame_size < MIN_SESSION_CONSENSUS_FRAME_SIZE
            || response_frame_size > self.max_frame_size
            || request_frame_size > self.max_frame_size
        {
            return Err(SessionConsensusPeerError::Protocol);
        }

        Ok((response_frame_size, request_frame_size))
    }

    async fn call_negotiated(
        &self,
        connection: &mut ConsensusConnection,
        request: SessionConsensusWireRequest,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let call_id = uuid::Uuid::new_v4();
        let call = async {
            write_frame_bounded_until(
                &mut connection.writer,
                &SessionConsensusTransportRequest::Call { call_id, request },
                connection.request_frame_size,
                deadline,
            )
            .await
            .map_err(|error| map_protocol_error(&error))?;
            let response: SessionConsensusTransportResponse =
                read_frame(&mut connection.reader, connection.response_frame_size)
                    .await
                    .map_err(|error| map_protocol_error(&error))?;
            let SessionConsensusTransportResponse::Call {
                call_id: response_call_id,
                response,
            } = response;
            if response_call_id != call_id {
                return Err(SessionConsensusPeerError::Protocol);
            }
            response.validate()?;
            Ok(response)
        };
        tokio::pin!(call);
        let mut lifecycle = connection.lifecycle.clone();
        let mut reauthentication_rx = self.reauthentication.subscribe();
        let mut material_rx = self
            .tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
        let response = loop {
            let now = tokio::time::Instant::now();
            lifecycle.observe_rotation(
                now,
                self.reauthentication.generation(),
                self.tls_config
                    .as_ref()
                    .map(|config| config.material_status().epoch()),
                &directed_connection_key(
                    b"consensus",
                    self.binding.local_replica_id().as_str(),
                    self.binding.remote_replica_id().as_str(),
                ),
            );
            let lifecycle_hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| SessionConsensusPeerError::Protocol)?;
            let hard_deadline = lifecycle_hard_deadline.min(deadline);
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(hard_deadline) => {
                    let now = tokio::time::Instant::now();
                    if now >= lifecycle_hard_deadline {
                        let _ = lifecycle.retirement(now);
                        lifecycle.record_hard_overrun();
                    }
                    break Err(SessionConsensusPeerError::Timeout);
                }
                response = &mut call => break response,
                _ = reauthentication_rx.changed() => {}
                _ = wait_consensus_material_change(&mut material_rx) => {}
            }
        };
        connection.lifecycle = lifecycle;
        response
    }
}

fn consensus_response_allows_connection_reuse(response: &SessionConsensusWireResponse) -> bool {
    matches!(
        &response.result,
        Ok(_) | Err(SessionConsensusPeerError::Unavailable)
    )
}

#[async_trait]
impl SessionConsensusPeer for RemoteSessionConsensusPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.binding.remote_consensus_node_id()
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let call_timeout = self.deadline_policy.for_family(request.family);
        self.call_with_timeout_inner(request, call_timeout).await
    }

    async fn call_with_timeout(
        &self,
        request: SessionConsensusWireRequest,
        timeout: Duration,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let call_timeout = timeout.min(self.deadline_policy.for_family(request.family));
        self.call_with_timeout_inner(request, call_timeout).await
    }
}

/// Dedicated consensus-only listener.
pub struct SessionConsensusServer {
    handler: Arc<dyn SessionConsensusRpcHandler>,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    binding: LocalReplicaBinding,
    max_connections: usize,
    max_frame_size: usize,
    idle_timeout: Duration,
    rpc_timeout: Duration,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
}

impl fmt::Debug for SessionConsensusServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionConsensusServer")
            .field("authenticated", &self.tls_config.is_some())
            .field("max_connections", &self.max_connections)
            .field("max_frame_size", &self.max_frame_size)
            .field("idle_timeout", &self.idle_timeout)
            .field("rpc_timeout", &self.rpc_timeout)
            .finish_non_exhaustive()
    }
}

impl SessionConsensusServer {
    /// Construct a mutually authenticated consensus-only listener.
    pub fn new(
        handler: Arc<dyn SessionConsensusRpcHandler>,
        tls_config: opc_tls::AuthenticatedServerConfig,
        binding: LocalReplicaBinding,
    ) -> Self {
        Self::from_transport(handler, Some(tls_config), binding)
    }

    /// Construct a plaintext consensus-only listener for transport tests.
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(
        handler: Arc<dyn SessionConsensusRpcHandler>,
        binding: LocalReplicaBinding,
    ) -> Self {
        Self::from_transport(handler, None, binding)
    }

    fn from_transport(
        handler: Arc<dyn SessionConsensusRpcHandler>,
        tls_config: Option<opc_tls::AuthenticatedServerConfig>,
        binding: LocalReplicaBinding,
    ) -> Self {
        Self {
            handler,
            tls_config,
            binding,
            max_connections: 128,
            max_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            idle_timeout: DEFAULT_CONSENSUS_IDLE_TIMEOUT,
            rpc_timeout: DEFAULT_CONSENSUS_RPC_TIMEOUT,
            lifecycle_policy: ConnectionLifecyclePolicy::default(),
            reauthentication: SessionReauthenticationControl::new(),
        }
    }

    /// Set the per-frame and handshake idle timeout.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum duration of one inbound handler call.
    #[must_use]
    pub fn with_rpc_timeout(mut self, timeout: Duration) -> Self {
        self.rpc_timeout = timeout;
        self
    }

    /// Set the maximum number of concurrently accepted connections.
    #[must_use]
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Set the encoded request/response frame budget.
    #[must_use]
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }

    /// Set the finite authentication and drain policy for accepted peers.
    #[must_use]
    pub fn with_connection_lifecycle(mut self, policy: ConnectionLifecyclePolicy) -> Self {
        self.lifecycle_policy = policy;
        self
    }

    /// Share the graceful reauthentication trigger used by this listener.
    #[must_use]
    pub fn with_reauthentication_control(
        mut self,
        control: SessionReauthenticationControl,
    ) -> Self {
        self.reauthentication = control;
        self
    }

    /// Control used by this listener for explicit graceful reauthentication.
    pub fn reauthentication_control(&self) -> SessionReauthenticationControl {
        self.reauthentication.clone()
    }

    /// Bind the dedicated listener and start accepting consensus connections.
    pub async fn listen(
        self,
        bind_addr: SocketAddr,
    ) -> io::Result<(SessionConsensusServerHandle, SocketAddr)> {
        self.validate_listener_configuration()?;
        let listener = TcpListener::bind(bind_addr).await?;
        self.serve_listener(listener).await
    }

    /// Start accepting consensus connections from an already-bound listener.
    ///
    /// This preserves listener ownership across multi-process discovery and
    /// configuration, avoiding a release-and-rebind race in orchestrators.
    pub async fn listen_on(
        self,
        listener: TcpListener,
    ) -> io::Result<(SessionConsensusServerHandle, SocketAddr)> {
        self.validate_listener_configuration()?;
        self.serve_listener(listener).await
    }

    fn validate_listener_configuration(&self) -> io::Result<()> {
        if self.max_connections == 0 || self.max_connections > Semaphore::MAX_PERMITS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "consensus connection limit is outside the supported range",
            ));
        }
        if !(MIN_SESSION_CONSENSUS_FRAME_SIZE..=MAX_NEGOTIATED_FRAME_SIZE)
            .contains(&self.max_frame_size)
            || checked_wire_frame_size(self.max_frame_size).is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "consensus frame size is outside the supported range",
            ));
        }
        let now = tokio::time::Instant::now();
        if now.checked_add(self.idle_timeout).is_none()
            || now.checked_add(self.rpc_timeout).is_none()
            || self.lifecycle_policy.validate_at(now).is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "consensus timeout is not representable",
            ));
        }
        Ok(())
    }

    async fn serve_listener(
        self,
        listener: TcpListener,
    ) -> io::Result<(SessionConsensusServerHandle, SocketAddr)> {
        let bound_addr = listener.local_addr()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let connection_tasks = Arc::new(std::sync::Mutex::new(ConnectionTaskRegistry {
            stopping: false,
            handles: Vec::new(),
        }));
        let sem = Arc::new(Semaphore::new(self.max_connections));
        let handler = self.handler;
        let tls_config = self.tls_config;
        let binding = self.binding;
        let max_frame_size = self.max_frame_size;
        let idle_timeout = self.idle_timeout;
        let rpc_timeout = self.rpc_timeout;
        let lifecycle_policy = self.lifecycle_policy;
        let reauthentication = self.reauthentication;
        let accept_cancellation = cancellation.clone();
        let task_registry = connection_tasks.clone();

        let accept_handle = tokio::spawn(async move {
            loop {
                let permit = match sem.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                let accepted = listener.accept().await;
                let Ok((stream, _peer_addr)) = accepted else {
                    continue;
                };
                let mut registry = task_registry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                registry.handles.retain(|handle| !handle.is_finished());
                if registry.stopping {
                    break;
                }
                let handler = handler.clone();
                let tls_config = tls_config.clone();
                let binding = binding.clone();
                let cancellation = accept_cancellation.clone();
                let shutdown_rx = shutdown_rx.clone();
                let reauthentication = reauthentication.clone();
                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    let mut attempt_metrics = ConnectionAttemptMetricGuard::started();
                    let result = handle_consensus_connection(
                        stream,
                        tls_config,
                        binding,
                        handler,
                        max_frame_size,
                        idle_timeout,
                        rpc_timeout,
                        cancellation,
                        shutdown_rx,
                        lifecycle_policy,
                        reauthentication,
                    )
                    .await;
                    record_consensus_server_connection_outcome(&result);
                    attempt_metrics.finish();
                });
                registry.handles.push(handle);
            }
        });

        Ok((
            SessionConsensusServerHandle {
                accept_handle,
                connection_tasks,
                cancellation,
                shutdown_tx,
            },
            bound_addr,
        ))
    }
}

#[derive(Debug)]
struct ConnectionTaskRegistry {
    stopping: bool,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Lifecycle handle for a running [`SessionConsensusServer`].
#[derive(Debug)]
pub struct SessionConsensusServerHandle {
    accept_handle: tokio::task::JoinHandle<()>,
    connection_tasks: Arc<std::sync::Mutex<ConnectionTaskRegistry>>,
    cancellation: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl SessionConsensusServerHandle {
    /// Schedule immediate cancellation of the listener and all connections.
    pub fn abort(&self) {
        self.cancellation.store(true, Ordering::Release);
        self.shutdown_tx.send_replace(true);
        self.accept_handle.abort();
        let mut registry = self
            .connection_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.stopping = true;
        for handle in &registry.handles {
            handle.abort();
        }
    }

    /// Cancel and await the listener and every registered connection.
    pub async fn abort_and_wait(mut self) {
        self.abort();
        let _ = (&mut self.accept_handle).await;
        let handles = {
            let mut registry = self
                .connection_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut registry.handles)
        };
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = handle.await;
        }
    }
}

enum ConnectionPeerIdentity {
    Authenticated(SpiffeId),
    InsecureTest,
}

struct PendingConsensusLifecycle {
    handshake: Option<opc_tls::TlsServerHandshake>,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    local_certificate_expiry: Option<CertificateExpiryEvidence>,
    peer_certificate_expiry: Option<CertificateExpiryEvidence>,
    established_at: tokio::time::Instant,
    generation: u64,
    #[cfg(test)]
    expire_at_final_ack_boundary: bool,
}

enum PendingConsensusAdmissionError {
    Retired(RetirementReason),
    Protocol(ProtocolError),
}

impl PendingConsensusLifecycle {
    fn insecure(generation: u64) -> Self {
        Self {
            handshake: None,
            tls_config: None,
            local_certificate_expiry: None,
            peer_certificate_expiry: None,
            established_at: tokio::time::Instant::now(),
            generation,
            #[cfg(test)]
            expire_at_final_ack_boundary: false,
        }
    }

    fn admit(
        self,
        policy: ConnectionLifecyclePolicy,
        current_generation: u64,
    ) -> Result<
        (
            ConnectionLifecycle,
            Option<opc_tls::AuthenticatedServerConfig>,
        ),
        PendingConsensusAdmissionError,
    > {
        if current_generation != self.generation {
            return Err(PendingConsensusAdmissionError::Retired(
                RetirementReason::Explicit,
            ));
        }
        let epoch = match self.handshake {
            Some(handshake) => {
                let admission = handshake.admit().map_err(|_| {
                    PendingConsensusAdmissionError::Retired(RetirementReason::MaterialEpoch)
                })?;
                Some(admission.epoch())
            }
            None => None,
        };
        let lifecycle = ConnectionLifecycle::new(
            policy,
            self.established_at,
            self.local_certificate_expiry,
            self.peer_certificate_expiry,
            self.generation,
            epoch,
        )
        .map_err(|_| PendingConsensusAdmissionError::Protocol(ProtocolError::InvalidWireValue))?;
        Ok((lifecycle, self.tls_config))
    }

    fn provisional_lifecycle(
        &self,
        policy: ConnectionLifecyclePolicy,
    ) -> Result<ConnectionLifecycle, ProtocolError> {
        ConnectionLifecycle::new(
            policy,
            self.established_at,
            self.local_certificate_expiry,
            self.peer_certificate_expiry,
            self.generation,
            self.handshake
                .as_ref()
                .map(opc_tls::TlsServerHandshake::epoch),
        )
        .map_err(|_| ProtocolError::InvalidWireValue)
    }
}

struct ConsensusLifecycleTask(tokio::task::JoinHandle<()>);

impl Drop for ConsensusLifecycleTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn spawn_consensus_lifecycle(
    mut lifecycle: ConnectionLifecycle,
    edge_key: [u8; 32],
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    reauthentication: SessionReauthenticationControl,
    mut server_shutdown: tokio::sync::watch::Receiver<bool>,
    connection_cancellation: Arc<AtomicBool>,
) -> (
    ConsensusLifecycleTask,
    tokio::sync::watch::Receiver<bool>,
    tokio::sync::watch::Receiver<bool>,
) {
    let (retirement_tx, retirement_rx) = tokio::sync::watch::channel(false);
    let (hard_tx, hard_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut reauthentication_rx = reauthentication.subscribe();
        let mut material_rx = tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedServerConfig::subscribe_material_changes);
        loop {
            let now = tokio::time::Instant::now();
            lifecycle.observe_rotation(
                now,
                reauthentication.generation(),
                tls_config
                    .as_ref()
                    .map(|config| config.material_status().epoch()),
                &edge_key,
            );
            if lifecycle.retirement(now).is_some() {
                retirement_tx.send_replace(true);
                let hard_deadline = match lifecycle.hard_deadline() {
                    Ok(deadline) => deadline,
                    Err(_) => {
                        connection_cancellation.store(true, Ordering::Release);
                        return;
                    }
                };
                tokio::select! {
                    _ = server_shutdown.changed() => {}
                    _ = tokio::time::sleep_until(hard_deadline) => {
                        lifecycle.record_hard_overrun();
                    }
                }
                hard_tx.send_replace(true);
                connection_cancellation.store(true, Ordering::Release);
                return;
            }
            tokio::select! {
                biased;
                _ = server_shutdown.changed() => {
                    hard_tx.send_replace(true);
                    connection_cancellation.store(true, Ordering::Release);
                    return;
                }
                _ = reauthentication_rx.changed() => {}
                _ = wait_consensus_material_change(&mut material_rx) => {}
                _ = tokio::time::sleep_until(lifecycle.retire_at()) => {}
            }
        }
    });
    (ConsensusLifecycleTask(task), retirement_rx, hard_rx)
}

#[allow(clippy::too_many_arguments)]
async fn handle_consensus_connection(
    stream: TcpStream,
    tls_config: Option<opc_tls::AuthenticatedServerConfig>,
    binding: LocalReplicaBinding,
    handler: Arc<dyn SessionConsensusRpcHandler>,
    max_frame_size: usize,
    idle_timeout: Duration,
    rpc_timeout: Duration,
    cancellation: Arc<AtomicBool>,
    server_shutdown: tokio::sync::watch::Receiver<bool>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
) -> Result<(), ProtocolError> {
    if let Some(tls_config) = tls_config {
        let generation = reauthentication.generation();
        let handshake = tls_config
            .begin_handshake()
            .map_err(|_| ProtocolError::Authentication)?;
        let acceptor =
            tokio_rustls::TlsAcceptor::from(consensus_server_tls_config(handshake.rustls_config()));
        let tls_stream = tokio::time::timeout(idle_timeout, acceptor.accept(stream))
            .await
            .map_err(|_| {
                ProtocolError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "consensus TLS handshake timed out",
                ))
            })?
            .map_err(classify_tls_io_error)?;
        let established_at = tokio::time::Instant::now();
        if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_CONSENSUS_ALPN) {
            return Err(ProtocolError::UnexpectedResponse);
        }
        let peer = opc_tls::peer_tls_identity_from_server_connection(tls_stream.get_ref().1)
            .map_err(|_| ProtocolError::Authentication)?;
        let local_certificate_expiry = CertificateExpiryEvidence::capture(
            handshake.leaf_expires_at(),
            handshake.certificate_chain_expires_at(),
            established_at,
        );
        let peer_certificate_expiry = CertificateExpiryEvidence::capture(
            peer.leaf_expires_at(),
            peer.certificate_chain_expires_at(),
            established_at,
        );
        let (mut reader, mut writer) = tokio::io::split(tls_stream);
        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::Authenticated(peer.spiffe_id().clone()),
            PendingConsensusLifecycle {
                handshake: Some(handshake),
                tls_config: Some(tls_config),
                local_certificate_expiry: Some(local_certificate_expiry),
                peer_certificate_expiry: Some(peer_certificate_expiry),
                established_at,
                generation,
                #[cfg(test)]
                expire_at_final_ack_boundary: false,
            },
            binding,
            handler,
            max_frame_size,
            idle_timeout,
            rpc_timeout,
            &cancellation,
            server_shutdown,
            lifecycle_policy,
            reauthentication,
        )
        .await
    } else {
        let (mut reader, mut writer) = tokio::io::split(stream);
        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            PendingConsensusLifecycle::insecure(reauthentication.generation()),
            binding,
            handler,
            max_frame_size,
            idle_timeout,
            rpc_timeout,
            &cancellation,
            server_shutdown,
            lifecycle_policy,
            reauthentication,
        )
        .await
    }
}

async fn reject_consensus_bootstrap<W>(
    writer: &mut W,
    error: SessionConsensusPeerError,
    idle_timeout: Duration,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    // `Rejected` is the bootstrap-only retirement sentinel. Keeping it out of
    // this ordinary error path proves that a real authentication, scope,
    // contract, or protocol rejection cannot be masked as a retryable local
    // rotation race.
    if error == SessionConsensusPeerError::Rejected {
        return Err(ProtocolError::InvalidWireValue);
    }
    let deadline = tokio::time::Instant::now()
        .checked_add(idle_timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    write_frame_bounded_until_cancellable(
        writer,
        &SessionConsensusBootstrapResponse::Rejected(error),
        MAX_HANDSHAKE_FRAME_SIZE,
        deadline,
        cancellation,
    )
    .await
}

async fn retire_consensus_bootstrap<W>(
    writer: &mut W,
    idle_timeout: Duration,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    tracing::debug!(
        reason = "rotation_bootstrap_retired",
        "retiring authenticated consensus connection before request admission"
    );
    let deadline = tokio::time::Instant::now()
        .checked_add(idle_timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    write_frame_bounded_until_cancellable(
        writer,
        &SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected),
        MAX_HANDSHAKE_FRAME_SIZE,
        deadline,
        cancellation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_consensus<R, W>(
    reader: &mut R,
    writer: &mut W,
    peer_identity: ConnectionPeerIdentity,
    pending_lifecycle: PendingConsensusLifecycle,
    binding: LocalReplicaBinding,
    handler: Arc<dyn SessionConsensusRpcHandler>,
    max_frame_size: usize,
    idle_timeout: Duration,
    rpc_timeout: Duration,
    global_cancellation: &AtomicBool,
    server_shutdown: tokio::sync::watch::Receiver<bool>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    #[cfg(test)]
    let expire_at_final_ack_boundary = pending_lifecycle.expire_at_final_ack_boundary;
    let bootstrap_lifecycle = pending_lifecycle.provisional_lifecycle(lifecycle_policy)?;
    let bootstrap_cancellation =
        Arc::new(AtomicBool::new(global_cancellation.load(Ordering::Acquire)));
    let bootstrap_hard_deadline = bootstrap_lifecycle
        .hard_deadline()
        .map_err(|_| ProtocolError::InvalidWireValue)?;
    let mut bootstrap_task_shutdown = server_shutdown.clone();
    let task_cancellation = bootstrap_cancellation.clone();
    let bootstrap_hard_lifecycle = bootstrap_lifecycle.clone();
    let _bootstrap_hard_task = ConsensusLifecycleTask(tokio::spawn(async move {
        tokio::select! {
            _ = bootstrap_task_shutdown.changed() => {}
            _ = tokio::time::sleep_until(bootstrap_hard_deadline) => {
                let now = tokio::time::Instant::now();
                let _ = bootstrap_hard_lifecycle.retirement(now);
                bootstrap_hard_lifecycle.record_hard_overrun();
            }
        }
        task_cancellation.store(true, Ordering::Release);
    }));
    let server_cancellation = bootstrap_cancellation.as_ref();
    let mut bootstrap_shutdown = server_shutdown.clone();
    let mut bootstrap_reauthentication_rx = reauthentication.subscribe();
    let mut bootstrap_material_rx = pending_lifecycle
        .tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::subscribe_material_changes);
    let hello: SessionConsensusBootstrapRequest = {
        let hello_read = read_frame_within(reader, MAX_HANDSHAKE_FRAME_SIZE, idle_timeout);
        tokio::pin!(hello_read);
        loop {
            let now = tokio::time::Instant::now();
            let current_material_status = pending_lifecycle
                .tls_config
                .as_ref()
                .map(opc_tls::AuthenticatedServerConfig::material_status);
            let mismatch = bootstrap_lifecycle.evidence_mismatch_reason(
                reauthentication.generation(),
                current_material_status.map(|status| status.epoch()),
            );
            if let Some(reason) = mismatch {
                bootstrap_lifecycle.record_forced_retirement(reason);
                return retire_consensus_bootstrap(writer, idle_timeout, server_cancellation).await;
            }
            if !material_status_matches_admission(
                bootstrap_lifecycle.admitted_material_epoch(),
                current_material_status,
            ) {
                bootstrap_lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
                return retire_consensus_bootstrap(writer, idle_timeout, server_cancellation).await;
            }
            if bootstrap_lifecycle.retirement(now).is_some() {
                return retire_consensus_bootstrap(writer, idle_timeout, server_cancellation).await;
            }
            tokio::select! {
                biased;
                _ = bootstrap_shutdown.changed() => {
                    return Err(ProtocolError::Io(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "consensus server stopped during bootstrap",
                    )));
                }
                changed = bootstrap_reauthentication_rx.changed() => {
                    if changed.is_err() {
                        return Err(ProtocolError::Authentication);
                    }
                }
                _ = wait_consensus_material_change(&mut bootstrap_material_rx) => {}
                _ = tokio::time::sleep_until(bootstrap_lifecycle.retire_at()) => {}
                result = &mut hello_read => break result?,
            }
        }
    };
    let SessionConsensusBootstrapRequest::Hello(hello) = hello;
    if hello.transport_revision != SESSION_CONSENSUS_TRANSPORT_REVISION
        || !hello.contract_profile.is_current()
    {
        reject_consensus_bootstrap(
            writer,
            SessionConsensusPeerError::Protocol,
            idle_timeout,
            server_cancellation,
        )
        .await?;
        return Err(ProtocolError::ContractMismatch);
    }
    let requested_response_frame_size =
        match negotiate_response_frame_size(hello.requested_response_frame_size, max_frame_size) {
            Ok(size) => size,
            Err(error) => {
                reject_consensus_bootstrap(
                    writer,
                    SessionConsensusPeerError::Protocol,
                    idle_timeout,
                    server_cancellation,
                )
                .await?;
                return Err(error);
            }
        };
    let effective_response_frame_size = checked_frame_size(requested_response_frame_size)?;
    if effective_response_frame_size < MIN_SESSION_CONSENSUS_FRAME_SIZE {
        reject_consensus_bootstrap(
            writer,
            SessionConsensusPeerError::Protocol,
            idle_timeout,
            server_cancellation,
        )
        .await?;
        return Err(ProtocolError::ContractMismatch);
    }
    let server_request_frame_size = checked_wire_frame_size(max_frame_size)?;

    let sender_replica_id = match ReplicaId::new(hello.sender_replica_id) {
        Ok(replica_id) => replica_id,
        Err(_) => {
            reject_consensus_bootstrap(
                writer,
                SessionConsensusPeerError::Protocol,
                idle_timeout,
                server_cancellation,
            )
            .await?;
            return Err(ProtocolError::InvalidWireValue);
        }
    };
    let expected_server_replica_id = match ReplicaId::new(hello.expected_server_replica_id) {
        Ok(replica_id) => replica_id,
        Err(_) => {
            reject_consensus_bootstrap(
                writer,
                SessionConsensusPeerError::Protocol,
                idle_timeout,
                server_cancellation,
            )
            .await?;
            return Err(ProtocolError::InvalidWireValue);
        }
    };
    let configured_sender_spiffe = binding.member_spiffe_id(&sender_replica_id);
    let authenticated_sender = match (&peer_identity, configured_sender_spiffe) {
        (ConnectionPeerIdentity::Authenticated(actual), Some(expected)) => {
            actual.as_str() == expected.as_str()
        }
        (ConnectionPeerIdentity::InsecureTest, Some(_)) => true,
        _ => false,
    };
    let expected_sender_node_id = binding.consensus_node_id(&sender_replica_id);
    let scope_matches = expected_server_replica_id == *binding.local_replica_id()
        && hello.identity == binding.consensus_identity()
        && hello.expected_server_node_id == binding.local_consensus_node_id()
        && expected_sender_node_id == Some(hello.sender_node_id);
    if !authenticated_sender || !scope_matches {
        reject_consensus_bootstrap(
            writer,
            if authenticated_sender {
                SessionConsensusPeerError::ScopeMismatch
            } else {
                SessionConsensusPeerError::Authentication
            },
            idle_timeout,
            server_cancellation,
        )
        .await?;
        return Err(ProtocolError::Authentication);
    }

    let mut admission_reauthentication_rx = reauthentication.subscribe();
    let (mut lifecycle, lifecycle_tls_config) =
        match pending_lifecycle.admit(lifecycle_policy, reauthentication.generation()) {
            Ok(admitted) => admitted,
            // Authentication and scope already succeeded. Prove the local
            // epoch/generation retirement before any Openraft request can be
            // dispatched, allowing exactly this cold-connect attempt to be
            // retried safely.
            Err(PendingConsensusAdmissionError::Retired(reason)) => {
                bootstrap_lifecycle.record_forced_retirement(reason);
                return retire_consensus_bootstrap(writer, idle_timeout, server_cancellation).await;
            }
            Err(PendingConsensusAdmissionError::Protocol(error)) => return Err(error),
        };
    drop(bootstrap_lifecycle);
    let mut admission_material_rx = lifecycle_tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::subscribe_material_changes);
    let edge_key = directed_connection_key(
        b"consensus",
        sender_replica_id.as_str(),
        binding.local_replica_id().as_str(),
    );
    let now = tokio::time::Instant::now();
    let admitted_material_epoch = lifecycle.admitted_material_epoch();
    let current_material_status = lifecycle_tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::material_status);
    lifecycle.observe_rotation(
        now,
        reauthentication.generation(),
        current_material_status.map(|status| status.epoch()),
        &edge_key,
    );
    if let Some(reason) = lifecycle.evidence_mismatch_reason(
        reauthentication.generation(),
        current_material_status.map(|status| status.epoch()),
    ) {
        lifecycle.record_forced_retirement(reason);
        return retire_consensus_bootstrap(writer, idle_timeout, server_cancellation).await;
    }
    if admission_reauthentication_rx.has_changed().unwrap_or(true) {
        lifecycle.record_forced_retirement(RetirementReason::Explicit);
        return retire_consensus_bootstrap(writer, idle_timeout, server_cancellation).await;
    }
    if !material_status_matches_admission(admitted_material_epoch, current_material_status) {
        lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
        return retire_consensus_bootstrap(writer, idle_timeout, server_cancellation).await;
    }
    if lifecycle.retirement(now).is_some() {
        return retire_consensus_bootstrap(writer, idle_timeout, server_cancellation).await;
    }
    drop(_bootstrap_hard_task);
    let connection_cancellation = Arc::new(AtomicBool::new(false));
    let admitted_generation = lifecycle.admitted_generation();
    let mut admission_shutdown = server_shutdown.clone();
    let (_lifecycle_task, mut retirement_rx, mut hard_rx) = spawn_consensus_lifecycle(
        lifecycle.clone(),
        edge_key,
        lifecycle_tls_config.clone(),
        reauthentication.clone(),
        server_shutdown,
        connection_cancellation.clone(),
    );
    let write_deadline = tokio::time::Instant::now()
        .checked_add(idle_timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    let accepted = SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
        transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
        contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
        identity: binding.consensus_identity(),
        server_node_id: binding.local_consensus_node_id(),
        accepted_sender_node_id: hello.sender_node_id,
        handshake_nonce: hello.handshake_nonce,
        accepted_response_frame_size: requested_response_frame_size,
        server_request_frame_size,
    });
    // This is the final zero-Accepted-byte boundary. Once the write future is
    // polled it may have emitted a partial Accepted frame, so a subsequent
    // retirement must conservatively close instead of appending the reserved
    // bootstrap retirement response.
    let pre_ack_material_status = lifecycle_tls_config
        .as_ref()
        .map(opc_tls::AuthenticatedServerConfig::material_status);
    if let Some(reason) = lifecycle.evidence_mismatch_reason(
        reauthentication.generation(),
        pre_ack_material_status.map(|status| status.epoch()),
    ) {
        lifecycle.record_forced_retirement(reason);
        return retire_consensus_bootstrap(writer, idle_timeout, connection_cancellation.as_ref())
            .await;
    }
    if !material_status_matches_admission(admitted_material_epoch, pre_ack_material_status) {
        lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
        return retire_consensus_bootstrap(writer, idle_timeout, connection_cancellation.as_ref())
            .await;
    }
    if *retirement_rx.borrow() || *hard_rx.borrow() {
        return retire_consensus_bootstrap(writer, idle_timeout, connection_cancellation.as_ref())
            .await;
    }
    #[cfg(test)]
    if expire_at_final_ack_boundary {
        // Deterministically model the soft deadline crossing after the earlier
        // sample while the spawned lifecycle task has not been scheduled.
        lifecycle.expire_at_final_ack_boundary_for_test();
    }
    if lifecycle.retirement(tokio::time::Instant::now()).is_some() {
        return retire_consensus_bootstrap(writer, idle_timeout, connection_cancellation.as_ref())
            .await;
    }
    {
        let acknowledgement = write_frame_bounded_until_cancellable(
            writer,
            &accepted,
            MAX_HANDSHAKE_FRAME_SIZE,
            write_deadline,
            connection_cancellation.as_ref(),
        );
        tokio::pin!(acknowledgement);
        loop {
            tokio::select! {
                biased;
                _ = admission_shutdown.changed() => return Ok(()),
                changed = admission_reauthentication_rx.changed() => {
                    if changed.is_err() || reauthentication.generation() != admitted_generation {
                        lifecycle.record_forced_retirement(RetirementReason::Explicit);
                        return Ok(());
                    }
                }
                _ = wait_consensus_material_change(&mut admission_material_rx) => {
                    let status = lifecycle_tls_config
                        .as_ref()
                        .map(opc_tls::AuthenticatedServerConfig::material_status);
                    if !material_status_matches_admission(admitted_material_epoch, status) {
                        lifecycle.record_forced_retirement(RetirementReason::MaterialEpoch);
                        return Ok(());
                    }
                }
                _ = hard_rx.changed() => return Ok(()),
                _ = retirement_rx.changed() => return Ok(()),
                result = &mut acknowledgement => {
                    result?;
                    break;
                }
            }
        }
    }
    let connection_cancellation = connection_cancellation.as_ref();

    loop {
        if *retirement_rx.borrow() || *hard_rx.borrow() {
            return Ok(());
        }
        let inbound_result = tokio::select! {
            biased;
            _ = hard_rx.changed() => return Ok(()),
            _ = retirement_rx.changed() => return Ok(()),
            inbound = read_authenticated_frame_within(reader, max_frame_size, idle_timeout) => inbound,
        };
        let inbound: SessionConsensusTransportRequest = match inbound_result {
            Ok(Some(request)) => request,
            Ok(None) => {
                lifecycle.record_forced_retirement(RetirementReason::IdleTimeout);
                return Ok(());
            }
            Err(ProtocolError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let SessionConsensusTransportRequest::Call { call_id, request } = inbound;
        let response = if request.validate().is_err() {
            SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Protocol),
            }
        } else if request.identity != binding.consensus_identity()
            || request.sender != hello.sender_node_id
        {
            SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::ScopeMismatch),
            }
        } else {
            let handled = tokio::select! {
                biased;
                _ = hard_rx.changed() => None,
                handled = tokio::time::timeout(
                    rpc_timeout,
                    handler.handle(hello.sender_node_id, request),
                ) => Some(handled),
            };
            match handled {
                None => return Ok(()),
                Some(Ok(response)) if response.validate().is_ok() => response,
                Some(Ok(_)) => SessionConsensusWireResponse {
                    result: Err(SessionConsensusPeerError::Protocol),
                },
                Some(Err(_)) => SessionConsensusWireResponse {
                    result: Err(SessionConsensusPeerError::Timeout),
                },
            }
        };
        let deadline = tokio::time::Instant::now()
            .checked_add(idle_timeout)
            .ok_or(ProtocolError::InvalidWireValue)?;
        let outbound = SessionConsensusTransportResponse::Call { call_id, response };
        tokio::select! {
            biased;
            _ = hard_rx.changed() => return Ok(()),
            result = write_frame_bounded_until_cancellable(
                writer,
                &outbound,
                effective_response_frame_size,
                deadline,
                connection_cancellation,
            ) => result?,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex as StdMutex;
    use std::{pin::Pin, task::Context, task::Poll};

    use opc_session_store::{
        QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
        ReplicaTlsIdentity, SessionConsensusRpcFamily, SessionOp,
    };
    use tokio::io::{AsyncWrite, AsyncWriteExt};
    use tokio::sync::Notify;

    use super::*;
    use crate::identity::{
        SessionClusterId, SessionConfigurationEpoch, SessionConfigurationGeneration,
        SessionReplicationManifest,
    };
    use crate::protocol::{write_frame, Request};

    #[derive(Debug)]
    struct CountingHandler(AtomicUsize);

    #[async_trait]
    impl SessionConsensusRpcHandler for CountingHandler {
        async fn handle(
            &self,
            _authenticated_sender: SessionConsensusNodeId,
            request: SessionConsensusWireRequest,
        ) -> SessionConsensusWireResponse {
            self.0.fetch_add(1, Ordering::Relaxed);
            SessionConsensusWireResponse {
                result: Ok(request.payload),
            }
        }
    }

    struct PartialConsensusAcknowledgementWriter {
        bytes: Arc<StdMutex<Vec<u8>>>,
        first_chunk_written: bool,
        wrote_first_chunk: Arc<Notify>,
    }

    impl AsyncWrite for PartialConsensusAcknowledgementWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            if self.first_chunk_written {
                return Poll::Pending;
            }
            let written = buffer.len().min(2);
            self.bytes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(&buffer[..written]);
            self.first_chunk_written = true;
            self.wrote_first_chunk.notify_one();
            Poll::Ready(Ok(written))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn descriptor(index: u16) -> QuorumReplicaDescriptor {
        QuorumReplicaDescriptor::new(
            ReplicaId::new(format!("replica-{index}")).expect("replica ID"),
            ReplicaEndpoint::new(format!("replica-{index}.invalid"), 7443).expect("endpoint"),
            ReplicaTlsIdentity::new(format!(
                "spiffe://test.invalid/tenant/test/ns/default/sa/session/nf/smf/instance/{index}"
            ))
            .expect("TLS identity"),
            ReplicaFailureDomain::new(format!("zone-{index}")).expect("failure domain"),
            ReplicaBackingIdentity::new(format!("disk-{index}")).expect("backing identity"),
        )
    }

    fn bindings() -> (LocalReplicaBinding, RemoteReplicaBinding) {
        let manifest = Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("consensus-raw-rejection").expect("cluster"),
                SessionConfigurationGeneration::new("legacy").expect("legacy generation"),
                SessionConfigurationEpoch::new(1).expect("epoch"),
                vec![descriptor(1), descriptor(2)],
            )
            .expect("manifest"),
        );
        let client = manifest
            .bind_local(ReplicaId::new("replica-1").expect("client ID"))
            .expect("client binding")
            .bind_remote(ReplicaId::new("replica-2").expect("server ID"))
            .expect("remote binding");
        let server = manifest
            .bind_local(ReplicaId::new("replica-2").expect("server ID"))
            .expect("server binding");
        (server, client)
    }

    #[tokio::test(start_paused = true)]
    async fn cached_consensus_lane_honors_material_rotation_jitter_before_retirement() {
        let (_server_binding, client_binding) = bindings();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_millis(10),
            Duration::from_millis(80),
            Duration::from_secs(10),
        )
        .expect("lifecycle policy");
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/1",
        );
        let tls_config = material.config();
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::pinned("127.0.0.1:9".parse().expect("test address")),
            Some(tls_config.clone()),
            client_binding.clone(),
            Some(Duration::from_secs(1)),
        )
        .with_connection_lifecycle(policy);
        let now = tokio::time::Instant::now();
        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        let mut connection = ConsensusConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            lifecycle: ConnectionLifecycle::new(
                policy,
                now,
                None,
                None,
                0,
                Some(tls_config.material_status().epoch()),
            )
            .expect("connection lifecycle"),
        };
        let edge_key = directed_connection_key(
            b"consensus",
            client_binding.local_replica_id().as_str(),
            client_binding.remote_replica_id().as_str(),
        );
        let jitter = policy.deterministic_jitter(&edge_key);
        assert!(!jitter.is_zero(), "fixture must exercise a non-zero jitter");

        material.rotate();
        assert!(peer.connection_is_current(&mut connection, now));
        tokio::time::advance(jitter - Duration::from_nanos(1)).await;
        assert!(peer.connection_is_current(&mut connection, tokio::time::Instant::now()));
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(!peer.connection_is_current(&mut connection, tokio::time::Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn cached_consensus_lane_retires_immediately_for_explicit_reauthentication() {
        let (_server_binding, client_binding) = bindings();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_millis(10),
            Duration::from_millis(80),
            Duration::from_secs(30),
        )
        .expect("lifecycle policy");
        let control = SessionReauthenticationControl::new();
        let peer = RemoteSessionConsensusPeer::new_insecure(
            client_binding,
            "127.0.0.1:9".parse().expect("test address"),
            Some(Duration::from_secs(1)),
        )
        .with_connection_lifecycle(policy)
        .with_reauthentication_control(control.clone());
        let now = tokio::time::Instant::now();
        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        let mut connection = ConsensusConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            lifecycle: ConnectionLifecycle::new(policy, now, None, None, 0, None)
                .expect("connection lifecycle"),
        };

        control
            .request_reauthentication()
            .expect("rotate generation");
        assert!(!peer.connection_is_current(&mut connection, now));
    }

    #[tokio::test(start_paused = true)]
    async fn consensus_epoch_supersession_conserves_connection_attempt_accounting() {
        let (_server_binding, client_binding) = bindings();
        let control = SessionReauthenticationControl::new();
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolver: RemoteAddrResolver = {
            let attempts = Arc::clone(&attempts);
            Arc::new(move || {
                let entered_tx = entered_tx.clone();
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    entered_tx.send(attempt).expect("report resolver entry");
                    std::future::pending::<io::Result<SocketAddr>>().await
                })
            })
        };
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(1)),
        )
        .with_reauthentication_control(control.clone());
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"supersede-connect".to_vec(),
        )
        .expect("bounded request");
        let accounting = Arc::new(crate::lifecycle::ConnectionAttemptTestAccounting::default());
        let call = tokio::spawn(crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING.scope(
            Arc::clone(&accounting),
            async move { peer.call(request).await },
        ));

        assert_eq!(entered_rx.recv().await, Some(0));
        control.request_reauthentication().expect("advance epoch");
        assert_eq!(entered_rx.recv().await, Some(1));
        assert_eq!(accounting.snapshot(), (2, 1, 1, 0));

        call.abort();
        assert!(call
            .await
            .expect_err("call must be cancelled")
            .is_cancelled());
        assert_eq!(accounting.snapshot(), (2, 2, 1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn consensus_soft_timeout_classifies_pending_connect_without_abandoning() {
        let (_server_binding, client_binding) = bindings();
        let resolver: RemoteAddrResolver =
            Arc::new(|| Box::pin(std::future::pending::<io::Result<SocketAddr>>()));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(30)),
        );
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::AppendEntries,
            b"openraft-soft-timeout".to_vec(),
        )
        .expect("bounded request");
        let accounting = Arc::new(crate::lifecycle::ConnectionAttemptTestAccounting::default());

        let result = crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING
            .scope(Arc::clone(&accounting), async move {
                peer.call_with_timeout(request, Duration::from_millis(100))
                    .await
            })
            .await;

        assert_eq!(result, Err(SessionConsensusPeerError::Timeout));
        let (attempts, terminals, superseded, abandoned) = accounting.snapshot();
        assert!(attempts > 0, "the stalled resolver must start an attempt");
        assert_eq!(terminals, attempts);
        assert_eq!(superseded, 0);
        assert_eq!(abandoned, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn configured_ceiling_can_shorten_the_consensus_soft_timeout() {
        let (_server_binding, client_binding) = bindings();
        let resolver: RemoteAddrResolver =
            Arc::new(|| Box::pin(std::future::pending::<io::Result<SocketAddr>>()));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_millis(50)),
        );
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::AppendEntries,
            b"configured-soft-ceiling".to_vec(),
        )
        .expect("bounded request");
        let accounting = Arc::new(crate::lifecycle::ConnectionAttemptTestAccounting::default());
        let started_at = tokio::time::Instant::now();

        let result = crate::lifecycle::CONNECTION_ATTEMPT_TEST_ACCOUNTING
            .scope(Arc::clone(&accounting), async move {
                peer.call_with_timeout(request, Duration::from_millis(500))
                    .await
            })
            .await;

        assert_eq!(result, Err(SessionConsensusPeerError::Timeout));
        assert_eq!(
            tokio::time::Instant::now().duration_since(started_at),
            Duration::from_millis(50)
        );
        let (attempts, terminals, superseded, abandoned) = accounting.snapshot();
        assert!(attempts > 0, "the stalled resolver must start an attempt");
        assert_eq!(terminals, attempts);
        assert_eq!(superseded, 0);
        assert_eq!(abandoned, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn cold_consensus_epoch_change_wakes_reconnect_cooldown() {
        let (_server_binding, client_binding) = bindings();
        let control = SessionReauthenticationControl::new();
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let entered_tx = entered_tx.clone();
            Box::pin(async move {
                entered_tx.send(()).expect("report resolver entry");
                std::future::pending::<io::Result<SocketAddr>>().await
            })
        });
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(60),
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .expect("lifecycle policy");
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(5)),
        )
        .with_connection_lifecycle(policy)
        .with_reauthentication_control(control.clone());
        let started_at = tokio::time::Instant::now();
        peer.connection_pool
            .reconnect_gate
            .acquire(
                started_at + Duration::from_secs(2),
                control.generation(),
                None,
            )
            .await
            .expect("seed reconnect attempt")
            .failed();
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"cold-epoch-wake".to_vec(),
        )
        .expect("bounded request");
        let call = tokio::spawn(async move { peer.call(request).await });
        tokio::task::yield_now().await;
        assert!(
            entered_rx.try_recv().is_err(),
            "the old epoch cooldown must initially hold a cold consensus caller"
        );

        control.request_reauthentication().expect("advance epoch");
        assert_eq!(entered_rx.recv().await, Some(()));
        assert_eq!(
            tokio::time::Instant::now(),
            started_at,
            "the new epoch must bypass the old cooldown without advancing time"
        );

        call.abort();
        assert!(call
            .await
            .expect_err("call must be cancelled")
            .is_cancelled());
    }

    fn test_consensus_lifecycle_policy() -> ConnectionLifecyclePolicy {
        ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::from_millis(5),
            Duration::ZERO,
        )
        .expect("test consensus lifecycle policy")
    }

    async fn valid_consensus_hello_bytes(binding: &RemoteReplicaBinding) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
                transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                sender_replica_id: binding.local_replica_id().as_str().to_owned(),
                expected_server_replica_id: binding.remote_replica_id().as_str().to_owned(),
                identity: binding.consensus_identity(),
                sender_node_id: binding.local_consensus_node_id(),
                expected_server_node_id: binding.remote_consensus_node_id(),
                handshake_nonce: uuid::Uuid::nil(),
                requested_response_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
            }),
        )
        .await
        .expect("encode valid consensus Hello");
        bytes
    }

    #[derive(Clone, Copy)]
    struct ConnectionOutcomeMetricSnapshot {
        idle_retirements: u64,
        timeout_failures: u64,
        successes: u64,
        drain_started: u64,
        drain_completed: u64,
    }

    fn connection_outcome_metrics() -> ConnectionOutcomeMetricSnapshot {
        ConnectionOutcomeMetricSnapshot {
            idle_retirements: METRICS
                .session_net_lifecycle_retirement_idle_timeout
                .load(Ordering::Relaxed),
            timeout_failures: METRICS
                .session_net_connection_failure_timeout
                .load(Ordering::Relaxed),
            successes: METRICS
                .session_net_connection_successes
                .load(Ordering::Relaxed),
            drain_started: METRICS
                .session_net_lifecycle_drain_started
                .load(Ordering::Relaxed),
            drain_completed: METRICS
                .session_net_lifecycle_drain_completed
                .load(Ordering::Relaxed),
        }
    }

    async fn wait_for_drain_completion(minimum: u64) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while METRICS
                .session_net_lifecycle_drain_completed
                .load(Ordering::Relaxed)
                < minimum
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted consensus lifecycle task must release its draining metric");
    }

    async fn dispatch_after_authentication(
        trailing_frame_bytes: &[u8],
    ) -> (Result<(), ProtocolError>, Vec<u8>) {
        let (server_binding, client_binding) = bindings();
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        let mut input = valid_consensus_hello_bytes(&client_binding).await;
        input.extend_from_slice(trailing_frame_bytes);
        let (mut peer, mut reader) = tokio::io::duplex(input.len() + 16);
        peer.write_all(&input)
            .await
            .expect("write authenticated consensus test input");
        let mut writer = Vec::new();
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let result = dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            server_binding,
            Arc::new(CountingHandler(AtomicUsize::new(0))),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_millis(20),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication,
        )
        .await;
        drop(peer);
        (result, writer)
    }

    #[tokio::test]
    async fn consensus_server_distinguishes_authenticated_idle_from_active_frame_timeout() {
        let _guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;

        let before_idle = connection_outcome_metrics();
        let (idle_result, acknowledgement) = dispatch_after_authentication(&[]).await;
        record_consensus_server_connection_outcome(&idle_result);
        idle_result.expect("byte-idle authenticated consensus connection is a policy retirement");
        wait_for_drain_completion(before_idle.drain_completed + 1).await;
        let after_idle = connection_outcome_metrics();
        assert_eq!(
            after_idle.idle_retirements,
            before_idle.idle_retirements + 1
        );
        assert_eq!(after_idle.timeout_failures, before_idle.timeout_failures);
        assert!(after_idle.successes > before_idle.successes);
        assert!(after_idle.drain_started > before_idle.drain_started);
        assert!(after_idle.drain_completed > before_idle.drain_completed);
        let mut acknowledgement = std::io::Cursor::new(acknowledgement);
        assert!(matches!(
            read_frame::<_, SessionConsensusBootstrapResponse>(
                &mut acknowledgement,
                MAX_HANDSHAKE_FRAME_SIZE,
            )
            .await
            .expect("decode authenticated consensus acknowledgement"),
            SessionConsensusBootstrapResponse::Accepted(_)
        ));

        let before_partial = connection_outcome_metrics();
        let (partial_result, _acknowledgement) = dispatch_after_authentication(&[0]).await;
        assert!(matches!(
            partial_result,
            Err(ProtocolError::Io(ref error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        record_consensus_server_connection_outcome(&partial_result);
        let after_partial = connection_outcome_metrics();
        assert_eq!(
            after_partial.idle_retirements, before_partial.idle_retirements,
            "one active consensus frame byte must preserve the slowloris timeout failure"
        );
        assert!(after_partial.timeout_failures > before_partial.timeout_failures);

        let before_handshake = connection_outcome_metrics();
        let (server_binding, _client_binding) = bindings();
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        let (_peer, mut reader) = tokio::io::duplex(16);
        let mut writer = Vec::new();
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handshake_result = dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            server_binding,
            Arc::new(CountingHandler(AtomicUsize::new(0))),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_millis(20),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication,
        )
        .await;
        assert!(matches!(
            handshake_result,
            Err(ProtocolError::Io(ref error)) if error.kind() == io::ErrorKind::TimedOut
        ));
        record_consensus_server_connection_outcome(&handshake_result);
        let after_handshake = connection_outcome_metrics();
        assert_eq!(
            after_handshake.idle_retirements,
            before_handshake.idle_retirements
        );
        assert!(after_handshake.timeout_failures > before_handshake.timeout_failures);
    }

    #[tokio::test]
    async fn consensus_pre_hello_generation_retirement_emits_one_no_dispatch_control() {
        let (server_binding, _client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        reauthentication
            .request_reauthentication()
            .expect("advance consensus test generation");
        let mut reader = tokio::io::empty();
        let mut writer = Vec::new();
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            server_binding,
            handler.clone(),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_secs(1),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication,
        )
        .await
        .expect("pre-Hello consensus retirement is an expected control exchange");

        let mut encoded = std::io::Cursor::new(writer);
        assert!(matches!(
            read_frame::<_, SessionConsensusBootstrapResponse>(
                &mut encoded,
                MAX_HANDSHAKE_FRAME_SIZE,
            )
            .await
            .expect("read consensus retirement control"),
            SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected)
        ));
        assert_eq!(
            usize::try_from(encoded.position()).expect("cursor position"),
            encoded.get_ref().len(),
            "exactly one consensus control frame must be emitted"
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn consensus_expiry_crossing_at_final_zero_ack_boundary_emits_only_retirement_control() {
        let (server_binding, client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let reauthentication = SessionReauthenticationControl::new();
        let mut pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        pending.expire_at_final_ack_boundary = true;
        let mut input = valid_consensus_hello_bytes(&client_binding).await;
        let hello_bytes = input.len();
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"must-not-dispatch".to_vec(),
        )
        .expect("bounded consensus request");
        write_frame(
            &mut input,
            &SessionConsensusTransportRequest::Call {
                call_id: uuid::Uuid::nil(),
                request,
            },
        )
        .await
        .expect("append Openraft call behind valid consensus Hello");
        let mut reader = std::io::Cursor::new(input);
        let mut writer = Vec::new();
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            server_binding,
            handler.clone(),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_secs(1),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication,
        )
        .await
        .expect("final-boundary consensus expiry is an expected control exchange");

        assert_eq!(
            usize::try_from(reader.position()).expect("reader position"),
            hello_bytes,
            "no Openraft call bytes may be read or dispatched"
        );
        let mut encoded = std::io::Cursor::new(writer);
        assert!(matches!(
            read_frame::<_, SessionConsensusBootstrapResponse>(
                &mut encoded,
                MAX_HANDSHAKE_FRAME_SIZE,
            )
            .await
            .expect("read final-boundary consensus retirement control"),
            SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected)
        ));
        assert_eq!(
            usize::try_from(encoded.position()).expect("writer position"),
            encoded.get_ref().len(),
            "one complete retirement control and zero Accepted bytes must be emitted"
        );
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn consensus_post_hello_pre_admit_material_change_is_recorded_once() {
        let material = crate::test_support::RotatableServerMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/server",
        );
        let tls_config = material.config();
        let handshake = tls_config
            .begin_handshake()
            .expect("capture pre-rotation consensus material");
        let established_at = tokio::time::Instant::now();
        let pending = PendingConsensusLifecycle {
            handshake: Some(handshake),
            tls_config: Some(tls_config),
            local_certificate_expiry: None,
            peer_certificate_expiry: None,
            established_at,
            generation: 0,
            expire_at_final_ack_boundary: false,
        };
        let policy = test_consensus_lifecycle_policy();
        let bootstrap_lifecycle = pending
            .provisional_lifecycle(policy)
            .expect("provisional post-TLS consensus lifecycle");

        // This admission gate runs after the consensus Hello has passed its
        // identity/scope checks and before Accepted or any Openraft call.
        material.rotate();
        let reason = match pending.admit(policy, 0) {
            Err(PendingConsensusAdmissionError::Retired(reason)) => reason,
            Err(PendingConsensusAdmissionError::Protocol(error)) => {
                panic!("consensus material race was misclassified as protocol: {error}")
            }
            Ok(_) => panic!("stale consensus handshake snapshot must not be admitted"),
        };
        assert_eq!(reason, RetirementReason::MaterialEpoch);
        bootstrap_lifecycle.record_forced_retirement(reason);
        bootstrap_lifecycle.record_forced_retirement(reason);
        assert_eq!(
            bootstrap_lifecycle.recorded_retirement_count(),
            1,
            "the consensus admission race must publish one retirement outcome"
        );
    }

    #[tokio::test]
    async fn consensus_rotation_after_ack_bytes_start_never_appends_retirement_control() {
        let (server_binding, client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let reauthentication = SessionReauthenticationControl::new();
        let pending = PendingConsensusLifecycle::insecure(reauthentication.generation());
        let mut reader = std::io::Cursor::new(valid_consensus_hello_bytes(&client_binding).await);
        let bytes = Arc::new(StdMutex::new(Vec::new()));
        let wrote_first_chunk = Arc::new(Notify::new());
        let first_chunk = wrote_first_chunk.notified();
        tokio::pin!(first_chunk);
        let mut writer = PartialConsensusAcknowledgementWriter {
            bytes: Arc::clone(&bytes),
            first_chunk_written: false,
            wrote_first_chunk: Arc::clone(&wrote_first_chunk),
        };
        let cancellation = AtomicBool::new(false);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let dispatch = dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            server_binding,
            handler.clone(),
            MAX_NEGOTIATED_FRAME_SIZE,
            Duration::from_secs(1),
            Duration::from_secs(1),
            &cancellation,
            shutdown_rx,
            test_consensus_lifecycle_policy(),
            reauthentication.clone(),
        );
        tokio::pin!(dispatch);
        tokio::select! {
            _ = &mut first_chunk => {}
            result = &mut dispatch => panic!("consensus dispatch ended before partial Ack: {result:?}"),
        }
        reauthentication
            .request_reauthentication()
            .expect("retire consensus connection after Ack transmission starts");
        tokio::time::timeout(Duration::from_secs(1), &mut dispatch)
            .await
            .expect("partial consensus Ack retirement must close promptly")
            .expect("partial consensus Ack retirement is a conservative close");

        let written = bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            written.len(),
            2,
            "only the partial Ack prefix may be written"
        );
        assert!(!String::from_utf8_lossy(&written).contains("Rejected"));
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
    }

    async fn raw_consensus_connection(
        addr: SocketAddr,
        binding: &RemoteReplicaBinding,
    ) -> TcpStream {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let nonce = uuid::Uuid::new_v4();
        write_frame(
            &mut stream,
            &SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
                transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                sender_replica_id: binding.local_replica_id().as_str().to_owned(),
                expected_server_replica_id: binding.remote_replica_id().as_str().to_owned(),
                identity: binding.consensus_identity(),
                sender_node_id: binding.local_consensus_node_id(),
                expected_server_node_id: binding.remote_consensus_node_id(),
                handshake_nonce: nonce,
                requested_response_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
            }),
        )
        .await
        .expect("write Hello");
        let response: SessionConsensusBootstrapResponse =
            read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read acknowledgement");
        assert!(matches!(
            response,
            SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                handshake_nonce,
                ..
            }) if handshake_nonce == nonce
        ));
        stream
    }

    async fn bootstrap_retirement_then_consensus_response_server(
        server_binding: RemoteReplicaBinding,
    ) -> (SocketAddr, tokio::task::JoinHandle<(usize, usize)>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind consensus bootstrap-retirement listener");
        let address = listener
            .local_addr()
            .expect("consensus bootstrap-retirement address");
        let task = tokio::spawn(async move {
            let mut application_calls = 0;
            for attempt in 0..2 {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("accept consensus bootstrap client");
                let hello: SessionConsensusBootstrapRequest =
                    read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                        .await
                        .expect("read consensus bootstrap Hello");
                let SessionConsensusBootstrapRequest::Hello(hello) = hello;
                if attempt == 0 {
                    write_frame(
                        &mut stream,
                        &SessionConsensusBootstrapResponse::Rejected(
                            SessionConsensusPeerError::Rejected,
                        ),
                    )
                    .await
                    .expect("write consensus pre-admission retirement control");
                    if matches!(
                        tokio::time::timeout(
                            Duration::from_millis(100),
                            read_frame::<_, SessionConsensusTransportRequest>(
                                &mut stream,
                                MAX_NEGOTIATED_FRAME_SIZE,
                            ),
                        )
                        .await,
                        Ok(Ok(_))
                    ) {
                        application_calls += 1;
                    }
                    continue;
                }
                write_frame(
                    &mut stream,
                    &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                        transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                        contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                        identity: hello.identity,
                        server_node_id: server_binding.remote_consensus_node_id(),
                        accepted_sender_node_id: hello.sender_node_id,
                        handshake_nonce: hello.handshake_nonce,
                        accepted_response_frame_size: hello.requested_response_frame_size,
                        server_request_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                    }),
                )
                .await
                .expect("write fresh consensus acknowledgement");
                let call: SessionConsensusTransportRequest =
                    read_frame(&mut stream, MAX_NEGOTIATED_FRAME_SIZE)
                        .await
                        .expect("read fresh consensus call");
                let SessionConsensusTransportRequest::Call { call_id, request } = call;
                application_calls += 1;
                write_frame(
                    &mut stream,
                    &SessionConsensusTransportResponse::Call {
                        call_id,
                        response: SessionConsensusWireResponse {
                            result: Ok(request.payload),
                        },
                    },
                )
                .await
                .expect("write fresh consensus response");
            }
            (2, application_calls)
        });
        (address, task)
    }

    #[tokio::test]
    async fn consensus_bootstrap_retirement_retries_before_any_openraft_call_dispatch() {
        let (_server_binding, client_binding) = bindings();
        let (address, server) =
            bootstrap_retirement_then_consensus_response_server(client_binding.clone()).await;
        let resolve: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, resolve),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(2)),
        )
        .with_connection_lifecycle(
            ConnectionLifecyclePolicy::try_new(
                Duration::from_secs(10),
                Duration::from_secs(1),
                Duration::from_millis(1),
                Duration::from_millis(5),
                Duration::ZERO,
            )
            .expect("test consensus lifecycle policy"),
        );
        let request = SessionConsensusWireRequest::try_new(
            client_binding.consensus_identity(),
            client_binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            b"fresh-consensus-route".to_vec(),
        )
        .expect("bounded consensus request");

        assert_eq!(
            peer.call(request).await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"fresh-consensus-route".to_vec()),
            })
        );
        assert_eq!(
            server.await.expect("consensus bootstrap-retirement server"),
            (2, 1),
            "the retired route must receive no Openraft call and the fresh route exactly one"
        );
    }

    #[tokio::test]
    async fn rejected_is_reserved_exclusively_for_consensus_bootstrap_retirement() {
        let mut sink = tokio::io::sink();
        let cancellation = AtomicBool::new(false);
        assert!(matches!(
            reject_consensus_bootstrap(
                &mut sink,
                SessionConsensusPeerError::Rejected,
                Duration::from_secs(1),
                &cancellation,
            )
            .await,
            Err(ProtocolError::InvalidWireValue)
        ));

        let (mut writer, mut reader) = tokio::io::duplex(1024);
        retire_consensus_bootstrap(&mut writer, Duration::from_secs(1), &cancellation)
            .await
            .expect("write reserved bootstrap retirement");
        assert!(matches!(
            read_frame::<_, SessionConsensusBootstrapResponse>(
                &mut reader,
                MAX_HANDSHAKE_FRAME_SIZE,
            )
            .await
            .expect("read reserved bootstrap retirement"),
            SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Rejected)
        ));
    }

    #[tokio::test]
    async fn bad_or_incomplete_consensus_response_connection_is_never_reused() {
        let (_server_binding, client_binding) = bindings();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind adversarial consensus listener");
        let addr = listener.local_addr().expect("adversarial listener address");
        let server_binding = client_binding.clone();
        let server = tokio::spawn(async move {
            for attempt in 0..3 {
                let (mut stream, _) = listener.accept().await.expect("accept consensus client");
                let hello: SessionConsensusBootstrapRequest =
                    read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                        .await
                        .expect("read consensus Hello");
                let SessionConsensusBootstrapRequest::Hello(hello) = hello;
                write_frame(
                    &mut stream,
                    &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
                        transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                        contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
                        identity: hello.identity,
                        server_node_id: server_binding.remote_consensus_node_id(),
                        accepted_sender_node_id: hello.sender_node_id,
                        handshake_nonce: hello.handshake_nonce,
                        accepted_response_frame_size: hello.requested_response_frame_size,
                        server_request_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
                    }),
                )
                .await
                .expect("write consensus acknowledgement");
                let call: SessionConsensusTransportRequest =
                    read_frame(&mut stream, MAX_NEGOTIATED_FRAME_SIZE)
                        .await
                        .expect("read consensus call");
                let SessionConsensusTransportRequest::Call { call_id, request } = call;
                if attempt == 1 {
                    // EOF after a complete request leaves the response position
                    // unknown and must make this stream permanently unusable.
                    continue;
                }
                let response_call_id = if attempt == 0 {
                    uuid::Uuid::new_v4()
                } else {
                    call_id
                };
                write_frame(
                    &mut stream,
                    &SessionConsensusTransportResponse::Call {
                        call_id: response_call_id,
                        response: SessionConsensusWireResponse {
                            result: Ok(request.payload),
                        },
                    },
                )
                .await
                .expect("write consensus response");
            }
        });
        let resolutions = Arc::new(AtomicUsize::new(0));
        let counted_resolver: RemoteAddrResolver = {
            let resolutions = Arc::clone(&resolutions);
            Arc::new(move || {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(addr) })
            })
        };
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(&client_binding, counted_resolver),
            None,
            client_binding.clone(),
            Some(Duration::from_secs(1)),
        );
        let wire_request = |payload: &'static [u8]| {
            SessionConsensusWireRequest::try_new(
                client_binding.consensus_identity(),
                client_binding.local_consensus_node_id(),
                SessionConsensusRpcFamily::Vote,
                payload.to_vec(),
            )
            .expect("bounded consensus request")
        };

        assert_eq!(
            peer.call(wire_request(b"wrong-correlation")).await,
            Err(SessionConsensusPeerError::Protocol)
        );
        assert_eq!(
            peer.call(wire_request(b"incomplete-response")).await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(
            peer.call(wire_request(b"fresh-after-errors")).await,
            Ok(SessionConsensusWireResponse {
                result: Ok(b"fresh-after-errors".to_vec()),
            })
        );
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            3,
            "correlation failure and EOF must each force one fresh bootstrap"
        );
        server.await.expect("adversarial consensus server");
    }

    #[tokio::test]
    async fn consensus_bootstrap_rejects_the_previous_nested_error_set() {
        let (server_binding, client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = SessionConsensusServer::from_transport(handler.clone(), None, server_binding);
        let (handle, addr) = server
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("listen");

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let mut previous_profile = CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE;
        previous_profile.error_set_revision = 1;
        let nonce = uuid::Uuid::new_v4();
        write_frame(
            &mut stream,
            &SessionConsensusBootstrapRequest::Hello(SessionConsensusBootstrapHello {
                transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
                contract_profile: previous_profile,
                sender_replica_id: client_binding.local_replica_id().as_str().to_owned(),
                expected_server_replica_id: client_binding.remote_replica_id().as_str().to_owned(),
                identity: client_binding.consensus_identity(),
                sender_node_id: client_binding.local_consensus_node_id(),
                expected_server_node_id: client_binding.remote_consensus_node_id(),
                handshake_nonce: nonce,
                requested_response_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
            }),
        )
        .await
        .expect("write previous-profile Hello");
        assert!(matches!(
            read_frame::<_, SessionConsensusBootstrapResponse>(
                &mut stream,
                MAX_HANDSHAKE_FRAME_SIZE
            )
            .await
            .expect("read rejection"),
            SessionConsensusBootstrapResponse::Rejected(SessionConsensusPeerError::Protocol)
        ));
        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
        handle.abort_and_wait().await;
    }

    #[tokio::test]
    async fn consensus_mode_rejects_raw_mutation_rebuild_and_malformed_frames() {
        let (server_binding, client_binding) = bindings();
        let handler = Arc::new(CountingHandler(AtomicUsize::new(0)));
        let server = SessionConsensusServer::from_transport(handler.clone(), None, server_binding);
        let (handle, addr) = server
            .listen("127.0.0.1:0".parse().expect("listen address"))
            .await
            .expect("listen");

        let mut raw_mutation = raw_consensus_connection(addr, &client_binding).await;
        write_frame(
            &mut raw_mutation,
            &Request::Batch {
                ops: Vec::<SessionOp>::new(),
            },
        )
        .await
        .expect("write raw mutation");
        assert!(read_frame::<_, SessionConsensusTransportResponse>(
            &mut raw_mutation,
            MAX_NEGOTIATED_FRAME_SIZE
        )
        .await
        .is_err());

        let mut raw_rebuild = raw_consensus_connection(addr, &client_binding).await;
        write_frame(
            &mut raw_rebuild,
            &Request::RebuildReplicationState {
                entries: Vec::new(),
            },
        )
        .await
        .expect("write raw rebuild");
        assert!(read_frame::<_, SessionConsensusTransportResponse>(
            &mut raw_rebuild,
            MAX_NEGOTIATED_FRAME_SIZE
        )
        .await
        .is_err());

        let mut malformed = raw_consensus_connection(addr, &client_binding).await;
        malformed
            .write_all(&1_u32.to_be_bytes())
            .await
            .expect("write malformed length");
        malformed
            .write_all(b"{")
            .await
            .expect("write malformed payload");
        malformed.flush().await.expect("flush malformed payload");
        assert!(read_frame::<_, SessionConsensusTransportResponse>(
            &mut malformed,
            MAX_NEGOTIATED_FRAME_SIZE
        )
        .await
        .is_err());

        let mut oversized = raw_consensus_connection(addr, &client_binding).await;
        oversized
            .write_all(
                &u32::try_from(MAX_NEGOTIATED_FRAME_SIZE + 1)
                    .expect("bounded oversize length")
                    .to_be_bytes(),
            )
            .await
            .expect("write oversized length");
        oversized.flush().await.expect("flush oversized length");
        assert!(read_frame::<_, SessionConsensusTransportResponse>(
            &mut oversized,
            MAX_NEGOTIATED_FRAME_SIZE
        )
        .await
        .is_err());

        assert_eq!(handler.0.load(Ordering::Relaxed), 0);
        handle.abort_and_wait().await;
    }

    #[test]
    fn remote_consensus_peer_is_accepted_only_as_the_consensus_port() {
        fn accepts_consensus_port<T: SessionConsensusPeer>() {}
        accepts_consensus_port::<RemoteSessionConsensusPeer>();

        let (server_binding, client_binding) = bindings();
        let _ = server_binding;
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(
                &client_binding,
                Arc::new(|| {
                    Box::pin(async {
                        Err(io::Error::new(io::ErrorKind::NotFound, "test resolver"))
                    })
                }),
            ),
            None,
            client_binding,
            None,
        );
        let _: &dyn SessionConsensusPeer = &peer;
        let request = SessionConsensusWireRequest::try_new(
            peer.binding.consensus_identity(),
            peer.binding.local_consensus_node_id(),
            SessionConsensusRpcFamily::Vote,
            Vec::new(),
        )
        .expect("request");
        assert!(request.validate().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_cached_consensus_connection_is_reaped_at_its_soft_lifecycle_bound() {
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(40),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("cached connection lifecycle policy");
        let established_at = tokio::time::Instant::now();
        let lifecycle = ConnectionLifecycle::new(policy, established_at, None, None, 0, None)
            .expect("cached connection lifecycle");
        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        {
            let mut primary = pool.primary.connection.lock().await;
            *primary = Some(ConsensusConnection {
                reader: Box::new(reader),
                writer: Box::new(writer),
                response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
                request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
                lifecycle,
            });
        }
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            None,
            SessionReauthenticationControl::new(),
            [0; 32],
        );
        pool.primary.changed.notify_one();
        tokio::task::yield_now().await;
        assert!(pool.primary.connection.lock().await.is_some());

        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert!(
            pool.primary.connection.lock().await.is_none(),
            "an idle cached connection must not survive its soft lifecycle bound"
        );
    }

    fn cached_consensus_connection(lifecycle: ConnectionLifecycle) -> ConsensusConnection {
        let (stream, _remote) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(stream);
        ConsensusConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            response_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            request_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE,
            lifecycle,
        }
    }

    async fn wait_for_cached_lane_to_empty(
        pool: &ConsensusConnectionPool,
        lane: ConsensusConnectionLane,
    ) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if pool.lane(lane).connection.lock().await.is_none() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cached consensus lane retirement");
    }

    #[tokio::test]
    async fn idle_cached_consensus_connection_reacts_to_explicit_reauthentication() {
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(40),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("explicit reauthentication lifecycle policy");
        let lifecycle =
            ConnectionLifecycle::new(policy, tokio::time::Instant::now(), None, None, 0, None)
                .expect("explicit reauthentication lifecycle");
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        *pool.primary.connection.lock().await = Some(cached_consensus_connection(lifecycle));
        let reauthentication = SessionReauthenticationControl::new();
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            None,
            reauthentication.clone(),
            [1; 32],
        );
        pool.primary.changed.notify_one();
        tokio::task::yield_now().await;

        reauthentication
            .request_reauthentication()
            .expect("request cached consensus reauthentication");
        wait_for_cached_lane_to_empty(&pool, ConsensusConnectionLane::Primary).await;
    }

    #[tokio::test]
    async fn idle_cached_consensus_connection_reacts_to_material_epoch_change() {
        let material = crate::test_support::RotatableClientMaterial::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/client",
        );
        let tls_config = material.config();
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(40),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("material epoch lifecycle policy");
        let lifecycle = ConnectionLifecycle::new(
            policy,
            tokio::time::Instant::now(),
            None,
            None,
            0,
            Some(tls_config.material_status().epoch()),
        )
        .expect("material epoch lifecycle");
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        *pool.primary.connection.lock().await = Some(cached_consensus_connection(lifecycle));
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            Some(tls_config),
            SessionReauthenticationControl::new(),
            [2; 32],
        );
        pool.primary.changed.notify_one();
        tokio::task::yield_now().await;

        material.rotate();
        wait_for_cached_lane_to_empty(&pool, ConsensusConnectionLane::Primary).await;
    }

    #[tokio::test(start_paused = true)]
    async fn cached_consensus_reaper_never_races_an_in_flight_lane() {
        let policy = ConnectionLifecyclePolicy::try_new(
            Duration::from_secs(40),
            Duration::from_secs(10),
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::ZERO,
        )
        .expect("in-flight exclusion lifecycle policy");
        let lifecycle =
            ConnectionLifecycle::new(policy, tokio::time::Instant::now(), None, None, 0, None)
                .expect("in-flight exclusion lifecycle");
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        *pool.primary.connection.lock().await = Some(cached_consensus_connection(lifecycle));
        let in_flight = pool.primary.connection.lock().await;
        pool.ensure_cached_connection_reaper(
            ConsensusConnectionLane::Primary,
            None,
            SessionReauthenticationControl::new(),
            [3; 32],
        );
        pool.primary.changed.notify_one();
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert!(
            in_flight.is_some(),
            "the reaper must wait for the in-flight lane owner"
        );
        drop(in_flight);
        wait_for_cached_lane_to_empty(&pool, ConsensusConnectionLane::Primary).await;
    }

    #[tokio::test]
    async fn reaper_inspection_never_redirects_sequential_work_to_overflow() {
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        let inspection = pool.primary.connection.lock().await;
        assert_eq!(pool.primary.in_flight.available_permits(), 1);

        let waiting_pool = Arc::clone(&pool);
        let waiter = tokio::spawn(async move { waiting_pool.acquire().await.lane });
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "an idle-lane inspection must make sequential work wait for primary"
        );
        assert_eq!(pool.primary.in_flight.available_permits(), 0);
        assert_eq!(pool.overflow.in_flight.available_permits(), 1);

        drop(inspection);
        assert!(matches!(
            waiter.await.expect("sequential lane acquisition"),
            ConsensusConnectionLane::Primary
        ));
        assert_eq!(pool.primary.in_flight.available_permits(), 1);
    }

    #[tokio::test]
    async fn concurrent_work_uses_overflow_while_reaper_inspects_primary() {
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        let inspection = pool.primary.connection.lock().await;

        let primary_pool = Arc::clone(&pool);
        let primary = tokio::spawn(async move { primary_pool.acquire().await.lane });
        tokio::time::timeout(Duration::from_secs(1), async {
            while pool.primary.in_flight.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first caller reserves the inspected primary lane");

        let overflow_pool = Arc::clone(&pool);
        let overflow = tokio::spawn(async move { overflow_pool.acquire().await.lane });
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), overflow)
                .await
                .expect("concurrent caller must not queue behind inspected primary")
                .expect("overflow lane acquisition"),
            ConsensusConnectionLane::Overflow
        ));

        drop(inspection);
        assert!(matches!(
            primary.await.expect("primary lane acquisition"),
            ConsensusConnectionLane::Primary
        ));
        assert_eq!(pool.primary.in_flight.available_permits(), 1);
        assert_eq!(pool.overflow.in_flight.available_permits(), 1);
    }

    #[tokio::test]
    async fn cached_consensus_reapers_are_fixed_to_two_and_do_not_retain_the_pool() {
        let pool = Arc::new(ConsensusConnectionPool::new(
            ConnectionLifecyclePolicy::default(),
        ));
        let reauthentication = SessionReauthenticationControl::new();
        for _ in 0..16 {
            pool.ensure_cached_connection_reaper(
                ConsensusConnectionLane::Primary,
                None,
                reauthentication.clone(),
                [4; 32],
            );
            pool.ensure_cached_connection_reaper(
                ConsensusConnectionLane::Overflow,
                None,
                reauthentication.clone(),
                [5; 32],
            );
        }
        assert!(pool.primary.reaper_started.load(Ordering::Acquire));
        assert!(pool.overflow.reaper_started.load(Ordering::Acquire));
        assert_eq!(
            pool.shutdown.receiver_count(),
            2,
            "one and only one reaper may exist for each fixed lane"
        );

        let weak = Arc::downgrade(&pool);
        drop(pool);
        tokio::task::yield_now().await;
        assert!(
            weak.upgrade().is_none(),
            "reaper tasks must hold only weak pool ownership"
        );
    }

    #[test]
    fn clone_local_consensus_builders_detach_incompatible_connection_state() {
        let (_server_binding, client_binding) = bindings();
        let peer = RemoteSessionConsensusPeer::from_transport(
            ConsensusTarget::resolved(
                &client_binding,
                Arc::new(|| {
                    Box::pin(async {
                        Err(io::Error::new(io::ErrorKind::NotFound, "test resolver"))
                    })
                }),
            ),
            None,
            client_binding,
            None,
        );
        let shared = peer.clone();
        assert!(Arc::ptr_eq(&peer.connection_pool, &shared.connection_pool));

        let different_frame = peer
            .clone()
            .with_max_frame_size(MIN_SESSION_CONSENSUS_FRAME_SIZE);
        assert!(!Arc::ptr_eq(
            &peer.connection_pool,
            &different_frame.connection_pool
        ));

        let different_lifecycle = peer
            .clone()
            .with_connection_lifecycle(ConnectionLifecyclePolicy::default());
        assert!(!Arc::ptr_eq(
            &peer.connection_pool,
            &different_lifecycle.connection_pool
        ));

        let different_control = peer
            .clone()
            .with_reauthentication_control(SessionReauthenticationControl::new());
        assert!(!Arc::ptr_eq(
            &peer.connection_pool,
            &different_control.connection_pool
        ));
    }
}
