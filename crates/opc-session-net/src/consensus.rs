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
use opc_session_store::{
    ReplicaId, SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
};
use opc_types::SpiffeId;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

use crate::error::ProtocolError;
use crate::identity::{LocalReplicaBinding, RemoteReplicaBinding};
use crate::lifecycle::{
    directed_connection_key, wall_expiry_deadline, ConnectionLifecycle, ConnectionLifecyclePolicy,
    SessionReauthenticationControl,
};
use crate::protocol::{
    checked_frame_size, checked_wire_frame_size, negotiate_response_frame_size, read_frame,
    read_frame_within, write_frame_bounded_until, write_frame_bounded_until_cancellable,
    SessionConsensusBootstrapAck, SessionConsensusBootstrapHello, SessionConsensusBootstrapRequest,
    SessionConsensusBootstrapResponse, SessionConsensusTransportRequest,
    SessionConsensusTransportResponse, CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
    MAX_HANDSHAKE_FRAME_SIZE, MAX_NEGOTIATED_FRAME_SIZE, MIN_SESSION_CONSENSUS_FRAME_SIZE,
    SESSION_CONSENSUS_ALPN, SESSION_CONSENSUS_TRANSPORT_REVISION,
};

const DEFAULT_CONSENSUS_DEADLINE: Duration = Duration::from_secs(2);
const DEFAULT_CONSENSUS_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONSENSUS_RPC_TIMEOUT: Duration = Duration::from_secs(30);

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

fn map_tls_connect_error(error: io::Error) -> SessionConsensusPeerError {
    if error
        .get_ref()
        .and_then(|source| source.downcast_ref::<tokio_rustls::rustls::Error>())
        .is_some()
    {
        SessionConsensusPeerError::Authentication
    } else {
        SessionConsensusPeerError::Unavailable
    }
}

async fn wait_consensus_material_change(receiver: &mut Option<opc_tls::TlsMaterialStatusReceiver>) {
    let closed = match receiver.as_mut() {
        Some(receiver) => receiver.changed().await.is_err(),
        None => {
            std::future::pending::<()>().await;
            false
        }
    };
    if closed {
        *receiver = None;
    }
}

struct ConsensusConnection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    response_frame_size: usize,
    request_frame_size: usize,
    lifecycle: ConnectionLifecycle,
}

/// Authenticated outbound peer implementing only the session consensus port.
#[derive(Clone)]
pub struct RemoteSessionConsensusPeer {
    target: ConsensusTarget,
    tls_config: Option<opc_tls::AuthenticatedClientConfig>,
    binding: RemoteReplicaBinding,
    deadline: Duration,
    max_frame_size: usize,
    call_gate: Arc<Mutex<()>>,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
}

impl fmt::Debug for RemoteSessionConsensusPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSessionConsensusPeer")
            .field("target", &self.target)
            .field("authenticated", &self.tls_config.is_some())
            .field("deadline", &self.deadline)
            .field("max_frame_size", &self.max_frame_size)
            .finish_non_exhaustive()
    }
}

impl RemoteSessionConsensusPeer {
    /// Construct a mutually authenticated consensus-only peer.
    pub fn new(
        binding: RemoteReplicaBinding,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let target = ConsensusTarget::configured(&binding);
        Self::from_transport(target, Some(tls_config), binding, deadline)
    }

    /// Construct a mutually authenticated peer with a reconnect-time resolver.
    pub fn new_with_resolver(
        binding: RemoteReplicaBinding,
        resolve: RemoteAddrResolver,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let target = ConsensusTarget::resolved(&binding, resolve);
        Self::from_transport(target, Some(tls_config), binding, deadline)
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
        Self {
            target,
            tls_config,
            binding,
            deadline: deadline.unwrap_or(DEFAULT_CONSENSUS_DEADLINE),
            // The bounded inner consensus payload needs the maximum profile
            // frame in its worst-case JSON byte-array expansion.
            max_frame_size: MAX_NEGOTIATED_FRAME_SIZE,
            call_gate: Arc::new(Mutex::new(())),
            lifecycle_policy: ConnectionLifecyclePolicy::default(),
            reauthentication: SessionReauthenticationControl::new(),
        }
    }

    /// Set the negotiated encoded request/response frame budget.
    #[must_use]
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }

    /// Set the finite authentication and drain policy for consensus calls.
    #[must_use]
    pub fn with_connection_lifecycle(mut self, policy: ConnectionLifecyclePolicy) -> Self {
        self.lifecycle_policy = policy;
        self
    }

    /// Share the graceful reauthentication trigger used by this peer.
    #[must_use]
    pub fn with_reauthentication_control(
        mut self,
        control: SessionReauthenticationControl,
    ) -> Self {
        self.reauthentication = control;
        self
    }

    /// Control used by this peer for explicit graceful reauthentication.
    pub fn reauthentication_control(&self) -> SessionReauthenticationControl {
        self.reauthentication.clone()
    }

    async fn call_once(
        &self,
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

        let mut backoff = self.lifecycle_policy.reconnect_backoff_min();
        let mut connection = loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(SessionConsensusPeerError::Timeout);
            }
            let admitted_generation = self.reauthentication.generation();
            let mut connection = if let Some(tls_config) = &self.tls_config {
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
                                return Err(SessionConsensusPeerError::Authentication);
                            }
                            let peer = opc_tls::peer_tls_identity_from_client_connection(
                                tls_stream.get_ref().1,
                            )
                            .map_err(|_| SessionConsensusPeerError::Authentication)?;
                            if peer.spiffe_id().as_str() != binding.remote_spiffe_id().as_str() {
                                return Err(SessionConsensusPeerError::Authentication);
                            }
                            let tls_completed_at = tokio::time::Instant::now();
                            let (mut reader, mut writer) = tokio::io::split(tls_stream);
                            let (response_frame_size, request_frame_size) =
                                self.bootstrap(&mut reader, &mut writer, deadline).await?;
                            Ok::<_, SessionConsensusPeerError>((
                                Box::new(reader) as Box<dyn AsyncRead + Unpin + Send>,
                                Box::new(writer) as Box<dyn AsyncWrite + Unpin + Send>,
                                response_frame_size,
                                request_frame_size,
                                tls_completed_at,
                                peer.leaf_expires_at(),
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
                        Some(wall_expiry_deadline(
                            admission.leaf_expires_at(),
                            tls_completed_at,
                        )),
                        Some(wall_expiry_deadline(peer_expiry, tls_completed_at)),
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
                let (response_frame_size, request_frame_size) =
                    self.bootstrap(&mut reader, &mut writer, deadline).await?;
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
            let now = tokio::time::Instant::now();
            let current_generation = self.reauthentication.generation();
            connection.lifecycle.observe_rotation(
                now,
                current_generation,
                self.tls_config
                    .as_ref()
                    .map(|config| config.material_status().epoch()),
                &directed_connection_key(
                    b"consensus",
                    self.binding.local_replica_id().as_str(),
                    self.binding.remote_replica_id().as_str(),
                ),
            );
            if current_generation == admitted_generation
                && connection.lifecycle.retirement(now).is_none()
            {
                break connection;
            }
            let retry_at = now.checked_add(backoff).unwrap_or(deadline).min(deadline);
            tokio::time::sleep_until(retry_at).await;
            backoff = self.lifecycle_policy.next_backoff(backoff);
        };
        self.call_negotiated(&mut connection, request, deadline)
            .await
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
        let mut lifecycle = connection.lifecycle;
        let mut reauthentication_rx = self.reauthentication.subscribe();
        let mut material_rx = self
            .tls_config
            .as_ref()
            .map(opc_tls::AuthenticatedClientConfig::subscribe_material_changes);
        loop {
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
            let hard_deadline = lifecycle
                .hard_deadline()
                .map_err(|_| SessionConsensusPeerError::Protocol)?
                .min(deadline);
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(hard_deadline) => {
                    return Err(SessionConsensusPeerError::Timeout);
                }
                response = &mut call => return response,
                _ = reauthentication_rx.changed() => {}
                _ = wait_consensus_material_change(&mut material_rx) => {}
            }
        }
    }
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
        let deadline = tokio::time::Instant::now()
            .checked_add(self.deadline)
            .ok_or(SessionConsensusPeerError::Protocol)?;
        // The gate bounds concurrent connection/TLS/frame memory per peer. It
        // is acquired under the same logical call deadline.
        let call = async {
            let _guard = self.call_gate.lock().await;
            self.call_once(request, deadline).await
        };
        tokio::time::timeout_at(deadline, call)
            .await
            .unwrap_or(Err(SessionConsensusPeerError::Timeout))
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

        let listener = TcpListener::bind(bind_addr).await?;
        let bound_addr = listener.local_addr()?;
        let cancellation = Arc::new(AtomicBool::new(false));
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
                let reauthentication = reauthentication.clone();
                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_consensus_connection(
                        stream,
                        tls_config,
                        binding,
                        handler,
                        max_frame_size,
                        idle_timeout,
                        rpc_timeout,
                        cancellation,
                        lifecycle_policy,
                        reauthentication,
                    )
                    .await;
                });
                registry.handles.push(handle);
            }
        });

        Ok((
            SessionConsensusServerHandle {
                accept_handle,
                connection_tasks,
                cancellation,
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
}

impl SessionConsensusServerHandle {
    /// Schedule immediate cancellation of the listener and all connections.
    pub fn abort(&self) {
        self.cancellation.store(true, Ordering::Release);
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
    peer_leaf_expiry: Option<opc_types::Timestamp>,
    established_at: tokio::time::Instant,
    generation: u64,
}

impl PendingConsensusLifecycle {
    fn insecure(generation: u64) -> Self {
        Self {
            handshake: None,
            tls_config: None,
            peer_leaf_expiry: None,
            established_at: tokio::time::Instant::now(),
            generation,
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
        ProtocolError,
    > {
        if current_generation != self.generation {
            return Err(ProtocolError::Authentication);
        }
        let (local_expiry, epoch) = match self.handshake {
            Some(handshake) => {
                let admission = handshake
                    .admit()
                    .map_err(|_| ProtocolError::Authentication)?;
                (
                    Some(wall_expiry_deadline(
                        admission.leaf_expires_at(),
                        self.established_at,
                    )),
                    Some(admission.epoch()),
                )
            }
            None => (None, None),
        };
        let lifecycle = ConnectionLifecycle::new(
            policy,
            self.established_at,
            local_expiry,
            self.peer_leaf_expiry
                .map(|expiry| wall_expiry_deadline(expiry, self.established_at)),
            self.generation,
            epoch,
        )
        .map_err(|_| ProtocolError::InvalidWireValue)?;
        Ok((lifecycle, self.tls_config))
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
                tokio::time::sleep_until(hard_deadline).await;
                hard_tx.send_replace(true);
                connection_cancellation.store(true, Ordering::Release);
                return;
            }
            tokio::select! {
                biased;
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
            .map_err(ProtocolError::Io)?;
        let established_at = tokio::time::Instant::now();
        if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_CONSENSUS_ALPN) {
            return Err(ProtocolError::Authentication);
        }
        let peer = opc_tls::peer_tls_identity_from_server_connection(tls_stream.get_ref().1)
            .map_err(|_| ProtocolError::Authentication)?;
        let (mut reader, mut writer) = tokio::io::split(tls_stream);
        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::Authenticated(peer.spiffe_id().clone()),
            PendingConsensusLifecycle {
                handshake: Some(handshake),
                tls_config: Some(tls_config),
                peer_leaf_expiry: Some(peer.leaf_expires_at()),
                established_at,
                generation,
            },
            binding,
            handler,
            max_frame_size,
            idle_timeout,
            rpc_timeout,
            &cancellation,
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
    cancellation: &AtomicBool,
    lifecycle_policy: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let hello: SessionConsensusBootstrapRequest =
        read_frame_within(reader, MAX_HANDSHAKE_FRAME_SIZE, idle_timeout).await?;
    let SessionConsensusBootstrapRequest::Hello(hello) = hello;
    if hello.transport_revision != SESSION_CONSENSUS_TRANSPORT_REVISION
        || !hello.contract_profile.is_current()
    {
        reject_consensus_bootstrap(
            writer,
            SessionConsensusPeerError::Protocol,
            idle_timeout,
            cancellation,
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
                    cancellation,
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
            cancellation,
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
                cancellation,
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
                cancellation,
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
            cancellation,
        )
        .await?;
        return Err(ProtocolError::Authentication);
    }

    let write_deadline = tokio::time::Instant::now()
        .checked_add(idle_timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    write_frame_bounded_until_cancellable(
        writer,
        &SessionConsensusBootstrapResponse::Accepted(SessionConsensusBootstrapAck {
            transport_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
            contract_profile: CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
            identity: binding.consensus_identity(),
            server_node_id: binding.local_consensus_node_id(),
            accepted_sender_node_id: hello.sender_node_id,
            handshake_nonce: hello.handshake_nonce,
            accepted_response_frame_size: requested_response_frame_size,
            server_request_frame_size,
        }),
        MAX_HANDSHAKE_FRAME_SIZE,
        write_deadline,
        cancellation,
    )
    .await?;

    let (mut lifecycle, lifecycle_tls_config) =
        pending_lifecycle.admit(lifecycle_policy, reauthentication.generation())?;
    let edge_key = directed_connection_key(
        b"consensus",
        sender_replica_id.as_str(),
        binding.local_replica_id().as_str(),
    );
    let now = tokio::time::Instant::now();
    lifecycle.observe_rotation(
        now,
        reauthentication.generation(),
        lifecycle_tls_config
            .as_ref()
            .map(|config| config.material_status().epoch()),
        &edge_key,
    );
    if lifecycle.retirement(now).is_some() {
        return Ok(());
    }
    let connection_cancellation = Arc::new(AtomicBool::new(false));
    let (_lifecycle_task, mut retirement_rx, mut hard_rx) = spawn_consensus_lifecycle(
        lifecycle,
        edge_key,
        lifecycle_tls_config,
        reauthentication,
        connection_cancellation.clone(),
    );
    let cancellation = connection_cancellation.as_ref();

    loop {
        if *retirement_rx.borrow() || *hard_rx.borrow() {
            return Ok(());
        }
        let inbound_result = tokio::select! {
            biased;
            _ = hard_rx.changed() => return Ok(()),
            _ = retirement_rx.changed() => return Ok(()),
            inbound = read_frame_within(reader, max_frame_size, idle_timeout) => inbound,
        };
        let inbound: SessionConsensusTransportRequest = match inbound_result {
            Ok(request) => request,
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
                cancellation,
            ) => result?,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use opc_session_store::{
        QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
        ReplicaTlsIdentity, SessionConsensusRpcFamily, SessionOp,
    };
    use tokio::io::AsyncWriteExt;

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
}
