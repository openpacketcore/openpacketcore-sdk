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

fn consensus_client_tls_config(
    config: &opc_tls::AuthenticatedClientConfig,
) -> Arc<opc_tls::ClientConfig> {
    let mut config = config.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![SESSION_CONSENSUS_ALPN.to_vec()];
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

fn consensus_server_tls_config(
    config: &opc_tls::AuthenticatedServerConfig,
) -> Arc<opc_tls::ServerConfig> {
    let mut config = config.rustls_config().as_ref().clone();
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

/// Authenticated outbound peer implementing only the session consensus port.
#[derive(Clone)]
pub struct RemoteSessionConsensusPeer {
    target: ConsensusTarget,
    tls_config: Option<Arc<opc_tls::ClientConfig>>,
    binding: RemoteReplicaBinding,
    deadline: Duration,
    max_frame_size: usize,
    call_gate: Arc<Mutex<()>>,
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
        Self::from_transport(
            target,
            Some(consensus_client_tls_config(&tls_config)),
            binding,
            deadline,
        )
    }

    /// Construct a mutually authenticated peer with a reconnect-time resolver.
    pub fn new_with_resolver(
        binding: RemoteReplicaBinding,
        resolve: RemoteAddrResolver,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let target = ConsensusTarget::resolved(&binding, resolve);
        Self::from_transport(
            target,
            Some(consensus_client_tls_config(&tls_config)),
            binding,
            deadline,
        )
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
        tls_config: Option<Arc<opc_tls::ClientConfig>>,
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
        }
    }

    /// Set the negotiated encoded request/response frame budget.
    #[must_use]
    pub fn with_max_frame_size(mut self, max_frame_size: usize) -> Self {
        self.max_frame_size = max_frame_size;
        self
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

        let addr = self
            .target
            .resolve()
            .await
            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|_| SessionConsensusPeerError::Unavailable)?;

        if let Some(tls_config) = &self.tls_config {
            let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
            let server_name = self.target.tls_server_name(addr)?;
            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(map_tls_connect_error)?;
            if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_CONSENSUS_ALPN) {
                return Err(SessionConsensusPeerError::Authentication);
            }
            let peer_spiffe =
                opc_tls::peer_spiffe_id_from_client_connection(tls_stream.get_ref().1)
                    .map_err(|_| SessionConsensusPeerError::Authentication)?;
            if peer_spiffe.as_str() != self.binding.remote_spiffe_id().as_str() {
                return Err(SessionConsensusPeerError::Authentication);
            }
            let (mut reader, mut writer) = tokio::io::split(tls_stream);
            self.exchange(&mut reader, &mut writer, request, deadline)
                .await
        } else {
            let (mut reader, mut writer) = tokio::io::split(tcp);
            self.exchange(&mut reader, &mut writer, request, deadline)
                .await
        }
    }

    async fn exchange<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        request: SessionConsensusWireRequest,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError>
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

        let call_id = uuid::Uuid::new_v4();
        write_frame_bounded_until(
            writer,
            &SessionConsensusTransportRequest::Call { call_id, request },
            request_frame_size,
            deadline,
        )
        .await
        .map_err(|error| map_protocol_error(&error))?;
        let response: SessionConsensusTransportResponse = read_frame(reader, response_frame_size)
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
    tls_config: Option<Arc<opc_tls::ServerConfig>>,
    binding: LocalReplicaBinding,
    max_connections: usize,
    max_frame_size: usize,
    idle_timeout: Duration,
    rpc_timeout: Duration,
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
        Self::from_transport(
            handler,
            Some(consensus_server_tls_config(&tls_config)),
            binding,
        )
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
        tls_config: Option<Arc<opc_tls::ServerConfig>>,
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

#[allow(clippy::too_many_arguments)]
async fn handle_consensus_connection(
    stream: TcpStream,
    tls_config: Option<Arc<opc_tls::ServerConfig>>,
    binding: LocalReplicaBinding,
    handler: Arc<dyn SessionConsensusRpcHandler>,
    max_frame_size: usize,
    idle_timeout: Duration,
    rpc_timeout: Duration,
    cancellation: Arc<AtomicBool>,
) -> Result<(), ProtocolError> {
    if let Some(tls_config) = tls_config {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let tls_stream = tokio::time::timeout(idle_timeout, acceptor.accept(stream))
            .await
            .map_err(|_| {
                ProtocolError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "consensus TLS handshake timed out",
                ))
            })?
            .map_err(ProtocolError::Io)?;
        if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_CONSENSUS_ALPN) {
            return Err(ProtocolError::Authentication);
        }
        let peer_spiffe = opc_tls::peer_spiffe_id_from_server_connection(tls_stream.get_ref().1)
            .map_err(|_| ProtocolError::Authentication)?;
        let (mut reader, mut writer) = tokio::io::split(tls_stream);
        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::Authenticated(peer_spiffe),
            binding,
            handler,
            max_frame_size,
            idle_timeout,
            rpc_timeout,
            &cancellation,
        )
        .await
    } else {
        let (mut reader, mut writer) = tokio::io::split(stream);
        dispatch_consensus(
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            binding,
            handler,
            max_frame_size,
            idle_timeout,
            rpc_timeout,
            &cancellation,
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
    binding: LocalReplicaBinding,
    handler: Arc<dyn SessionConsensusRpcHandler>,
    max_frame_size: usize,
    idle_timeout: Duration,
    rpc_timeout: Duration,
    cancellation: &AtomicBool,
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

    loop {
        let inbound: SessionConsensusTransportRequest =
            match read_frame_within(reader, max_frame_size, idle_timeout).await {
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
            match tokio::time::timeout(rpc_timeout, handler.handle(hello.sender_node_id, request))
                .await
            {
                Ok(response) if response.validate().is_ok() => response,
                Ok(_) => SessionConsensusWireResponse {
                    result: Err(SessionConsensusPeerError::Protocol),
                },
                Err(_) => SessionConsensusWireResponse {
                    result: Err(SessionConsensusPeerError::Timeout),
                },
            }
        };
        let deadline = tokio::time::Instant::now()
            .checked_add(idle_timeout)
            .ok_or(ProtocolError::InvalidWireValue)?;
        write_frame_bounded_until_cancellable(
            writer,
            &SessionConsensusTransportResponse::Call { call_id, response },
            effective_response_frame_size,
            deadline,
            cancellation,
        )
        .await?;
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
