use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::Stream;
use opc_session_store::backend::{
    validate_replication_page_owned, validate_replication_prefix_owned, BackendInstanceIdentity,
    BackendPeerBinding, CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp,
    SessionBackend, SessionOp, SessionOpResult, WATCH_CHANNEL_CAPACITY,
};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::error::{LeaseError, StoreError};
use opc_session_store::lease::{LeaseGuard, SessionLeaseManager};
use opc_session_store::model::{OwnerId, SessionKey};

use opc_session_store::record::StoredSessionRecord;
use opc_session_store::{
    validate_session_ttl, ReplicaId, ReplicaReadinessFailure, RestoreScanCursorProfile,
    RestoreScanPage, RestoreScanRequest,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub use crate::consensus::RemoteAddrResolver;
use crate::error::ProtocolError;
use crate::identity::RemoteReplicaBinding;
use crate::protocol::{
    bounded_session_op_expectations, checked_frame_size, checked_wire_frame_size,
    compare_and_set_result_matches_key, conservative_payload_budget, get_result_matches_key,
    read_frame, read_response_frame, session_op_results_match_expectations,
    validate_request_payload_limit, validate_request_profile, write_frame_bounded_until,
    BootstrapHello, BootstrapRequest, BootstrapResponse, ContractProfile, Request, Response,
    RestoreScanWireRequest, CONTRACT_VERSION, CURRENT_CONTRACT_PROFILE, DEFAULT_MAX_FRAME_SIZE,
    MAX_HANDSHAKE_FRAME_SIZE, MAX_SESSION_NET_BATCH_OPERATIONS, MAX_SESSION_NET_REBUILD_ENTRIES,
    MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES, MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
    SESSION_NET_ALPN,
};

/// Persistent transport connection to a remote session backend.
///
/// The client keeps a single connection and allows one in-flight request at
/// a time; clones of [`RemoteSessionBackend`] share this connection.
struct Connection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    authenticated_peer: Option<ReplicaId>,
    contract_profile: ContractProfile,
    frame_limits: NegotiatedFrameLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NegotiatedFrameLimits {
    response_frame_size: usize,
    request_frame_size: usize,
}

#[derive(Debug)]
struct NegotiatedResponse {
    response: Response,
    contract_profile: ContractProfile,
    frame_limits: NegotiatedFrameLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteRequestFailure {
    Transport,
    Authentication,
    Timeout,
    Protocol,
    Backend,
    PayloadTooLarge { actual: usize, max: usize },
}

impl RemoteRequestFailure {
    fn from_protocol_error(error: &ProtocolError) -> Self {
        match error {
            ProtocolError::Io(error) if error.kind() == io::ErrorKind::TimedOut => Self::Timeout,
            ProtocolError::Io(_) => Self::Transport,
            ProtocolError::Authentication => Self::Authentication,
            ProtocolError::BackendUnavailable(_) => Self::Backend,
            ProtocolError::FrameTooLarge(_)
            | ProtocolError::VersionMismatch { .. }
            | ProtocolError::ContractMismatch
            | ProtocolError::InvalidWireValue
            | ProtocolError::UnexpectedResponse
            | ProtocolError::Serialization(_) => Self::Protocol,
        }
    }

    const fn is_retryable(self) -> bool {
        matches!(self, Self::Transport | Self::Timeout | Self::Backend)
    }

    const fn reason_code(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Authentication => "authentication",
            Self::Timeout => "timeout",
            Self::Protocol => "protocol",
            Self::Backend => "backend",
            Self::PayloadTooLarge { .. } => "payload_too_large",
        }
    }

    fn from_store_preflight(error: StoreError) -> Self {
        match error {
            StoreError::PayloadTooLarge { actual, max } => Self::PayloadTooLarge { actual, max },
            _ => Self::Protocol,
        }
    }
}

fn invalidates_negotiated_contract(error: &ProtocolError) -> bool {
    matches!(
        error,
        ProtocolError::Authentication
            | ProtocolError::VersionMismatch { .. }
            | ProtocolError::ContractMismatch
            | ProtocolError::InvalidWireValue
            | ProtocolError::UnexpectedResponse
            | ProtocolError::FrameTooLarge(_)
            | ProtocolError::Serialization(_)
    )
}

const fn unavailable_capabilities() -> BackendCapabilities {
    BackendCapabilities {
        atomic_compare_and_set: false,
        monotonic_fencing_token: false,
        per_key_ttl: false,
        server_side_lease_expiry: false,
        ordered_replication_log: false,
        batch_write: false,
        watch: false,
        restore_scan: false,
        max_value_bytes: 0,
    }
}

const REMOTE_PROTOCOL_VIOLATION: &str =
    "remote session backend response violated the protocol contract";

fn classify_tls_connect_error(error: io::Error) -> ProtocolError {
    if let Some(rustls_error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<tokio_rustls::rustls::Error>())
    {
        return match rustls_error {
            tokio_rustls::rustls::Error::NoApplicationProtocol
            | tokio_rustls::rustls::Error::AlertReceived(
                tokio_rustls::rustls::AlertDescription::NoApplicationProtocol,
            ) => ProtocolError::UnexpectedResponse,
            _ => ProtocolError::Authentication,
        };
    }
    ProtocolError::Io(error)
}

impl From<RemoteRequestFailure> for ReplicaReadinessFailure {
    fn from(failure: RemoteRequestFailure) -> Self {
        match failure {
            RemoteRequestFailure::Transport => Self::Transport,
            RemoteRequestFailure::Authentication => Self::Authentication,
            RemoteRequestFailure::Timeout => Self::Timeout,
            RemoteRequestFailure::Protocol => Self::Protocol,
            RemoteRequestFailure::Backend => Self::Backend,
            RemoteRequestFailure::PayloadTooLarge { .. } => Self::Protocol,
        }
    }
}

#[derive(Clone)]
enum RemoteTarget {
    #[cfg(feature = "insecure-test")]
    Pinned(SocketAddr),
    Resolved {
        server_name: Option<Arc<str>>,
        resolve: RemoteAddrResolver,
    },
}

impl RemoteTarget {
    #[cfg(feature = "insecure-test")]
    fn pinned(addr: SocketAddr) -> Self {
        Self::Pinned(addr)
    }

    fn resolved(server_name: Option<String>, resolve: RemoteAddrResolver) -> Self {
        Self::Resolved {
            server_name: server_name.map(Arc::<str>::from),
            resolve,
        }
    }

    fn configured(binding: &RemoteReplicaBinding) -> Self {
        let endpoint = binding.remote_endpoint();
        let server_name = endpoint.host().to_string();
        let host = Arc::<str>::from(endpoint.host());
        let port = endpoint.port();
        let resolve: RemoteAddrResolver = Arc::new(move || {
            let host = host.clone();
            Box::pin(async move {
                let mut addresses = tokio::net::lookup_host((host.as_ref(), port)).await?;
                addresses.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "replica endpoint did not resolve")
                })
            })
        });
        Self::resolved(Some(server_name), resolve)
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
    ) -> Result<rustls_pki_types::ServerName<'static>, ProtocolError> {
        match self {
            #[cfg(feature = "insecure-test")]
            Self::Pinned(_) => Ok(rustls_pki_types::ServerName::IpAddress(
                resolved_addr.ip().into(),
            )),
            Self::Resolved {
                server_name: Some(server_name),
                ..
            } => rustls_pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|_| ProtocolError::Authentication),
            Self::Resolved {
                server_name: None, ..
            } => Ok(rustls_pki_types::ServerName::IpAddress(
                resolved_addr.ip().into(),
            )),
        }
    }
}

impl std::fmt::Debug for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RemoteTarget(<redacted>)")
    }
}

impl std::fmt::Display for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted-target>")
    }
}

fn session_client_tls_config(
    config: &opc_tls::AuthenticatedClientConfig,
) -> Arc<opc_tls::ClientConfig> {
    let mut config = config.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    // Session identity is defined by the certificate presented on this exact
    // connection. A resumed TLS session can carry cached peer certificates and
    // skip verification of a rotated SVID, so replication deliberately pays
    // for a full mutually authenticated handshake on every reconnect.
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Arc::new(config)
}

async fn open_connection(
    target: RemoteTarget,
    tls_config: Option<Arc<opc_tls::ClientConfig>>,
    binding: RemoteReplicaBinding,
    requested_response_frame_size: usize,
    operation_deadline: tokio::time::Instant,
) -> Result<Connection, ProtocolError> {
    // Reject unrepresentable or unusably small local budgets before DNS or a
    // socket allocation. The handshake repeats this conversion when building
    // the fixed-width field, keeping direct callers fail closed as well.
    checked_wire_frame_size(requested_response_frame_size)?;
    let addr = target.resolve().await.map_err(ProtocolError::Io)?;
    let tcp = TcpStream::connect(addr).await.map_err(ProtocolError::Io)?;

    if let Some(tls_config) = tls_config {
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name = target.tls_server_name(addr)?;
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(classify_tls_connect_error)?;
        if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_NET_ALPN) {
            return Err(ProtocolError::UnexpectedResponse);
        }
        let peer_spiffe = opc_tls::peer_spiffe_id_from_client_connection(tls_stream.get_ref().1)
            .map_err(|_| ProtocolError::Authentication)?;
        if peer_spiffe.as_str() != binding.remote_spiffe_id().as_str() {
            return Err(ProtocolError::Authentication);
        }

        let (mut reader, mut writer) = tokio::io::split(tls_stream);
        let (contract_profile, frame_limits) = perform_client_handshake(
            &mut reader,
            &mut writer,
            &binding,
            requested_response_frame_size,
            operation_deadline,
        )
        .await?;
        Ok(Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            authenticated_peer: Some(binding.remote_replica_id().clone()),
            contract_profile,
            frame_limits,
        })
    } else {
        let (mut reader, mut writer) = tokio::io::split(tcp);
        let (contract_profile, frame_limits) = perform_client_handshake(
            &mut reader,
            &mut writer,
            &binding,
            requested_response_frame_size,
            operation_deadline,
        )
        .await?;
        Ok(Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            authenticated_peer: None,
            contract_profile,
            frame_limits,
        })
    }
}

async fn perform_client_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    binding: &RemoteReplicaBinding,
    requested_response_frame_size: usize,
    operation_deadline: tokio::time::Instant,
) -> Result<(ContractProfile, NegotiatedFrameLimits), ProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let handshake_nonce = uuid::Uuid::new_v4();
    let configuration_id = binding.configuration_id().to_hex();
    let requested_response_frame_size = checked_wire_frame_size(requested_response_frame_size)?;
    write_frame_bounded_until(
        writer,
        &BootstrapRequest::Hello(BootstrapHello {
            contract_version: CONTRACT_VERSION,
            node_id: binding.local_replica_id().as_str().to_string(),
            expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_string()),
            cluster_id: Some(binding.cluster_id().as_str().to_string()),
            configuration_id: Some(configuration_id.clone()),
            handshake_nonce: Some(handshake_nonce),
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
            requested_response_frame_size: Some(requested_response_frame_size),
        }),
        MAX_HANDSHAKE_FRAME_SIZE,
        operation_deadline,
    )
    .await?;

    let ack: BootstrapResponse = read_frame(reader, MAX_HANDSHAKE_FRAME_SIZE).await?;
    match ack {
        BootstrapResponse::HelloAck(ack) => {
            if ack.contract_version != CONTRACT_VERSION {
                return Err(ProtocolError::VersionMismatch {
                    local: CONTRACT_VERSION,
                    remote: ack.contract_version,
                });
            }
            if ack.contract_profile != Some(CURRENT_CONTRACT_PROFILE) {
                return Err(ProtocolError::ContractMismatch);
            }
            let identity_matches = ack.server_replica_id.as_deref()
                == Some(binding.remote_replica_id().as_str())
                && ack.accepted_client_replica_id.as_deref()
                    == Some(binding.local_replica_id().as_str())
                && ack.cluster_id.as_deref() == Some(binding.cluster_id().as_str())
                && ack.configuration_id.as_deref() == Some(configuration_id.as_str());
            if !identity_matches {
                return Err(ProtocolError::Authentication);
            }
            if ack.handshake_nonce != Some(handshake_nonce) {
                return Err(ProtocolError::UnexpectedResponse);
            }
            let accepted_response_frame_size = checked_frame_size(
                ack.accepted_response_frame_size
                    .ok_or(ProtocolError::ContractMismatch)?,
            )?;
            if accepted_response_frame_size > checked_frame_size(requested_response_frame_size)? {
                return Err(ProtocolError::ContractMismatch);
            }
            let request_frame_size = checked_frame_size(
                ack.server_request_frame_size
                    .ok_or(ProtocolError::ContractMismatch)?,
            )?
            .min(checked_frame_size(requested_response_frame_size)?);
            Ok((
                CURRENT_CONTRACT_PROFILE,
                NegotiatedFrameLimits {
                    response_frame_size: accepted_response_frame_size,
                    request_frame_size,
                },
            ))
        }
        BootstrapResponse::HelloRejected { .. } => Err(ProtocolError::Authentication),
    }
}

fn discard_replication_payloads_from_response(response: Response) {
    match response {
        Response::GetReplicationLog(Ok(entries)) => {
            entries
                .into_iter()
                .for_each(discard_replication_entry_iteratively);
        }
        Response::WatchEntry(Ok(entry)) => {
            discard_replication_entry_iteratively(entry);
        }
        _ => {}
    }
}

fn discard_replication_entry_iteratively(entry: ReplicationEntry) {
    let ReplicationEntry { op, .. } = entry;
    let mut pending = vec![vec![op].into_iter()];
    while let Some(current) = pending.last_mut() {
        match current.next() {
            Some(ReplicationOp::Batch { ops }) => pending.push(ops.into_iter()),
            Some(_) => {}
            None => {
                pending.pop();
            }
        }
    }
}

/// Remote session backend client.
#[derive(Clone)]
pub struct RemoteSessionBackend {
    target: RemoteTarget,
    tls_config: Option<Arc<opc_tls::ClientConfig>>,
    binding: RemoteReplicaBinding,
    deadline: Duration,
    max_frame_size: usize,
    conn: Arc<Mutex<Option<Connection>>>,
    negotiated_frame_limits: Arc<RwLock<Option<NegotiatedFrameLimits>>>,
    cached_capabilities:
        Arc<RwLock<Option<(ContractProfile, NegotiatedFrameLimits, BackendCapabilities)>>>,
}

impl std::fmt::Debug for RemoteSessionBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSessionBackend")
            .field("target", &self.target)
            .field("tls_config", &self.tls_config.is_some())
            .field("deadline", &self.deadline)
            .field("max_frame_size", &self.max_frame_size)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl RemoteSessionBackend {
    /// Create a new mTLS remote backend client.
    ///
    /// `binding` supplies the exact local and remote replica IDs, expected peer
    /// SPIFFE identity, dial endpoint, and cluster/configuration scope. The
    /// endpoint may resolve to different addresses across reconnects, but every
    /// new connection revalidates the same authenticated member identity.
    /// Session resumption and early data are disabled so a reconnect must
    /// present and verify the peer's current certificate.
    ///
    /// `deadline` bounds every backend method end-to-end, including connection
    /// retries with backoff (default 2s when `None`). On expiry the method
    /// returns the store's unavailable error so a quorum layer treats this
    /// replica as offline instead of stalling.
    pub fn new(
        binding: RemoteReplicaBinding,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let target = RemoteTarget::configured(&binding);
        Self::from_transport(
            target,
            Some(session_client_tls_config(&tls_config)),
            binding,
            deadline,
        )
    }

    /// Create a new mTLS remote backend client that re-resolves before each
    /// new connection.
    ///
    /// Existing live connections are reused. When a connection is dropped,
    /// the next retry calls `resolve` and connects to the returned address.
    /// TLS routing keeps using the binding endpoint as `server_name`; neither
    /// that name nor the resolved IP can replace the binding's expected
    /// `ReplicaId` and certificate SPIFFE identity.
    pub fn new_with_resolver(
        binding: RemoteReplicaBinding,
        resolve: RemoteAddrResolver,
        tls_config: opc_tls::AuthenticatedClientConfig,
        deadline: Option<Duration>,
    ) -> Self {
        let server_name = binding.remote_endpoint().host().to_string();
        Self::from_transport(
            RemoteTarget::resolved(Some(server_name), resolve),
            Some(session_client_tls_config(&tls_config)),
            binding,
            deadline,
        )
    }

    /// Create a plaintext remote backend client for tests.
    ///
    /// Production replication clients must use [`RemoteSessionBackend::new`].
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(addr: SocketAddr, deadline: Option<Duration>) -> Self {
        Self::from_transport(
            RemoteTarget::pinned(addr),
            None,
            crate::identity::insecure_test_client_binding(),
            deadline,
        )
    }

    /// Create a plaintext remote backend client with re-resolution for tests.
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure_with_resolver(
        resolve: RemoteAddrResolver,
        deadline: Option<Duration>,
    ) -> Self {
        Self::from_transport(
            RemoteTarget::resolved(None, resolve),
            None,
            crate::identity::insecure_test_client_binding(),
            deadline,
        )
    }

    fn from_transport(
        target: RemoteTarget,
        tls_config: Option<Arc<opc_tls::ClientConfig>>,
        binding: RemoteReplicaBinding,
        deadline: Option<Duration>,
    ) -> Self {
        Self {
            target,
            tls_config,
            binding,
            deadline: deadline.unwrap_or(Duration::from_secs(2)),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            conn: Arc::new(Mutex::new(None)),
            negotiated_frame_limits: Arc::new(RwLock::new(None)),
            cached_capabilities: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the local request bound and requested response-frame budget.
    ///
    /// The effective request limit is the smaller of this value and the
    /// server's acknowledged request budget. Values below
    /// [`crate::MIN_NEGOTIATED_FRAME_SIZE`] or above
    /// [`crate::MAX_NEGOTIATED_FRAME_SIZE`] fail before DNS or socket
    /// allocation.
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        // `max_frame_size` is clone-local, so this configured value must not
        // reuse connection or negotiation state created by another clone.
        self.conn = Arc::new(Mutex::new(None));
        self.negotiated_frame_limits = Arc::new(RwLock::new(None));
        self.cached_capabilities = Arc::new(RwLock::new(None));
        self
    }

    async fn send_request_classified(
        &self,
        req: Request,
    ) -> Result<NegotiatedResponse, RemoteRequestFailure> {
        validate_request_profile(&req).map_err(|_| RemoteRequestFailure::Protocol)?;
        validate_request_payload_limit(&req, conservative_payload_budget(self.max_frame_size))
            .map_err(RemoteRequestFailure::from_store_preflight)?;
        let operation_deadline = tokio::time::Instant::now()
            .checked_add(self.deadline)
            .ok_or(RemoteRequestFailure::Protocol)?;
        let mut last_failure = None;
        let mut request_in_flight = true;
        let attempts = async {
            let mut backoff_ms = 100u64;
            loop {
                request_in_flight = true;
                match self.do_request(&req, operation_deadline).await {
                    Ok(resp) => return Ok(resp),
                    Err(failure) => {
                        if !failure.is_retryable() {
                            return Err(failure);
                        }
                        last_failure = Some(failure);
                        request_in_flight = false;
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(1000);
                    }
                }
            }
        };
        match tokio::time::timeout_at(operation_deadline, attempts).await {
            Ok(res) => res,
            Err(_) if request_in_flight => Err(RemoteRequestFailure::Timeout),
            Err(_) => Err(last_failure.unwrap_or(RemoteRequestFailure::Timeout)),
        }
    }

    async fn send_request_with_retry(&self, req: Request) -> Result<Response, StoreError> {
        self.send_request_with_retry_negotiated(req)
            .await
            .map(|response| response.response)
    }

    async fn send_request_with_retry_negotiated(
        &self,
        req: Request,
    ) -> Result<NegotiatedResponse, StoreError> {
        self.send_request_classified(req)
            .await
            .map_err(|failure| match failure {
                RemoteRequestFailure::PayloadTooLarge { actual, max } => {
                    StoreError::PayloadTooLarge { actual, max }
                }
                _ => StoreError::BackendUnavailable(format!(
                    "remote session backend request failed: {}",
                    failure.reason_code()
                )),
            })
    }

    async fn send_lease_request_with_retry(&self, req: Request) -> Result<Response, LeaseError> {
        self.send_request_with_retry(req)
            .await
            .map_err(|e| LeaseError::Backend(e.to_string()))
    }

    async fn do_request(
        &self,
        req: &Request,
        operation_deadline: tokio::time::Instant,
    ) -> Result<NegotiatedResponse, RemoteRequestFailure> {
        let mut guard = self.conn.lock().await;

        // Take the connection out of the slot for the duration of the
        // exchange. If this future is cancelled mid-exchange (the per-call
        // deadline can fire between writing a request and reading its
        // response), a connection left in the slot would deliver the stale
        // response of the cancelled request to the next caller; taking it
        // means cancellation drops the connection and the next request
        // reconnects cleanly. Errors drop it for the same reason.
        let mut conn = match guard.take() {
            Some(conn) => conn,
            None => self
                .connect(operation_deadline)
                .await
                .map_err(|error| RemoteRequestFailure::from_protocol_error(&error))?,
        };

        let transport_limit = conservative_payload_budget(conn.frame_limits.request_frame_size)
            .min(conservative_payload_budget(
                conn.frame_limits.response_frame_size,
            ));
        if let Err(error) = validate_request_payload_limit(req, transport_limit) {
            *guard = Some(conn);
            return Err(RemoteRequestFailure::from_store_preflight(error));
        }

        match self.exchange(req, &mut conn, operation_deadline).await {
            Ok(resp) => {
                let response = NegotiatedResponse {
                    response: resp,
                    contract_profile: conn.contract_profile,
                    frame_limits: conn.frame_limits,
                };
                *guard = Some(conn);
                Ok(response)
            }
            Err(error) => {
                if invalidates_negotiated_contract(&error) {
                    self.clear_cached_capabilities();
                }
                Err(RemoteRequestFailure::from_protocol_error(&error))
            }
        }
    }

    async fn connect(
        &self,
        operation_deadline: tokio::time::Instant,
    ) -> Result<Connection, ProtocolError> {
        let result = open_connection(
            self.target.clone(),
            self.tls_config.clone(),
            self.binding.clone(),
            self.max_frame_size,
            operation_deadline,
        )
        .await;
        if let Ok(connection) = &result {
            let changed = self
                .negotiated_frame_limits()
                .is_some_and(|limits| limits != connection.frame_limits);
            if changed {
                self.clear_cached_capabilities();
            }
            if let Ok(mut limits) = self.negotiated_frame_limits.write() {
                *limits = Some(connection.frame_limits);
            }
        }
        if result.as_ref().is_err_and(invalidates_negotiated_contract) {
            self.clear_cached_capabilities();
        }
        result
    }

    async fn exchange(
        &self,
        req: &Request,
        conn: &mut Connection,
        operation_deadline: tokio::time::Instant,
    ) -> Result<Response, ProtocolError> {
        if self.tls_config.is_some()
            && conn.authenticated_peer.as_ref() != Some(self.binding.remote_replica_id())
        {
            return Err(ProtocolError::Authentication);
        }
        if conn.contract_profile != CURRENT_CONTRACT_PROFILE {
            return Err(ProtocolError::ContractMismatch);
        }
        write_frame_bounded_until(
            &mut conn.writer,
            req,
            conn.frame_limits.request_frame_size,
            operation_deadline,
        )
        .await?;
        read_response_frame(&mut conn.reader, conn.frame_limits.response_frame_size).await
    }

    fn remember_capabilities(
        &self,
        contract_profile: ContractProfile,
        frame_limits: NegotiatedFrameLimits,
        caps: BackendCapabilities,
    ) {
        if let Ok(mut cached) = self.cached_capabilities.write() {
            *cached = Some((contract_profile, frame_limits, caps));
        }
    }

    fn clear_cached_capabilities(&self) {
        if let Ok(mut cached) = self.cached_capabilities.write() {
            *cached = None;
        }
    }

    fn negotiated_frame_limits(&self) -> Option<NegotiatedFrameLimits> {
        self.negotiated_frame_limits
            .read()
            .ok()
            .and_then(|limits| *limits)
    }

    fn cached_capabilities(
        &self,
    ) -> Option<(ContractProfile, NegotiatedFrameLimits, BackendCapabilities)> {
        let frame_limits = self.negotiated_frame_limits()?;
        self.cached_capabilities
            .read()
            .ok()
            .and_then(|cached| *cached)
            .filter(|(profile, cached_limits, _)| {
                *profile == CURRENT_CONTRACT_PROFILE && *cached_limits == frame_limits
            })
    }

    fn capabilities_for_transport(
        mut caps: BackendCapabilities,
        fresh_v4_negotiation: bool,
        contract_profile: ContractProfile,
        frame_limits: NegotiatedFrameLimits,
    ) -> BackendCapabilities {
        if contract_profile != CURRENT_CONTRACT_PROFILE {
            return unavailable_capabilities();
        }
        let response_frame_size = frame_limits.response_frame_size;
        caps.max_value_bytes = caps
            .max_value_bytes
            .min(conservative_payload_budget(response_frame_size));
        let request_frame_size = frame_limits.request_frame_size;
        caps.max_value_bytes = caps
            .max_value_bytes
            .min(conservative_payload_budget(request_frame_size));
        if !fresh_v4_negotiation || response_frame_size < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
            caps.restore_scan = false;
        }
        caps
    }

    fn capabilities_after_probe_failure(&self, reason: &str) -> BackendCapabilities {
        if let Some((contract_profile, frame_limits, caps)) = self.cached_capabilities() {
            tracing::warn!(
                target = %self.target,
                reason,
                "remote capabilities probe failed; using cached capabilities with negotiated operations masked"
            );
            Self::capabilities_for_transport(caps, false, contract_profile, frame_limits)
        } else {
            tracing::warn!(
                target = %self.target,
                reason,
                "remote capabilities probe failed before any cached success; returning unavailable capabilities"
            );
            unavailable_capabilities()
        }
    }

    async fn discard_connection(&self) {
        self.conn.lock().await.take();
    }

    async fn store_protocol_violation(&self, response: Response) -> StoreError {
        discard_replication_payloads_from_response(response);
        self.discard_connection().await;
        self.clear_cached_capabilities();
        StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
    }

    async fn lease_protocol_violation(&self, response: Response) -> LeaseError {
        discard_replication_payloads_from_response(response);
        self.discard_connection().await;
        self.clear_cached_capabilities();
        LeaseError::Backend(REMOTE_PROTOCOL_VIOLATION.to_string())
    }

    async fn readiness_protocol_violation(&self, response: Response) -> ReplicaReadinessFailure {
        discard_replication_payloads_from_response(response);
        self.discard_connection().await;
        self.clear_cached_capabilities();
        ReplicaReadinessFailure::Protocol
    }
}

#[async_trait]
impl SessionBackend for RemoteSessionBackend {
    fn restore_scan_cursor_profile(&self) -> Option<RestoreScanCursorProfile> {
        Some(RestoreScanCursorProfile::DurableOpaqueV1)
    }

    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.conn))
    }

    fn peer_binding(&self) -> Option<BackendPeerBinding> {
        self.tls_config
            .as_ref()
            .map(|_| self.binding.backend_peer_binding())
    }

    async fn capabilities(&self) -> BackendCapabilities {
        match self
            .send_request_with_retry_negotiated(Request::Capabilities)
            .await
        {
            Ok(NegotiatedResponse {
                response: Response::Capabilities(caps),
                contract_profile,
                frame_limits,
            }) => {
                let caps =
                    Self::capabilities_for_transport(caps, true, contract_profile, frame_limits);
                self.remember_capabilities(contract_profile, frame_limits, caps);
                caps
            }
            Ok(NegotiatedResponse { response, .. }) => {
                discard_replication_payloads_from_response(response);
                self.discard_connection().await;
                self.clear_cached_capabilities();
                tracing::warn!(
                    target = %self.target,
                    reason = "unexpected_response",
                    "remote capabilities probe violated the negotiated contract; returning unavailable capabilities"
                );
                unavailable_capabilities()
            }
            Err(err) => {
                let reason = store_error_kind(&err);
                self.capabilities_after_probe_failure(reason)
            }
        }
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        match self
            .send_request_with_retry(Request::Get { key: key.clone() })
            .await?
        {
            Response::Get(res) if get_result_matches_key(key, &res) => res,
            Response::Get(res) => Err(self.store_protocol_violation(Response::Get(res)).await),
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let expected_key = op.key.clone();
        match self
            .send_request_with_retry(Request::CompareAndSet {
                op,
                request_id: Some(uuid::Uuid::new_v4().to_string()),
            })
            .await?
        {
            Response::CompareAndSet(res)
                if compare_and_set_result_matches_key(&expected_key, &res) =>
            {
                res
            }
            Response::CompareAndSet(res) => Err(self
                .store_protocol_violation(Response::CompareAndSet(res))
                .await),
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        match self
            .send_request_with_retry(Request::DeleteFenced {
                lease: lease.clone(),
            })
            .await?
        {
            Response::DeleteFenced(res) => res,
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        match self
            .send_request_with_retry(Request::RefreshTtl {
                lease: lease.clone(),
                ttl,
            })
            .await?
        {
            Response::RefreshTtl(res) => res,
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        if ops.len() > MAX_SESSION_NET_BATCH_OPERATIONS {
            return Err(StoreError::ReplicationOperationLimitExceeded);
        }
        for op in &ops {
            op.validate_ttls()?;
        }
        let expected = bounded_session_op_expectations(&ops)?;
        match self.send_request_with_retry(Request::Batch { ops }).await? {
            Response::Batch(Ok(results))
                if session_op_results_match_expectations(&expected, &results) =>
            {
                Ok(results)
            }
            Response::Batch(Ok(results)) => {
                drop(results);
                self.discard_connection().await;
                self.clear_cached_capabilities();
                Err(StoreError::BackendUnavailable(
                    "remote batch response violated the protocol contract".to_string(),
                ))
            }
            Response::Batch(Err(error)) => Err(error),
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        request.validate()?;
        if request
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.is_legacy_compatibility())
        {
            return Err(StoreError::CapabilityNotSupported(
                "legacy_remote_restore_scan".to_string(),
            ));
        }
        if self.max_frame_size < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
            return Err(StoreError::RestoreScanResponseTooLarge {
                max_bytes: self.max_frame_size,
            });
        }
        let wire_request = RestoreScanWireRequest::try_from(&request)?;
        let max_response_frame_size =
            checked_wire_frame_size(self.max_frame_size).map_err(|_| {
                StoreError::InvalidRestoreScanRequest(
                    "configured response frame size is outside the negotiated range".to_string(),
                )
            })?;
        let outbound = Request::ScanRestoreRecords {
            request: wire_request,
            max_response_frame_size,
        };
        let response = match self.send_request_with_retry(outbound).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    target = %self.target,
                    failure = store_error_kind(&error),
                    "remote restore scan failed"
                );
                return Err(error);
            }
        };

        match response {
            Response::ScanRestoreRecords(Ok(page)) => {
                if page.cursor_profile != RestoreScanCursorProfile::DurableOpaqueV1 {
                    self.discard_connection().await;
                    self.clear_cached_capabilities();
                    return Err(StoreError::CapabilityNotSupported(
                        "legacy_remote_restore_scan".to_string(),
                    ));
                }
                if let Err(error) = page.validate_for_request(&request) {
                    self.discard_connection().await;
                    self.clear_cached_capabilities();
                    tracing::warn!(
                        target = %self.target,
                        failure = store_error_kind(&error),
                        "remote restore scan response was rejected"
                    );
                    return Err(error);
                }
                Ok(page)
            }
            Response::ScanRestoreRecords(Err(error)) => {
                tracing::warn!(
                    target = %self.target,
                    failure = store_error_kind(&error),
                    "remote restore scan failed"
                );
                Err(error)
            }
            response => {
                tracing::warn!(
                    target = %self.target,
                    failure = "unexpected_response",
                    "remote restore scan response was rejected"
                );
                Err(self.store_protocol_violation(response).await)
            }
        }
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        match self
            .send_request_with_retry(Request::MaxReplicationSequence)
            .await?
        {
            Response::MaxReplicationSequence(res) => res,
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn probe_replication_head(&self) -> Result<u64, ReplicaReadinessFailure> {
        let response = self
            .send_request_classified(Request::MaxReplicationSequence)
            .await
            .map_err(ReplicaReadinessFailure::from)?;
        match response.response {
            Response::MaxReplicationSequence(Ok(sequence)) => Ok(sequence),
            Response::MaxReplicationSequence(Err(_)) => Err(ReplicaReadinessFailure::Backend),
            response => Err(self.readiness_protocol_violation(response).await),
        }
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        if limit > MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES {
            return Err(StoreError::ReplicationOperationLimitExceeded);
        }
        match self
            .send_request_with_retry(Request::GetReplicationLog { start, limit })
            .await?
        {
            Response::GetReplicationLog(res) => {
                let entries = res?;
                if entries.len() > limit {
                    drop(validate_replication_page_owned(entries));
                    self.discard_connection().await;
                    self.clear_cached_capabilities();
                    return Err(StoreError::BackendUnavailable(
                        "remote replication page violated the protocol contract".to_string(),
                    ));
                }
                match validate_replication_page_owned(entries) {
                    Ok(entries) => Ok(entries),
                    Err(error) => {
                        self.discard_connection().await;
                        self.clear_cached_capabilities();
                        Err(error)
                    }
                }
            }
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        match self
            .send_request_with_retry(Request::ReplicateEntry { entry })
            .await?
        {
            Response::ReplicateEntry(res) => res,
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        if entries.len() > MAX_SESSION_NET_REBUILD_ENTRIES {
            return Err(StoreError::ReplicationOperationLimitExceeded);
        }
        let entries = validate_replication_prefix_owned(entries)?;
        match self
            .send_request_with_retry(Request::RebuildReplicationState { entries })
            .await?
        {
            Response::RebuildReplicationState(res) => res,
            response => Err(self.store_protocol_violation(response).await),
        }
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<BoxStream<'static, Result<ReplicationEntry, StoreError>>, StoreError> {
        checked_wire_frame_size(self.max_frame_size).map_err(|_| {
            StoreError::BackendUnavailable(
                "remote watch frame size is outside the negotiated range".to_string(),
            )
        })?;
        tokio::time::Instant::now()
            .checked_add(self.deadline)
            .ok_or_else(|| {
                StoreError::BackendUnavailable(
                    "remote watch deadline is not representable".to_string(),
                )
            })?;
        let target = self.target.clone();
        let tls_config = self.tls_config.clone();
        let max_frame_size = self.max_frame_size;
        let binding = self.binding.clone();
        let deadline = self.deadline;

        let (tx, rx) = tokio::sync::mpsc::channel(WATCH_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let result = watch_connect_and_read(
                target,
                tls_config,
                max_frame_size,
                binding,
                start_sequence,
                deadline,
                tx,
            )
            .await;
            if let Err(e) = result {
                tracing::debug!(
                    failure = RemoteRequestFailure::from_protocol_error(&e).reason_code(),
                    "watch stream ended"
                );
            }
        });

        Ok(Box::pin(WatchStream { rx }))
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        match self.send_request_with_retry(Request::NextLeaseInfo).await? {
            Response::NextLeaseInfo(res) => res,
            response => Err(self.store_protocol_violation(response).await),
        }
    }
}

#[async_trait]
impl SessionLeaseManager for RemoteSessionBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        let expected_owner = owner.clone();
        match self
            .send_lease_request_with_retry(Request::AcquireLease {
                key: key.clone(),
                owner,
                ttl,
            })
            .await?
        {
            Response::AcquireLease(Ok(lease))
                if lease.key() == key && lease.owner() == &expected_owner =>
            {
                Ok(lease)
            }
            Response::AcquireLease(Err(error)) => Err(error),
            Response::AcquireLease(Ok(lease)) => Err(self
                .lease_protocol_violation(Response::AcquireLease(Ok(lease)))
                .await),
            response => Err(self.lease_protocol_violation(response).await),
        }
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        match self
            .send_lease_request_with_retry(Request::RenewLease {
                lease: lease.clone(),
                ttl,
            })
            .await?
        {
            Response::RenewLease(Ok(renewed))
                if renewed.key() == lease.key()
                    && renewed.owner() == lease.owner()
                    && renewed.fence() == lease.fence()
                    && renewed.credential_id() == lease.credential_id() =>
            {
                Ok(renewed)
            }
            Response::RenewLease(Err(error)) => Err(error),
            Response::RenewLease(Ok(renewed)) => Err(self
                .lease_protocol_violation(Response::RenewLease(Ok(renewed)))
                .await),
            response => Err(self.lease_protocol_violation(response).await),
        }
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        match self
            .send_lease_request_with_retry(Request::ReleaseLease { lease })
            .await?
        {
            Response::ReleaseLease(res) => res,
            response => Err(self.lease_protocol_violation(response).await),
        }
    }
}

async fn watch_connect_and_read(
    target: RemoteTarget,
    tls_config: Option<Arc<opc_tls::ClientConfig>>,
    max_frame_size: usize,
    binding: RemoteReplicaBinding,
    start_sequence: u64,
    deadline: Duration,
    tx: tokio::sync::mpsc::Sender<Result<ReplicationEntry, StoreError>>,
) -> Result<(), ProtocolError> {
    // Bound connect + handshake by the client deadline. After the handshake,
    // bounded channel sends backpressure socket reads when consumers lag.
    let operation_deadline = tokio::time::Instant::now()
        .checked_add(deadline)
        .ok_or(ProtocolError::InvalidWireValue)?;
    let open = async {
        let mut connection = open_connection(
            target,
            tls_config,
            binding,
            max_frame_size,
            operation_deadline,
        )
        .await?;
        let watch = Request::Watch { start_sequence };
        write_frame_bounded_until(
            &mut connection.writer,
            &watch,
            connection.frame_limits.request_frame_size,
            operation_deadline,
        )
        .await?;
        match read_response_frame(
            &mut connection.reader,
            connection.frame_limits.response_frame_size,
        )
        .await?
        {
            Response::WatchStream => Ok::<_, ProtocolError>((
                connection.reader,
                connection.frame_limits.response_frame_size,
            )),
            Response::Error { .. } => Err(ProtocolError::BackendUnavailable(
                "watch request rejected".to_string(),
            )),
            response => {
                discard_replication_payloads_from_response(response);
                Err(ProtocolError::UnexpectedResponse)
            }
        }
    };
    let (mut reader, response_frame_size) =
        match tokio::time::timeout_at(operation_deadline, open).await {
            Ok(res) => res?,
            Err(_) => {
                let _ = tx
                    .send(Err(StoreError::BackendUnavailable(
                        "remote session watch handshake timed out".to_string(),
                    )))
                    .await;
                return Err(ProtocolError::BackendUnavailable(
                    "watch handshake timed out".into(),
                ));
            }
        };

    loop {
        match read_response_frame(&mut reader, response_frame_size).await {
            Ok(Response::WatchEntry(item)) => {
                let item = item.and_then(ReplicationEntry::into_validated);
                if tx.send(item).await.is_err() {
                    break;
                }
            }
            Ok(response) => {
                discard_replication_payloads_from_response(response);
                let _ = tx
                    .send(Err(StoreError::BackendUnavailable(
                        "unexpected watch frame".into(),
                    )))
                    .await;
                break;
            }
            Err(ProtocolError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => {
                let reason = RemoteRequestFailure::from_protocol_error(&e).reason_code();
                let _ = tx
                    .send(Err(StoreError::BackendUnavailable(format!(
                        "remote session watch failed: {reason}"
                    ))))
                    .await;
                break;
            }
        }
    }

    Ok(())
}

fn store_error_kind(err: &StoreError) -> &'static str {
    match err {
        StoreError::NotFound => "not_found",
        StoreError::StaleFence => "stale_fence",
        StoreError::CasConflict => "cas_conflict",
        StoreError::CapabilityNotSupported(_) => "capability_not_supported",
        StoreError::BackendUnavailable(_) => "backend_unavailable",
        StoreError::InvalidKey(_) => "invalid_key",
        StoreError::InvalidReplicationSequence => "invalid_replication_sequence",
        StoreError::ReplicationOperationLimitExceeded => "replication_operation_limit_exceeded",
        StoreError::InvalidSessionTtl => "invalid_session_ttl",
        StoreError::LeaseHeld => "lease_held",
        StoreError::LeaseExpired => "lease_expired",
        StoreError::Crypto(_) => "crypto",
        StoreError::Serialization(_) => "serialization",
        StoreError::PayloadTooLarge { .. } => "payload_too_large",
        StoreError::InvalidRestoreScanRequest(_) => "invalid_restore_scan_request",
        StoreError::InvalidRestoreScanResponse(_) => "invalid_restore_scan_response",
        StoreError::RestoreScanPageTooLarge { .. } => "restore_scan_page_too_large",
        StoreError::RestoreScanCursorStale => "restore_scan_cursor_stale",
        StoreError::RestoreScanWorkBudgetExceeded => "restore_scan_work_budget_exceeded",
        StoreError::RestoreScanResponseTooLarge { .. } => "restore_scan_response_too_large",
    }
}

struct WatchStream {
    rx: tokio::sync::mpsc::Receiver<Result<ReplicationEntry, StoreError>>,
}

impl Stream for WatchStream {
    type Item = Result<ReplicationEntry, StoreError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

#[cfg(all(test, feature = "insecure-test"))]
mod tests {
    use super::*;
    use crate::protocol::write_frame;
    use futures_util::{FutureExt, StreamExt};
    use opc_session_store::{
        BackendCapabilities, EncryptedSessionPayload, FakeSessionBackend, FenceToken, Generation,
        StateClass, StateType, MAX_REPLICATION_OPERATIONS_PER_ENTRY,
        MAX_REPLICATION_OPERATION_DEPTH,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn successful_hello_ack(hello: &Request) -> Response {
        let requested = match hello {
            Request::Hello {
                requested_response_frame_size: Some(requested),
                ..
            } => *requested,
            _ => DEFAULT_MAX_FRAME_SIZE as u32,
        };
        hello_ack_with_limits(hello, requested, DEFAULT_MAX_FRAME_SIZE as u32)
    }

    fn hello_ack_with_limits(
        hello: &Request,
        accepted_response_frame_size: u32,
        server_request_frame_size: u32,
    ) -> Response {
        let Request::Hello {
            node_id,
            expected_server_replica_id,
            cluster_id,
            configuration_id,
            handshake_nonce,
            ..
        } = hello
        else {
            panic!("expected Hello request");
        };
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
            server_replica_id: expected_server_replica_id.clone(),
            accepted_client_replica_id: Some(node_id.clone()),
            cluster_id: cluster_id.clone(),
            configuration_id: configuration_id.clone(),
            handshake_nonce: *handshake_nonce,
            accepted_response_frame_size: Some(accepted_response_frame_size),
            server_request_frame_size: Some(server_request_frame_size),
        }
    }

    fn valid_deadline_entry() -> ReplicationEntry {
        let timestamp =
            opc_types::Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let expires_at = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH
                .checked_add(time::Duration::seconds(60))
                .expect("representable test deadline"),
        );
        ReplicationEntry {
            sequence: 1,
            tx_id: "forged-response-deadline".to_string(),
            op: opc_session_store::ReplicationOp::RefreshTtl {
                key: SessionKey {
                    tenant: opc_types::TenantId::new("tenant-a").expect("test tenant"),
                    nf_kind: opc_types::NetworkFunctionKind::from_static("smf"),
                    key_type: opc_session_store::SessionKeyType::PduSession,
                    stable_id: bytes::Bytes::from_static(b"forged-response"),
                },
                owner: OwnerId::new("forged-response-owner").expect("test owner"),
                fence: opc_session_store::FenceToken::new(1),
                ttl: Duration::from_secs(60),
                expires_at,
            },
            timestamp,
        }
    }

    async fn valid_compare_and_set(payload_len: usize) -> CompareAndSet {
        let backend = FakeSessionBackend::new();
        let key = match valid_deadline_entry().op {
            ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let owner = OwnerId::new("client-preflight-owner").expect("test owner");
        let lease = backend
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .expect("test lease");
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: FenceToken::new(lease.fence().get()),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("client-preflight").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(vec![7; payload_len]),
        };
        CompareAndSet {
            key,
            lease,
            expected_generation: None,
            new_record: record,
        }
    }

    fn forge_deadline_in_wire_response(
        mut response: serde_json::Value,
        entry_pointer: &str,
    ) -> serde_json::Value {
        let forged_expires_at = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH
                .checked_add(time::Duration::seconds(61))
                .expect("representable forged deadline"),
        );
        response
            .pointer_mut(entry_pointer)
            .expect("wire response entry")["operation_nodes"][0]["RefreshTtl"]["expires_at"] =
            serde_json::to_value(forged_expires_at).expect("serialize forged deadline");
        response
    }

    fn operation_tree_at_depth(depth: usize) -> opc_session_store::ReplicationOp {
        let mut op = opc_session_store::ReplicationOp::Batch { ops: Vec::new() };
        for _ in 1..depth {
            op = opc_session_store::ReplicationOp::Batch { ops: vec![op] };
        }
        op
    }

    fn replication_entry_at_depth(depth: usize) -> ReplicationEntry {
        ReplicationEntry {
            sequence: 1,
            tx_id: "over-depth-response".to_string(),
            op: operation_tree_at_depth(depth),
            timestamp: opc_types::Timestamp::now_utc(),
        }
    }

    fn replication_entry_at_operation_limit() -> ReplicationEntry {
        let ops = (1..MAX_REPLICATION_OPERATIONS_PER_ENTRY)
            .map(|_| opc_session_store::ReplicationOp::Batch { ops: Vec::new() })
            .collect();
        ReplicationEntry {
            sequence: 1,
            tx_id: "over-count-response".to_string(),
            op: opc_session_store::ReplicationOp::Batch { ops },
            timestamp: opc_types::Timestamp::now_utc(),
        }
    }

    async fn capability_server(
        caps: BackendCapabilities,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        capability_server_with_limits(
            caps,
            DEFAULT_MAX_FRAME_SIZE as u32,
            DEFAULT_MAX_FRAME_SIZE as u32,
        )
        .await
    }

    async fn capability_server_with_limits(
        caps: BackendCapabilities,
        accepted_response_frame_size: u32,
        server_request_frame_size: u32,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(
                    &hello,
                    accepted_response_frame_size,
                    server_request_frame_size,
                ),
            )
            .await
            .expect("write hello ack");

            let req: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read request");
            assert!(matches!(req, Request::Capabilities));
            write_frame(&mut stream, &Response::Capabilities(caps))
                .await
                .expect("write capabilities");
        });
        (addr, handle)
    }

    async fn warmed_malicious_response_server(
        response: Response,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malicious peer");
        let addr = listener.local_addr().expect("malicious peer address");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello acknowledgement");

            let capabilities: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read capabilities request");
            assert!(matches!(capabilities, Request::Capabilities));
            write_frame(
                &mut stream,
                &Response::Capabilities(BackendCapabilities::all_enabled()),
            )
            .await
            .expect("write capabilities response");

            let _: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read operation request");
            write_frame(&mut stream, &response)
                .await
                .expect("write malicious response");
        });
        (addr, handle)
    }

    async fn version_mismatch_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            assert!(matches!(hello, Request::Hello { .. }));
            write_frame(
                &mut stream,
                &Response::HelloAck {
                    contract_version: CONTRACT_VERSION - 1,
                    contract_profile: None,
                    server_replica_id: None,
                    accepted_client_replica_id: None,
                    cluster_id: None,
                    configuration_id: None,
                    handshake_nonce: None,
                    accepted_response_frame_size: None,
                    server_request_frame_size: None,
                },
            )
            .await
            .expect("write incompatible hello ack");
        });
        (addr, handle)
    }

    async fn legacy_close_without_ack_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            assert!(matches!(hello, Request::Hello { .. }));
            // Protocol v1 closed immediately when the peer version differed;
            // it did not send a HelloAck that disclosed its version.
        });
        (addr, handle)
    }

    async fn invalid_ack_server(stale_nonce: bool) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            let mut ack = successful_hello_ack(&hello);
            let Response::HelloAck {
                server_replica_id,
                handshake_nonce,
                ..
            } = &mut ack
            else {
                unreachable!("helper always returns HelloAck");
            };
            if stale_nonce {
                *handshake_nonce = Some(uuid::Uuid::nil());
            } else {
                *server_replica_id = Some("different-server".to_string());
            }
            write_frame(&mut stream, &ack)
                .await
                .expect("write invalid hello ack");
        });
        (addr, handle)
    }

    async fn contract_profile_mismatch_server(
        contract_profile: Option<ContractProfile>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            let mut ack = successful_hello_ack(&hello);
            let Response::HelloAck {
                contract_profile: accepted_profile,
                ..
            } = &mut ack
            else {
                unreachable!("helper always returns HelloAck");
            };
            *accepted_profile = contract_profile;
            write_frame(&mut stream, &ack)
                .await
                .expect("write incompatible hello ack");
        });
        (addr, handle)
    }

    async fn frame_limit_ack_server(
        accepted_response_frame_size: u32,
        server_request_frame_size: u32,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(
                    &hello,
                    accepted_response_frame_size,
                    server_request_frame_size,
                ),
            )
            .await
            .expect("write frame-limit acknowledgement");
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn hello_ack_enforces_profile_frame_boundaries() {
        let below_minimum = (crate::MIN_NEGOTIATED_FRAME_SIZE - 1) as u32;
        let minimum = crate::MIN_NEGOTIATED_FRAME_SIZE as u32;
        let maximum = crate::MAX_NEGOTIATED_FRAME_SIZE as u32;
        let over_ceiling = (crate::MAX_NEGOTIATED_FRAME_SIZE + 1) as u32;
        for (
            accepted_response_frame_size,
            server_request_frame_size,
            configured_frame_size,
            accepted,
        ) in [
            (
                below_minimum,
                DEFAULT_MAX_FRAME_SIZE as u32,
                DEFAULT_MAX_FRAME_SIZE,
                false,
            ),
            (
                DEFAULT_MAX_FRAME_SIZE as u32,
                below_minimum,
                DEFAULT_MAX_FRAME_SIZE,
                false,
            ),
            (minimum, minimum, crate::MIN_NEGOTIATED_FRAME_SIZE, true),
            (maximum, maximum, crate::MAX_NEGOTIATED_FRAME_SIZE, true),
            (
                over_ceiling,
                DEFAULT_MAX_FRAME_SIZE as u32,
                DEFAULT_MAX_FRAME_SIZE,
                false,
            ),
            (
                DEFAULT_MAX_FRAME_SIZE as u32,
                over_ceiling,
                DEFAULT_MAX_FRAME_SIZE,
                false,
            ),
        ] {
            let (addr, server) =
                frame_limit_ack_server(accepted_response_frame_size, server_request_frame_size)
                    .await;
            let deadline = tokio::time::Instant::now()
                .checked_add(Duration::from_secs(1))
                .expect("test deadline");
            match open_connection(
                RemoteTarget::pinned(addr),
                None,
                crate::identity::insecure_test_client_binding(),
                configured_frame_size,
                deadline,
            )
            .await
            {
                Ok(_) if accepted => {}
                Ok(_) => panic!("an out-of-profile HelloAck frame limit must fail closed"),
                Err(error) if accepted => {
                    panic!("an in-profile HelloAck frame limit must succeed: {error}")
                }
                Err(error) => assert!(matches!(error, ProtocolError::InvalidWireValue)),
            };
            server.await.expect("frame-limit server task");
        }
    }

    #[tokio::test]
    async fn resolver_backend_reconnects_to_changed_address() {
        let caps_a = BackendCapabilities::minimal();
        let mut expected_caps_a = caps_a;
        expected_caps_a.max_value_bytes = conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE);
        let caps_b = BackendCapabilities::all_enabled();
        let mut expected_caps_b = caps_b;
        expected_caps_b.max_value_bytes = conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE);
        let (addr_a, handle_a) = capability_server(caps_a).await;
        let (addr_b, handle_b) = capability_server(caps_b).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(addr_a)
                } else {
                    Ok(addr_b)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(2)),
        );

        assert_eq!(backend.capabilities().await, expected_caps_a);
        let _ = handle_a.await;

        assert_eq!(backend.capabilities().await, expected_caps_b);
        let _ = handle_b.await;
        assert!(calls.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn concurrent_capability_responses_keep_their_connection_limits_when_reordered() {
        let large = DEFAULT_MAX_FRAME_SIZE as u32;
        let small = MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE as u32;
        let (first_addr, first_server) =
            capability_server_with_limits(BackendCapabilities::all_enabled(), large, large).await;
        let (second_addr, second_server) =
            capability_server_with_limits(BackendCapabilities::all_enabled(), small, small).await;
        let resolves = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolves);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(first_addr)
                } else {
                    Ok(second_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(2)),
        );

        let (first, second) = tokio::join!(
            backend.send_request_classified(Request::Capabilities),
            backend.send_request_classified(Request::Capabilities)
        );
        let first = first.expect("first capability response");
        let second = second.expect("second capability response");
        let NegotiatedResponse {
            response: Response::Capabilities(first_caps),
            contract_profile: first_profile,
            frame_limits: first_limits,
        } = first
        else {
            panic!("first response family");
        };
        let NegotiatedResponse {
            response: Response::Capabilities(second_caps),
            contract_profile: second_profile,
            frame_limits: second_limits,
        } = second
        else {
            panic!("second response family");
        };

        assert_eq!(first_limits.response_frame_size, large as usize);
        assert_eq!(second_limits.response_frame_size, small as usize);
        let first_caps = RemoteSessionBackend::capabilities_for_transport(
            first_caps,
            true,
            first_profile,
            first_limits,
        );
        let second_caps = RemoteSessionBackend::capabilities_for_transport(
            second_caps,
            true,
            second_profile,
            second_limits,
        );
        assert!(first_caps.max_value_bytes > second_caps.max_value_bytes);

        // Simulate the older response being processed after the reconnect.
        backend.remember_capabilities(first_profile, first_limits, first_caps);
        assert!(
            backend.cached_capabilities().is_none(),
            "an old response tuple must not be relabelled with the current connection limits"
        );
        backend.remember_capabilities(second_profile, second_limits, second_caps);
        assert_eq!(
            backend.cached_capabilities().map(|(_, _, caps)| caps),
            Some(second_caps)
        );

        first_server.await.expect("first server");
        second_server.await.expect("second server");
    }

    #[tokio::test]
    async fn clone_before_frame_builder_detaches_transport_and_preserves_each_bound() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind capability listener");
        let addr = listener.local_addr().expect("listener address");
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(2);
        let server = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept capability client");
                let observed_tx = observed_tx.clone();
                handlers.spawn(async move {
                    let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                        .await
                        .expect("read hello");
                    let requested = match &hello {
                        Request::Hello {
                            requested_response_frame_size: Some(requested),
                            ..
                        } => *requested,
                        _ => panic!("requested frame size"),
                    };
                    write_frame(
                        &mut stream,
                        &hello_ack_with_limits(&hello, requested, requested),
                    )
                    .await
                    .expect("write hello acknowledgement");
                    let request: Request = read_frame(&mut stream, requested as usize)
                        .await
                        .expect("read capabilities");
                    assert!(matches!(request, Request::Capabilities));
                    write_frame(
                        &mut stream,
                        &Response::Capabilities(BackendCapabilities::all_enabled()),
                    )
                    .await
                    .expect("write capabilities");
                    observed_tx.send(requested).await.expect("record request");
                });
            }
            while handlers.join_next().await.is_some() {}
        });

        let original = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(2)));
        let configured_limit = 2 * crate::MIN_NEGOTIATED_FRAME_SIZE;
        let configured = original.clone().with_max_frame_size(configured_limit);
        assert!(!Arc::ptr_eq(&original.conn, &configured.conn));
        assert!(!Arc::ptr_eq(
            &original.negotiated_frame_limits,
            &configured.negotiated_frame_limits
        ));
        assert!(!Arc::ptr_eq(
            &original.cached_capabilities,
            &configured.cached_capabilities
        ));

        let configured_caps = configured.capabilities().await;
        let original_caps = original.capabilities().await;
        assert_eq!(
            configured_caps.max_value_bytes,
            conservative_payload_budget(configured_limit)
        );
        assert_eq!(
            original_caps.max_value_bytes,
            conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE)
        );
        let mut observed = vec![
            observed_rx.recv().await.expect("configured hello"),
            observed_rx.recv().await.expect("original hello"),
        ];
        observed.sort_unstable();
        assert_eq!(
            observed,
            vec![configured_limit as u32, DEFAULT_MAX_FRAME_SIZE as u32]
        );
        server.await.expect("capability server");
    }

    #[tokio::test]
    async fn retained_profile_and_payload_failures_do_not_resolve_a_peer() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok("127.0.0.1:1".parse().expect("address")) }.boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        );

        let mut invalid_key = match valid_deadline_entry().op {
            ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        invalid_key.stable_id =
            bytes::Bytes::from(vec![7; crate::MAX_SESSION_NET_STABLE_ID_BYTES + 1]);
        assert!(matches!(
            backend
                .send_request_classified(Request::Get { key: invalid_key })
                .await,
            Err(RemoteRequestFailure::Protocol)
        ));

        let mut invalid_tx = valid_deadline_entry();
        invalid_tx.tx_id = "x".repeat(crate::MAX_SESSION_NET_REPLICATION_TX_ID_BYTES + 1);
        assert!(matches!(
            backend
                .send_request_classified(Request::ReplicateEntry { entry: invalid_tx })
                .await,
            Err(RemoteRequestFailure::Protocol)
        ));

        let op = valid_compare_and_set(0).await;
        assert!(matches!(
            backend
                .send_request_classified(Request::CompareAndSet {
                    op,
                    request_id: Some("not-a-canonical-uuid".to_string()),
                })
                .await,
            Err(RemoteRequestFailure::Protocol)
        ));

        assert!(matches!(
            backend
                .send_request_classified(Request::GetReplicationLog {
                    start: 1,
                    limit: MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES + 1,
                })
                .await,
            Err(RemoteRequestFailure::Protocol)
        ));

        let constrained = backend
            .clone()
            .with_max_frame_size(crate::MIN_NEGOTIATED_FRAME_SIZE);
        let payload_error = constrained
            .compare_and_set(valid_compare_and_set(1).await)
            .await
            .expect_err("one byte above the clone-local limit must fail locally");
        assert_eq!(
            payload_error,
            StoreError::PayloadTooLarge { actual: 1, max: 0 }
        );
        assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn negotiated_unequal_limits_clamp_capabilities_and_preflight_requests() {
        let response_budget = (2 * MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE) as u32;
        let request_budget = MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE as u32;
        let (addr, server) = capability_server_with_limits(
            BackendCapabilities::all_enabled(),
            response_budget,
            request_budget,
        )
        .await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let capabilities = backend.capabilities().await;
        assert_eq!(
            capabilities.max_value_bytes,
            conservative_payload_budget(request_budget as usize),
            "payload capability must use the smaller request direction"
        );
        server.await.expect("capability server");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind preflight listener");
        let addr = listener.local_addr().expect("preflight address");
        let no_request_prefix = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(&hello, DEFAULT_MAX_FRAME_SIZE as u32, request_budget),
            )
            .await
            .expect("write constrained acknowledgement");
            let mut byte = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .expect("client must close after local preflight")
                .expect("read connection close");
            assert_eq!(read, 0, "no operation prefix may be emitted");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut key = match valid_deadline_entry().op {
            opc_session_store::ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        key.stable_id = bytes::Bytes::from(vec![u8::MAX; crate::MAX_SESSION_NET_STABLE_ID_BYTES]);
        let error = backend
            .batch(vec![SessionOp::Get { key }; 128])
            .await
            .expect_err("request above negotiated server limit must fail locally");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));
        no_request_prefix.await.expect("preflight server");
    }

    #[tokio::test]
    async fn negotiated_payload_limit_rejects_one_over_before_writing() {
        let request_budget = (2 * crate::MIN_NEGOTIATED_FRAME_SIZE) as u32;
        let negotiated_max = conservative_payload_budget(request_budget as usize);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind negotiated preflight listener");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(&hello, DEFAULT_MAX_FRAME_SIZE as u32, request_budget),
            )
            .await
            .expect("write constrained acknowledgement");
            let mut byte = [0_u8; 1];
            assert!(
                tokio::time::timeout(Duration::from_millis(250), stream.read(&mut byte))
                    .await
                    .is_err(),
                "negotiated preflight must emit no operation prefix and may retain the clean connection"
            );
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = backend
            .compare_and_set(valid_compare_and_set(negotiated_max + 1).await)
            .await
            .expect_err("one byte above the negotiated payload limit must fail locally");
        assert_eq!(
            error,
            StoreError::PayloadTooLarge {
                actual: negotiated_max + 1,
                max: negotiated_max,
            }
        );
        server.await.expect("negotiated preflight server");
    }

    #[tokio::test]
    async fn reconnect_with_changed_limits_evicts_incompatible_capability_cache() {
        let (first_addr, first_server) =
            capability_server(BackendCapabilities::all_enabled()).await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind changed-budget listener");
        let second_addr = listener.local_addr().expect("changed-budget address");
        let second_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept reconnect");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read reconnect hello");
            write_frame(
                &mut stream,
                &hello_ack_with_limits(
                    &hello,
                    MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE as u32,
                    MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE as u32,
                ),
            )
            .await
            .expect("write changed-budget acknowledgement");
            let request: Request = read_frame(&mut stream, MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE)
                .await
                .expect("read capability probe");
            assert!(matches!(request, Request::Capabilities));
            // Close without a response. The client must not fall back to the
            // capability cache populated under the old frame limits.
        });

        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(first_addr)
                } else {
                    Ok(second_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_millis(350)),
        );
        let warmed = backend.capabilities().await;
        assert!(
            warmed.max_value_bytes
                > conservative_payload_budget(MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE)
        );
        first_server.await.expect("first capability server");

        assert_eq!(
            backend.capabilities().await,
            unavailable_capabilities(),
            "a changed negotiated budget must invalidate the old cache before probe fallback"
        );
        second_server.await.expect("changed-budget server");
        assert!(resolve_calls.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn replayed_or_relabelled_hello_ack_is_rejected() {
        for stale_nonce in [true, false] {
            let (addr, handle) = invalid_ack_server(stale_nonce).await;
            let backend =
                RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(250)));

            let expected = if stale_nonce {
                ReplicaReadinessFailure::Protocol
            } else {
                ReplicaReadinessFailure::Authentication
            };
            assert_eq!(backend.probe_replication_head().await, Err(expected));
            let _ = handle.await;
        }
    }

    #[tokio::test]
    async fn socket_addr_constructor_remains_pinned_after_disconnect() {
        let caps_a = BackendCapabilities::minimal();
        let mut expected_caps_a = caps_a;
        expected_caps_a.max_value_bytes = conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE);
        let (addr_a, handle_a) = capability_server(caps_a).await;
        let (_addr_b, handle_b) = capability_server(BackendCapabilities::all_enabled()).await;
        let backend = RemoteSessionBackend::new_insecure(addr_a, Some(Duration::from_millis(250)));

        assert_eq!(backend.capabilities().await, expected_caps_a);
        let _ = handle_a.await;

        assert_eq!(backend.capabilities().await, expected_caps_a);
        handle_b.abort();
    }

    #[tokio::test]
    async fn explicit_version_mismatch_clears_all_cached_capabilities() {
        let (compatible_addr, compatible_handle) =
            capability_server(BackendCapabilities::all_enabled()).await;
        let (incompatible_addr, incompatible_handle) = version_mismatch_server().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = calls.clone();
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(compatible_addr)
                } else {
                    Ok(incompatible_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        );

        assert!(backend.capabilities().await.restore_scan);
        let _ = compatible_handle.await;

        assert_eq!(
            backend.capabilities().await,
            unavailable_capabilities(),
            "an explicitly incompatible protocol must clear the entire negotiated cache"
        );
        let _ = incompatible_handle.await;
    }

    #[tokio::test]
    async fn invalid_hello_ack_clears_all_cached_capabilities() {
        for stale_nonce in [true, false] {
            let (compatible_addr, compatible_handle) =
                capability_server(BackendCapabilities::all_enabled()).await;
            let (invalid_addr, invalid_handle) = invalid_ack_server(stale_nonce).await;
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver_calls = calls.clone();
            let resolver: RemoteAddrResolver = Arc::new(move || {
                let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call == 0 {
                        Ok(compatible_addr)
                    } else {
                        Ok(invalid_addr)
                    }
                }
                .boxed()
            });
            let backend = RemoteSessionBackend::new_insecure_with_resolver(
                resolver,
                Some(Duration::from_secs(1)),
            );

            let mut expected = BackendCapabilities::all_enabled();
            expected.max_value_bytes = conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE);
            assert_eq!(backend.capabilities().await, expected);
            let _ = compatible_handle.await;
            assert_eq!(
                backend.capabilities().await,
                unavailable_capabilities(),
                "an invalid fresh HelloAck must clear every cached capability"
            );
            let _ = invalid_handle.await;
        }
    }

    #[tokio::test]
    async fn missing_or_wrong_v4_contract_profile_clears_all_cached_capabilities() {
        let mut wrong_profile = CURRENT_CONTRACT_PROFILE;
        wrong_profile.error_set_revision = wrong_profile.error_set_revision.saturating_add(1);

        for incompatible_profile in [None, Some(wrong_profile)] {
            let (compatible_addr, compatible_handle) =
                capability_server(BackendCapabilities::all_enabled()).await;
            let (incompatible_addr, incompatible_handle) =
                contract_profile_mismatch_server(incompatible_profile).await;
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver_calls = calls.clone();
            let resolver: RemoteAddrResolver = Arc::new(move || {
                let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call == 0 {
                        Ok(compatible_addr)
                    } else {
                        Ok(incompatible_addr)
                    }
                }
                .boxed()
            });
            let backend = RemoteSessionBackend::new_insecure_with_resolver(
                resolver,
                Some(Duration::from_secs(1)),
            );

            assert!(backend.capabilities().await.restore_scan);
            let _ = compatible_handle.await;
            assert_eq!(
                backend.capabilities().await,
                unavailable_capabilities(),
                "same-version peers with a missing or different contract profile must fail closed"
            );
            let _ = incompatible_handle.await;
        }
    }

    #[tokio::test]
    async fn mismatched_batch_response_count_discards_connection_and_capability_cache() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");

            let capabilities: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read capabilities request");
            assert!(matches!(capabilities, Request::Capabilities));
            write_frame(
                &mut stream,
                &Response::Capabilities(BackendCapabilities::all_enabled()),
            )
            .await
            .expect("write capabilities response");

            let batch: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read batch request");
            assert!(matches!(batch, Request::Batch { ops } if ops.len() == 1));
            write_frame(&mut stream, &Response::Batch(Ok(Vec::new())))
                .await
                .expect("write wrong-cardinality batch response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(250)));

        assert!(backend.capabilities().await.restore_scan);
        let key = match valid_deadline_entry().op {
            opc_session_store::ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let error = backend
            .batch(vec![SessionOp::Get { key }])
            .await
            .expect_err("wrong response cardinality must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(
                "remote batch response violated the protocol contract".to_string()
            )
        );
        assert!(
            backend.conn.lock().await.is_none(),
            "the violating connection must not return to the pool"
        );
        let _ = server.await;
        assert_eq!(
            backend.capabilities().await,
            unavailable_capabilities(),
            "a later failed probe must not reuse capabilities negotiated on the violating connection"
        );
    }

    #[tokio::test]
    async fn wrong_response_family_drops_connection_clears_cache_and_forces_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind violating server");
        let first_addr = listener.local_addr().expect("violating address");
        let first_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, MAX_HANDSHAKE_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello acknowledgement");
            let capabilities: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read capabilities");
            assert!(matches!(capabilities, Request::Capabilities));
            write_frame(
                &mut stream,
                &Response::Capabilities(BackendCapabilities::all_enabled()),
            )
            .await
            .expect("write capabilities");
            let get: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read Get");
            assert!(matches!(get, Request::Get { .. }));
            write_frame(&mut stream, &Response::MaxReplicationSequence(Ok(7)))
                .await
                .expect("write wrong response family");
        });
        let (second_addr, second_server) = capability_server(BackendCapabilities::minimal()).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(first_addr)
                } else {
                    Ok(second_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        );
        assert!(backend.capabilities().await.restore_scan);
        let key = match valid_deadline_entry().op {
            ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };

        let error = backend
            .get(&key)
            .await
            .expect_err("wrong response family must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
        );
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());

        let refreshed = backend.capabilities().await;
        assert!(!refreshed.restore_scan);
        assert!(calls.load(Ordering::SeqCst) >= 2);
        first_server.await.expect("violating server");
        second_server.await.expect("replacement server");
    }

    #[tokio::test]
    async fn peer_record_for_a_different_key_is_a_protocol_violation() {
        let mut operation = valid_compare_and_set(0).await;
        let wrong_record = operation.new_record.clone();
        operation.key.stable_id = bytes::Bytes::from_static(b"requested-peer-key");
        let requested_key = operation.key;
        assert_ne!(wrong_record.key, requested_key);
        let (addr, server) =
            warmed_malicious_response_server(Response::Get(Ok(Some(wrong_record)))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_some());

        let error = backend
            .get(&requested_key)
            .await
            .expect_err("a record for another key must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
        );
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    #[tokio::test]
    async fn peer_cas_conflict_for_a_different_key_is_a_protocol_violation() {
        let operation = valid_compare_and_set(0).await;
        let mut wrong_record = operation.new_record.clone();
        wrong_record.key.stable_id = bytes::Bytes::from_static(b"wrong-cas-conflict-key");
        let response = Response::CompareAndSet(Ok(CompareAndSetResult::Conflict {
            current: Some(wrong_record),
        }));
        let (addr, server) = warmed_malicious_response_server(response).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);

        let error = backend
            .compare_and_set(operation)
            .await
            .expect_err("a CAS conflict for another key must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(REMOTE_PROTOCOL_VIOLATION.to_string())
        );
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    async fn assert_malicious_batch_response_is_rejected(
        ops: Vec<SessionOp>,
        results: Vec<SessionOpResult>,
    ) {
        let (addr, server) = warmed_malicious_response_server(Response::Batch(Ok(results))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);

        let error = backend
            .batch(ops)
            .await
            .expect_err("a batch response that does not match its request must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(
                "remote batch response violated the protocol contract".to_string()
            )
        );
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    #[tokio::test]
    async fn peer_batch_result_kind_must_match_the_requested_operation() {
        let operation = valid_compare_and_set(0).await;
        assert_malicious_batch_response_is_rejected(
            vec![SessionOp::Get { key: operation.key }],
            vec![SessionOpResult::CompareAndSet(Ok(
                CompareAndSetResult::Success,
            ))],
        )
        .await;
    }

    #[tokio::test]
    async fn peer_batch_get_and_cas_results_must_match_their_requested_keys() {
        let operation = valid_compare_and_set(0).await;
        let requested_key = operation.key.clone();
        let mut wrong_record = operation.new_record.clone();
        wrong_record.key.stable_id = bytes::Bytes::from_static(b"wrong-batch-get-key");
        assert_malicious_batch_response_is_rejected(
            vec![SessionOp::Get { key: requested_key }],
            vec![SessionOpResult::Get(Ok(Some(wrong_record)))],
        )
        .await;

        let operation = valid_compare_and_set(0).await;
        let mut wrong_record = operation.new_record.clone();
        wrong_record.key.stable_id = bytes::Bytes::from_static(b"wrong-batch-cas-key");
        assert_malicious_batch_response_is_rejected(
            vec![SessionOp::CompareAndSet(operation)],
            vec![SessionOpResult::CompareAndSet(Ok(
                CompareAndSetResult::Conflict {
                    current: Some(wrong_record),
                },
            ))],
        )
        .await;
    }

    #[tokio::test]
    async fn peer_acquire_lease_must_match_the_requested_key_and_owner() {
        let requested_key = match valid_deadline_entry().op {
            ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let requested_owner = OwnerId::new("requested-owner").expect("test owner");
        let mut wrong_key = requested_key.clone();
        wrong_key.stable_id = bytes::Bytes::from_static(b"wrong-acquire-key");
        let wrong_lease = FakeSessionBackend::new()
            .acquire(
                &wrong_key,
                OwnerId::new("wrong-owner").expect("test owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("wrong test lease");
        let (addr, server) =
            warmed_malicious_response_server(Response::AcquireLease(Ok(wrong_lease))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);

        let error = backend
            .acquire(&requested_key, requested_owner, Duration::from_secs(60))
            .await
            .expect_err("an acquire response for another key and owner must fail closed");
        assert_eq!(
            error,
            LeaseError::Backend(REMOTE_PROTOCOL_VIOLATION.to_string())
        );
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    #[tokio::test]
    async fn peer_renewal_must_preserve_key_owner_fence_and_credential() {
        let lease = valid_compare_and_set(0).await.lease;
        let mut forged_wire = serde_json::to_value(&lease).expect("serialize lease");
        let mut wrong_key = lease.key().clone();
        wrong_key.stable_id = bytes::Bytes::from_static(b"wrong-renew-key");
        forged_wire["key"] = serde_json::to_value(wrong_key).expect("serialize wrong key");
        forged_wire["owner"] = serde_json::json!("wrong-renew-owner");
        forged_wire["fence"] = serde_json::json!(lease.fence().get() + 1);
        forged_wire["credential_id"] = serde_json::json!(lease.credential_id() + 1);
        let forged_lease: LeaseGuard =
            serde_json::from_value(forged_wire).expect("deserialize forged lease");
        assert_ne!(forged_lease.key(), lease.key());
        assert_ne!(forged_lease.owner(), lease.owner());
        assert_ne!(forged_lease.fence(), lease.fence());
        assert_ne!(forged_lease.credential_id(), lease.credential_id());

        let (addr, server) =
            warmed_malicious_response_server(Response::RenewLease(Ok(forged_lease))).await;
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        assert!(backend.capabilities().await.restore_scan);

        let error = backend
            .renew(&lease, Duration::from_secs(60))
            .await
            .expect_err("a renewal that changes its credential must fail closed");
        assert_eq!(
            error,
            LeaseError::Backend(REMOTE_PROTOCOL_VIOLATION.to_string())
        );
        assert!(backend.conn.lock().await.is_none());
        assert!(backend
            .cached_capabilities
            .read()
            .expect("cache lock")
            .is_none());
        server.await.expect("malicious peer");
    }

    #[tokio::test]
    async fn legacy_close_without_ack_masks_cached_restore_capability() {
        let (compatible_addr, compatible_handle) =
            capability_server(BackendCapabilities::all_enabled()).await;
        let (legacy_addr, legacy_handle) = legacy_close_without_ack_server().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = calls.clone();
        let resolver: RemoteAddrResolver = Arc::new(move || {
            let call = resolver_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if call == 0 {
                    Ok(compatible_addr)
                } else {
                    Ok(legacy_addr)
                }
            }
            .boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_millis(250)),
        );

        let warmed = backend.capabilities().await;
        assert!(warmed.restore_scan);
        let _ = compatible_handle.await;

        let mut expected = warmed;
        expected.restore_scan = false;
        assert_eq!(
            backend.capabilities().await,
            expected,
            "clean transport EOF may retain descriptive operations, but fresh-negotiation capabilities must be masked"
        );
        let _ = legacy_handle.await;
    }

    #[tokio::test]
    async fn malformed_restore_page_is_rejected_and_discards_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read restore request");
            assert!(matches!(request, Request::ScanRestoreRecords { .. }));

            let mut invalid_page = serde_json::to_value(Response::ScanRestoreRecords(Ok(
                RestoreScanPage::new(Vec::new(), 0, None),
            )))
            .expect("serialize valid restore page");
            invalid_page["ScanRestoreRecords"]["Ok"]["loaded_count"] = serde_json::json!(1);
            write_frame(&mut stream, &invalid_page)
                .await
                .expect("write malformed restore-page wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("malformed peer page must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(
                "remote session backend request failed: protocol".to_string()
            )
        );
        assert!(
            backend.conn.lock().await.is_none(),
            "a connection that returned a malformed page must not be reused"
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn forged_replication_log_deadline_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read replication-log request");
            assert!(matches!(request, Request::GetReplicationLog { .. }));
            let response =
                serde_json::to_value(Response::GetReplicationLog(Ok(
                    vec![valid_deadline_entry()],
                )))
                .expect("serialize valid replication-log response");
            let response = forge_deadline_in_wire_response(response, "/GetReplicationLog/Ok/0");
            write_frame(&mut stream, &response)
                .await
                .expect("write forged replication-log wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = backend
            .get_replication_log(1, 1)
            .await
            .expect_err("forged response deadline must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(
                "remote session backend request failed: protocol".to_string()
            )
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn forged_watch_deadline_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read watch request");
            assert!(matches!(request, Request::Watch { .. }));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write watch acknowledgement");
            let response = serde_json::to_value(Response::WatchEntry(Ok(valid_deadline_entry())))
                .expect("serialize valid watch response");
            let response = forge_deadline_in_wire_response(response, "/WatchEntry/Ok");
            write_frame(&mut stream, &response)
                .await
                .expect("write forged watch wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut watch = backend.watch(1).await.expect("create watch stream");

        let error = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("watch response deadline")
            .expect("watch error item")
            .expect_err("forged watch deadline must fail closed");
        assert_eq!(
            error,
            StoreError::BackendUnavailable("remote session watch failed: protocol".to_string())
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn over_limit_replication_log_entry_is_rejected_before_return() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read replication-log request");
            assert!(matches!(request, Request::GetReplicationLog { .. }));

            let mut response = serde_json::to_value(Response::GetReplicationLog(Ok(vec![
                replication_entry_at_depth(MAX_REPLICATION_OPERATION_DEPTH),
            ])))
            .expect("serialize exact-depth replication-log response");
            let nodes = response["GetReplicationLog"]["Ok"][0]["operation_nodes"]
                .as_array_mut()
                .expect("flat replication operation nodes");
            nodes.insert(
                nodes.len() - 1,
                serde_json::json!({"Batch": {"child_count": 1}}),
            );
            write_frame(&mut stream, &response)
                .await
                .expect("write over-depth replication-log wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = match backend.get_replication_log(1, 1).await {
            Err(error) => error,
            Ok(entries) => {
                drop(validate_replication_page_owned(entries));
                panic!("an over-depth log entry must not be returned")
            }
        };
        assert_eq!(
            error,
            StoreError::BackendUnavailable(
                "remote session backend request failed: protocol".to_string()
            )
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn over_limit_watch_entry_is_rejected_before_delivery() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read watch request");
            assert!(matches!(request, Request::Watch { .. }));
            write_frame(&mut stream, &Response::WatchStream)
                .await
                .expect("write watch acknowledgement");

            let mut response = serde_json::to_value(Response::WatchEntry(Ok(
                replication_entry_at_operation_limit(),
            )))
            .expect("serialize maximum-width watch response");
            let nodes = response["WatchEntry"]["Ok"]["operation_nodes"]
                .as_array_mut()
                .expect("flat replication operation nodes");
            let leaf = nodes.last().expect("last operation node").clone();
            nodes.push(leaf);
            write_frame(&mut stream, &response)
                .await
                .expect("write over-count watch wire response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut watch = backend.watch(1).await.expect("create watch stream");

        let item = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("watch response deadline")
            .expect("watch error item");
        let error = match item {
            Err(error) => error,
            Ok(entry) => {
                drop(entry.into_validated());
                panic!("an over-count watch entry must not be delivered")
            }
        };
        assert_eq!(
            error,
            StoreError::BackendUnavailable("remote session watch failed: protocol".to_string())
        );
        let _ = server.await;
    }

    #[tokio::test]
    async fn remote_restore_scan_timeout_respects_the_method_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
                .await
                .expect("write hello ack");
            let request: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read restore request");
            assert!(matches!(request, Request::ScanRestoreRecords { .. }));
            std::future::pending::<()>().await;
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(100)));
        let started = tokio::time::Instant::now();

        let error = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("stalled restore response must time out");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(backend.conn.lock().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn invalid_restore_request_fails_before_connecting() {
        let backend = RemoteSessionBackend::new_insecure(
            "127.0.0.1:1".parse().expect("address"),
            Some(Duration::from_secs(1)),
        );

        let error = backend
            .scan_restore_records(RestoreScanRequest::all(0))
            .await
            .expect_err("zero limit must fail validation");
        assert!(matches!(error, StoreError::InvalidRestoreScanRequest(_)));
    }

    #[tokio::test]
    async fn legacy_restore_cursor_fails_before_connecting() {
        let backend = RemoteSessionBackend::new_insecure(
            "127.0.0.1:1".parse().expect("address"),
            Some(Duration::from_secs(1)),
        );
        let error = backend
            .scan_restore_records(RestoreScanRequest {
                cursor: Some(opc_session_store::RestoreScanCursor::from_offset(0)),
                ..RestoreScanRequest::all(1)
            })
            .await
            .expect_err("legacy cursor is local-test evidence only");
        assert_eq!(
            error,
            StoreError::CapabilityNotSupported("legacy_remote_restore_scan".to_string())
        );
    }

    #[tokio::test]
    async fn collection_limits_fail_before_resolving_or_dialing() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok("127.0.0.1:1".parse().expect("address")) }.boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        );

        let key = match valid_deadline_entry().op {
            opc_session_store::ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let batch_error = backend
            .batch(vec![
                SessionOp::Get { key };
                MAX_SESSION_NET_BATCH_OPERATIONS + 1
            ])
            .await
            .expect_err("oversized batch must fail locally");
        assert_eq!(batch_error, StoreError::ReplicationOperationLimitExceeded);

        let log_error = backend
            .get_replication_log(1, MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES + 1)
            .await
            .expect_err("oversized log page must fail locally");
        assert_eq!(log_error, StoreError::ReplicationOperationLimitExceeded);

        let lightweight_entry = ReplicationEntry {
            sequence: 1,
            tx_id: String::new(),
            op: opc_session_store::ReplicationOp::Batch { ops: Vec::new() },
            timestamp: opc_types::Timestamp::now_utc(),
        };
        let rebuild_error = backend
            .rebuild_replication_state(vec![lightweight_entry; MAX_SESSION_NET_REBUILD_ENTRIES + 1])
            .await
            .expect_err("oversized rebuild must fail locally");
        assert_eq!(rebuild_error, StoreError::ReplicationOperationLimitExceeded);

        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            0,
            "collection preflight failures must not resolve or dial a peer"
        );
    }

    #[tokio::test]
    async fn frame_size_above_negotiated_ceiling_fails_before_resolving_or_dialing() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok("127.0.0.1:1".parse().expect("address")) }.boxed()
        });
        let backend = RemoteSessionBackend::new_insecure_with_resolver(
            resolver,
            Some(Duration::from_secs(1)),
        )
        .with_max_frame_size(crate::MAX_NEGOTIATED_FRAME_SIZE + 1);

        let key = match valid_deadline_entry().op {
            opc_session_store::ReplicationOp::RefreshTtl { key, .. } => key,
            _ => unreachable!("fixture operation is fixed"),
        };
        let error = backend
            .get(&key)
            .await
            .expect_err("an over-ceiling ordinary request must fail locally");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));

        let error = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("an over-ceiling restore response frame must fail locally");
        assert!(matches!(error, StoreError::InvalidRestoreScanRequest(_)));
        assert!(
            backend.watch(0).await.is_err(),
            "an over-ceiling watch must fail before spawning its resolver task"
        );
        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            0,
            "ordinary, restore, and watch width failures must not resolve or dial a peer"
        );
    }

    #[tokio::test]
    async fn unrepresentable_client_deadline_fails_before_resolving_or_dialing() {
        let resolve_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&resolve_calls);
        let resolver: RemoteAddrResolver = Arc::new(move || {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            async { Ok("127.0.0.1:1".parse().expect("address")) }.boxed()
        });
        let backend =
            RemoteSessionBackend::new_insecure_with_resolver(resolver, Some(Duration::MAX));

        let error = backend
            .max_replication_sequence()
            .await
            .expect_err("an unrepresentable absolute deadline must fail locally");
        assert!(matches!(error, StoreError::BackendUnavailable(_)));
        assert_eq!(
            resolve_calls.load(Ordering::SeqCst),
            0,
            "deadline conversion failure must not resolve or dial a peer"
        );
    }

    #[test]
    fn resolver_target_uses_hostname_for_tls_server_name_across_addresses() {
        let resolver: RemoteAddrResolver =
            Arc::new(|| async { Ok("127.0.0.1:1".parse().expect("addr")) }.boxed());
        let target = RemoteTarget::resolved(
            Some("peer-0.sessions.core.svc.cluster.local".to_string()),
            resolver,
        );
        let first = target
            .tls_server_name("127.0.0.1:1234".parse().expect("addr"))
            .expect("first server name");
        let second = target
            .tls_server_name("127.0.0.2:1234".parse().expect("addr"))
            .expect("second server name");

        assert_eq!(format!("{first:?}"), format!("{second:?}"));
        assert!(format!("{first:?}").contains("peer-0.sessions.core.svc.cluster.local"));
        assert!(!format!("{first:?}").contains("127.0.0.1"));
    }
}
