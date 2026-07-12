use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use futures_util::Stream;
use opc_session_store::backend::{
    validate_replication_page_owned, validate_replication_prefix_owned, BackendInstanceIdentity,
    BackendPeerBinding, CompareAndSet, CompareAndSetResult, ReplicationEntry, SessionBackend,
    SessionOp, SessionOpResult, WATCH_CHANNEL_CAPACITY,
};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::error::{LeaseError, StoreError};
use opc_session_store::lease::{LeaseGuard, SessionLeaseManager};
use opc_session_store::model::{OwnerId, SessionKey};

use opc_session_store::record::StoredSessionRecord;
use opc_session_store::{
    validate_session_ttl, ReplicaId, ReplicaReadinessFailure, RestoreScanPage, RestoreScanRequest,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::error::ProtocolError;
use crate::identity::RemoteReplicaBinding;
use crate::protocol::{
    ensure_frame_fits, read_frame, write_frame, Request, Response, RestoreScanWireRequest,
    CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE, MAX_HANDSHAKE_FRAME_SIZE,
    MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE, SESSION_NET_ALPN,
};

/// Resolver callback used by [`RemoteSessionBackend::new_with_resolver`].
pub type RemoteAddrResolver =
    Arc<dyn Fn() -> BoxFuture<'static, io::Result<SocketAddr>> + Send + Sync>;

/// Persistent transport connection to a remote session backend.
///
/// The client keeps a single connection and allows one in-flight request at
/// a time; clones of [`RemoteSessionBackend`] share this connection.
struct Connection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    authenticated_peer: Option<ReplicaId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteRequestFailure {
    Transport,
    Authentication,
    Timeout,
    Protocol,
    Backend,
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
        }
    }
}

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
) -> Result<Connection, ProtocolError> {
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
        perform_client_handshake(&mut reader, &mut writer, &binding).await?;
        Ok(Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            authenticated_peer: Some(binding.remote_replica_id().clone()),
        })
    } else {
        let (mut reader, mut writer) = tokio::io::split(tcp);
        perform_client_handshake(&mut reader, &mut writer, &binding).await?;
        Ok(Connection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            authenticated_peer: None,
        })
    }
}

async fn perform_client_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    binding: &RemoteReplicaBinding,
) -> Result<(), ProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let handshake_nonce = uuid::Uuid::new_v4();
    let configuration_id = binding.configuration_id().to_hex();
    write_frame(
        writer,
        &Request::Hello {
            contract_version: CONTRACT_VERSION,
            node_id: binding.local_replica_id().as_str().to_string(),
            expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_string()),
            cluster_id: Some(binding.cluster_id().as_str().to_string()),
            configuration_id: Some(configuration_id.clone()),
            handshake_nonce: Some(handshake_nonce),
        },
    )
    .await?;

    let ack: Response = read_frame(reader, MAX_HANDSHAKE_FRAME_SIZE).await?;
    match ack {
        Response::HelloAck {
            contract_version,
            server_replica_id,
            accepted_client_replica_id,
            cluster_id,
            configuration_id: accepted_configuration_id,
            handshake_nonce: accepted_nonce,
        } => {
            if contract_version != CONTRACT_VERSION {
                return Err(ProtocolError::VersionMismatch {
                    local: CONTRACT_VERSION,
                    remote: contract_version,
                });
            }
            let identity_matches = server_replica_id.as_deref()
                == Some(binding.remote_replica_id().as_str())
                && accepted_client_replica_id.as_deref()
                    == Some(binding.local_replica_id().as_str())
                && cluster_id.as_deref() == Some(binding.cluster_id().as_str())
                && accepted_configuration_id.as_deref() == Some(configuration_id.as_str());
            if !identity_matches {
                return Err(ProtocolError::Authentication);
            }
            if accepted_nonce != Some(handshake_nonce) {
                return Err(ProtocolError::UnexpectedResponse);
            }
            Ok(())
        }
        Response::HelloRejected { .. } => Err(ProtocolError::Authentication),
        response => {
            discard_replication_payloads_from_response(response);
            Err(ProtocolError::UnexpectedResponse)
        }
    }
}

fn discard_replication_payloads_from_response(response: Response) {
    match response {
        Response::GetReplicationLog(Ok(entries)) => {
            drop(validate_replication_page_owned(entries));
        }
        Response::WatchEntry(Ok(entry)) => {
            drop(entry.into_validated());
        }
        _ => {}
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
    cached_capabilities: Arc<RwLock<Option<BackendCapabilities>>>,
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
            cached_capabilities: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the maximum frame size.
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    async fn send_request_classified(
        &self,
        req: Request,
    ) -> Result<Response, RemoteRequestFailure> {
        let mut last_failure = None;
        let mut request_in_flight = true;
        let attempts = async {
            let mut backoff_ms = 100u64;
            loop {
                request_in_flight = true;
                match self.do_request(&req).await {
                    Ok(resp) => return Ok(resp),
                    Err(error) => {
                        let failure = RemoteRequestFailure::from_protocol_error(&error);
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
        match tokio::time::timeout(self.deadline, attempts).await {
            Ok(res) => res,
            Err(_) if request_in_flight => Err(RemoteRequestFailure::Timeout),
            Err(_) => Err(last_failure.unwrap_or(RemoteRequestFailure::Timeout)),
        }
    }

    async fn send_request_with_retry(&self, req: Request) -> Result<Response, StoreError> {
        self.send_request_classified(req).await.map_err(|failure| {
            StoreError::BackendUnavailable(format!(
                "remote session backend request failed: {}",
                failure.reason_code()
            ))
        })
    }

    async fn send_lease_request_with_retry(&self, req: Request) -> Result<Response, LeaseError> {
        self.send_request_with_retry(req)
            .await
            .map_err(|e| LeaseError::Backend(e.to_string()))
    }

    async fn do_request(&self, req: &Request) -> Result<Response, ProtocolError> {
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
            None => self.connect().await?,
        };

        match self.exchange(req, &mut conn).await {
            Ok(resp) => {
                *guard = Some(conn);
                Ok(resp)
            }
            Err(e) => Err(e),
        }
    }

    async fn connect(&self) -> Result<Connection, ProtocolError> {
        let result = open_connection(
            self.target.clone(),
            self.tls_config.clone(),
            self.binding.clone(),
        )
        .await;
        if result.as_ref().is_err_and(|error| {
            matches!(
                error,
                ProtocolError::Authentication
                    | ProtocolError::VersionMismatch { .. }
                    | ProtocolError::UnexpectedResponse
                    | ProtocolError::FrameTooLarge(_)
                    | ProtocolError::Serialization(_)
            )
        }) {
            self.clear_cached_capabilities();
        }
        result
    }

    async fn exchange(
        &self,
        req: &Request,
        conn: &mut Connection,
    ) -> Result<Response, ProtocolError> {
        if self.tls_config.is_some()
            && conn.authenticated_peer.as_ref() != Some(self.binding.remote_replica_id())
        {
            return Err(ProtocolError::Authentication);
        }
        write_frame(&mut conn.writer, req).await?;
        read_frame(&mut conn.reader, self.max_frame_size).await
    }

    fn remember_capabilities(&self, caps: BackendCapabilities) {
        if let Ok(mut cached) = self.cached_capabilities.write() {
            *cached = Some(caps);
        }
    }

    fn clear_cached_capabilities(&self) {
        if let Ok(mut cached) = self.cached_capabilities.write() {
            *cached = None;
        }
    }

    fn cached_capabilities(&self) -> Option<BackendCapabilities> {
        self.cached_capabilities
            .read()
            .ok()
            .and_then(|cached| *cached)
    }

    fn capabilities_for_transport(
        &self,
        mut caps: BackendCapabilities,
        fresh_v3_negotiation: bool,
    ) -> BackendCapabilities {
        if !fresh_v3_negotiation || self.max_frame_size < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
            caps.restore_scan = false;
        }
        caps
    }

    fn capabilities_after_probe_failure(&self, reason: &str) -> BackendCapabilities {
        if let Some(caps) = self.cached_capabilities() {
            tracing::warn!(
                target = %self.target,
                reason,
                "remote capabilities probe failed; using cached capabilities with negotiated operations masked"
            );
            self.capabilities_for_transport(caps, false)
        } else {
            tracing::warn!(
                target = %self.target,
                reason,
                "remote capabilities probe failed before any cached success; returning minimal capabilities"
            );
            BackendCapabilities::minimal()
        }
    }

    async fn discard_connection(&self) {
        self.conn.lock().await.take();
    }
}

#[async_trait]
impl SessionBackend for RemoteSessionBackend {
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.conn))
    }

    fn peer_binding(&self) -> Option<BackendPeerBinding> {
        self.tls_config
            .as_ref()
            .map(|_| self.binding.backend_peer_binding())
    }

    async fn capabilities(&self) -> BackendCapabilities {
        match self.send_request_with_retry(Request::Capabilities).await {
            Ok(Response::Capabilities(caps)) => {
                self.remember_capabilities(caps);
                self.capabilities_for_transport(caps, true)
            }
            Ok(response) => {
                discard_replication_payloads_from_response(response);
                self.capabilities_after_probe_failure("unexpected_response")
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
            Response::Get(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
        }
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        match self
            .send_request_with_retry(Request::CompareAndSet {
                op,
                request_id: Some(uuid::Uuid::new_v4().to_string()),
            })
            .await?
        {
            Response::CompareAndSet(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
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
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
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
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
        }
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        for op in &ops {
            op.validate_ttls()?;
        }
        match self.send_request_with_retry(Request::Batch { ops }).await? {
            Response::Batch(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
        }
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        request.validate()?;
        if self.max_frame_size < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
            return Err(StoreError::RestoreScanResponseTooLarge {
                max_bytes: self.max_frame_size,
            });
        }
        let wire_request = RestoreScanWireRequest::try_from(&request)?;
        let max_response_frame_size = u32::try_from(self.max_frame_size).unwrap_or(u32::MAX);
        let outbound = Request::ScanRestoreRecords {
            request: wire_request,
            max_response_frame_size,
        };
        ensure_frame_fits(&outbound, self.max_frame_size)
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;

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
                if let Err(error) = page.validate_for_request(&request) {
                    self.discard_connection().await;
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
            Response::Error { .. } => {
                self.discard_connection().await;
                tracing::warn!(
                    target = %self.target,
                    failure = "protocol_error",
                    "remote restore scan failed"
                );
                Err(StoreError::BackendUnavailable(
                    "remote restore scan returned a protocol error".to_string(),
                ))
            }
            response => {
                discard_replication_payloads_from_response(response);
                self.discard_connection().await;
                tracing::warn!(
                    target = %self.target,
                    failure = "unexpected_response",
                    "remote restore scan response was rejected"
                );
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
        }
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        match self
            .send_request_with_retry(Request::MaxReplicationSequence)
            .await?
        {
            Response::MaxReplicationSequence(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
        }
    }

    async fn probe_replication_head(&self) -> Result<u64, ReplicaReadinessFailure> {
        let response = self
            .send_request_classified(Request::MaxReplicationSequence)
            .await
            .map_err(ReplicaReadinessFailure::from)?;
        match response {
            Response::MaxReplicationSequence(Ok(sequence)) => Ok(sequence),
            Response::MaxReplicationSequence(Err(_)) => Err(ReplicaReadinessFailure::Backend),
            Response::Error { .. } => {
                self.discard_connection().await;
                Err(ReplicaReadinessFailure::Protocol)
            }
            response => {
                discard_replication_payloads_from_response(response);
                self.discard_connection().await;
                Err(ReplicaReadinessFailure::Protocol)
            }
        }
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        match self
            .send_request_with_retry(Request::GetReplicationLog { start, limit })
            .await?
        {
            Response::GetReplicationLog(res) => {
                let entries = res?;
                validate_replication_page_owned(entries)
            }
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
        }
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        match self
            .send_request_with_retry(Request::ReplicateEntry { entry })
            .await?
        {
            Response::ReplicateEntry(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
        }
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let entries = validate_replication_prefix_owned(entries)?;
        match self
            .send_request_with_retry(Request::RebuildReplicationState { entries })
            .await?
        {
            Response::RebuildReplicationState(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
        }
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<BoxStream<'static, Result<ReplicationEntry, StoreError>>, StoreError> {
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
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(StoreError::BackendUnavailable("unexpected response".into()))
            }
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
        match self
            .send_lease_request_with_retry(Request::AcquireLease {
                key: key.clone(),
                owner,
                ttl,
            })
            .await?
        {
            Response::AcquireLease(res) => res,
            Response::Error { message } => Err(LeaseError::Backend(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(LeaseError::Backend("unexpected response".into()))
            }
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
            Response::RenewLease(res) => res,
            Response::Error { message } => Err(LeaseError::Backend(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(LeaseError::Backend("unexpected response".into()))
            }
        }
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        match self
            .send_lease_request_with_retry(Request::ReleaseLease { lease })
            .await?
        {
            Response::ReleaseLease(res) => res,
            Response::Error { message } => Err(LeaseError::Backend(message)),
            response => {
                discard_replication_payloads_from_response(response);
                Err(LeaseError::Backend("unexpected response".into()))
            }
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
    let open = async {
        let mut connection = open_connection(target, tls_config, binding).await?;
        write_frame(&mut connection.writer, &Request::Watch { start_sequence }).await?;
        match read_frame::<_, Response>(&mut connection.reader, max_frame_size).await? {
            Response::WatchStream => Ok::<_, ProtocolError>(connection.reader),
            Response::Error { .. } => Err(ProtocolError::BackendUnavailable(
                "watch request rejected".to_string(),
            )),
            response => {
                discard_replication_payloads_from_response(response);
                Err(ProtocolError::UnexpectedResponse)
            }
        }
    };
    let mut reader = match tokio::time::timeout(deadline, open).await {
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
        match read_frame::<_, Response>(&mut reader, max_frame_size).await {
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
    use futures_util::{FutureExt, StreamExt};
    use opc_session_store::{
        BackendCapabilities, MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_OPERATION_DEPTH,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    fn successful_hello_ack(hello: &Request) -> Response {
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
            server_replica_id: expected_server_replica_id.clone(),
            accepted_client_replica_id: Some(node_id.clone()),
            cluster_id: cluster_id.clone(),
            configuration_id: configuration_id.clone(),
            handshake_nonce: *handshake_nonce,
        }
    }

    fn forged_deadline_entry() -> ReplicationEntry {
        let timestamp =
            opc_types::Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let expires_at = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH
                .checked_add(time::Duration::seconds(61))
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

    fn operation_tree_at_depth(depth: usize) -> opc_session_store::ReplicationOp {
        let mut op = opc_session_store::ReplicationOp::Batch { ops: Vec::new() };
        for _ in 1..depth {
            op = opc_session_store::ReplicationOp::Batch { ops: vec![op] };
        }
        op
    }

    fn over_depth_replication_entry() -> ReplicationEntry {
        ReplicationEntry {
            sequence: 1,
            tx_id: "over-depth-response".to_string(),
            op: operation_tree_at_depth(MAX_REPLICATION_OPERATION_DEPTH + 1),
            timestamp: opc_types::Timestamp::now_utc(),
        }
    }

    fn over_count_replication_entry() -> ReplicationEntry {
        let ops = (0..MAX_REPLICATION_OPERATIONS_PER_ENTRY)
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
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept client");
            let hello: Request = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
                .await
                .expect("read hello");
            write_frame(&mut stream, &successful_hello_ack(&hello))
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
                    server_replica_id: None,
                    accepted_client_replica_id: None,
                    cluster_id: None,
                    configuration_id: None,
                    handshake_nonce: None,
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

    #[tokio::test]
    async fn resolver_backend_reconnects_to_changed_address() {
        let caps_a = BackendCapabilities::minimal();
        let caps_b = BackendCapabilities::all_enabled();
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

        assert_eq!(backend.capabilities().await, caps_a);
        let _ = handle_a.await;

        assert_eq!(backend.capabilities().await, caps_b);
        let _ = handle_b.await;
        assert!(calls.load(Ordering::SeqCst) >= 2);
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
        let (addr_a, handle_a) = capability_server(caps_a).await;
        let (_addr_b, handle_b) = capability_server(BackendCapabilities::all_enabled()).await;
        let backend = RemoteSessionBackend::new_insecure(addr_a, Some(Duration::from_millis(250)));

        assert_eq!(backend.capabilities().await, caps_a);
        let _ = handle_a.await;

        assert_eq!(backend.capabilities().await, caps_a);
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
            BackendCapabilities::minimal(),
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

            assert_eq!(
                backend.capabilities().await,
                BackendCapabilities::all_enabled()
            );
            let _ = compatible_handle.await;
            assert_eq!(
                backend.capabilities().await,
                BackendCapabilities::minimal(),
                "an invalid fresh HelloAck must clear every cached capability"
            );
            let _ = invalid_handle.await;
        }
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

            let mut invalid_page = RestoreScanPage::new(Vec::new(), 0, None);
            invalid_page.loaded_count = 1;
            write_frame(&mut stream, &Response::ScanRestoreRecords(Ok(invalid_page)))
                .await
                .expect("write invalid page");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("malformed peer page must fail closed");
        assert!(matches!(error, StoreError::InvalidRestoreScanResponse(_)));
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
            write_frame(
                &mut stream,
                &Response::GetReplicationLog(Ok(vec![forged_deadline_entry()])),
            )
            .await
            .expect("write forged replication-log response");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = backend
            .get_replication_log(1, 1)
            .await
            .expect_err("forged response deadline must fail closed");
        assert_eq!(error, StoreError::InvalidSessionTtl);
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
            write_frame(
                &mut stream,
                &Response::WatchEntry(Ok(forged_deadline_entry())),
            )
            .await
            .expect("write forged watch entry");
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));
        let mut watch = backend.watch(1).await.expect("create watch stream");

        let error = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("watch response deadline")
            .expect("watch error item")
            .expect_err("forged watch deadline must fail closed");
        assert_eq!(error, StoreError::InvalidSessionTtl);
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

            let response = Response::GetReplicationLog(Ok(vec![over_depth_replication_entry()]));
            write_frame(&mut stream, &response)
                .await
                .expect("write over-depth replication-log response");
            let Response::GetReplicationLog(Ok(entries)) = response else {
                unreachable!("test response shape is fixed")
            };
            drop(validate_replication_page_owned(entries));
        });
        let backend = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

        let error = match backend.get_replication_log(1, 1).await {
            Err(error) => error,
            Ok(entries) => {
                drop(validate_replication_page_owned(entries));
                panic!("an over-depth log entry must not be returned")
            }
        };
        assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
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

            let response = Response::WatchEntry(Ok(over_count_replication_entry()));
            write_frame(&mut stream, &response)
                .await
                .expect("write over-count watch entry");
            let Response::WatchEntry(Ok(entry)) = response else {
                unreachable!("test response shape is fixed")
            };
            drop(entry.into_validated());
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
        assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
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
