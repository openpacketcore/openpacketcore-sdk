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
    BackendInstanceIdentity, CompareAndSet, CompareAndSetResult, ReplicationEntry, SessionBackend,
    SessionOp, SessionOpResult, WATCH_CHANNEL_CAPACITY,
};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::error::{LeaseError, StoreError};
use opc_session_store::lease::{LeaseGuard, SessionLeaseManager};
use opc_session_store::model::{OwnerId, SessionKey};

use opc_session_store::record::StoredSessionRecord;
use opc_session_store::{ReplicaReadinessFailure, RestoreScanPage, RestoreScanRequest};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::error::ProtocolError;
use crate::protocol::{
    ensure_frame_fits, read_frame, write_frame, Request, Response, RestoreScanWireRequest,
    CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE, MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
};

/// Resolver callback used by [`RemoteSessionBackend::new_with_resolver`].
pub type RemoteAddrResolver =
    Arc<dyn Fn() -> BoxFuture<'static, io::Result<SocketAddr>> + Send + Sync>;

/// Persistent transport connection to a remote session backend.
///
/// The v0 client keeps a single connection and allows one in-flight request at
/// a time; clones of [`RemoteSessionBackend`] share this connection.
struct Connection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
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
    let is_rustls_failure = error.get_ref().is_some_and(|source| {
        source
            .downcast_ref::<tokio_rustls::rustls::Error>()
            .is_some()
    });
    if is_rustls_failure {
        ProtocolError::Authentication
    } else {
        ProtocolError::Io(error)
    }
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
    Pinned(SocketAddr),
    Resolved {
        server_name: Option<Arc<str>>,
        resolve: RemoteAddrResolver,
    },
}

impl RemoteTarget {
    fn pinned(addr: SocketAddr) -> Self {
        Self::Pinned(addr)
    }

    fn resolved(server_name: Option<String>, resolve: RemoteAddrResolver) -> Self {
        Self::Resolved {
            server_name: server_name.map(Arc::<str>::from),
            resolve,
        }
    }

    async fn resolve(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Pinned(addr) => Ok(*addr),
            Self::Resolved { resolve, .. } => resolve().await,
        }
    }

    fn tls_server_name(
        &self,
        resolved_addr: SocketAddr,
    ) -> Result<rustls_pki_types::ServerName<'static>, ProtocolError> {
        match self {
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
        match self {
            Self::Pinned(addr) => f.debug_tuple("Pinned").field(addr).finish(),
            Self::Resolved { server_name, .. } => f
                .debug_struct("Resolved")
                .field("server_name", server_name)
                .finish_non_exhaustive(),
        }
    }
}

impl std::fmt::Display for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pinned(addr) => write!(f, "{addr}"),
            Self::Resolved {
                server_name: Some(server_name),
                ..
            } => write!(f, "{server_name}"),
            Self::Resolved {
                server_name: None, ..
            } => f.write_str("<resolver>"),
        }
    }
}

/// Remote session backend client.
#[derive(Clone)]
pub struct RemoteSessionBackend {
    target: RemoteTarget,
    tls_config: Option<Arc<opc_tls::ClientConfig>>,
    deadline: Duration,
    max_frame_size: usize,
    node_id: String,
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
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

impl RemoteSessionBackend {
    /// Create a new mTLS remote backend client.
    ///
    /// `deadline` bounds every backend method end-to-end, including connection
    /// retries with backoff (default 2s when `None`). On expiry the method
    /// returns the store's unavailable error so a quorum layer treats this
    /// replica as offline instead of stalling.
    pub fn new(
        addr: SocketAddr,
        tls_config: Arc<opc_tls::ClientConfig>,
        deadline: Option<Duration>,
    ) -> Self {
        Self::from_transport(RemoteTarget::pinned(addr), Some(tls_config), deadline)
    }

    /// Create a new mTLS remote backend client that re-resolves before each
    /// new connection.
    ///
    /// Existing live connections are reused. When a connection is dropped,
    /// the next retry calls `resolve` and connects to the returned address.
    /// TLS verification keeps using `server_name`; it is not changed to the
    /// resolved IP address.
    pub fn new_with_resolver(
        server_name: String,
        resolve: RemoteAddrResolver,
        tls_config: Arc<opc_tls::ClientConfig>,
        deadline: Option<Duration>,
    ) -> Self {
        Self::from_transport(
            RemoteTarget::resolved(Some(server_name), resolve),
            Some(tls_config),
            deadline,
        )
    }

    /// Create a plaintext remote backend client for tests.
    ///
    /// Production replication clients must use [`RemoteSessionBackend::new`].
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(addr: SocketAddr, deadline: Option<Duration>) -> Self {
        Self::from_transport(RemoteTarget::pinned(addr), None, deadline)
    }

    /// Create a plaintext remote backend client with re-resolution for tests.
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure_with_resolver(
        resolve: RemoteAddrResolver,
        deadline: Option<Duration>,
    ) -> Self {
        Self::from_transport(RemoteTarget::resolved(None, resolve), None, deadline)
    }

    fn from_transport(
        target: RemoteTarget,
        tls_config: Option<Arc<opc_tls::ClientConfig>>,
        deadline: Option<Duration>,
    ) -> Self {
        Self {
            target,
            tls_config,
            deadline: deadline.unwrap_or(Duration::from_secs(2)),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            node_id: format!("opc-session-net/{}", std::process::id()),
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
        let addr = self.target.resolve().await.map_err(ProtocolError::Io)?;
        let tcp = TcpStream::connect(addr).await.map_err(ProtocolError::Io)?;

        let (mut reader, mut writer): (
            Box<dyn AsyncRead + Unpin + Send>,
            Box<dyn AsyncWrite + Unpin + Send>,
        ) = if let Some(tls_config) = &self.tls_config {
            let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
            let server_name = self.target.tls_server_name(addr)?;
            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(classify_tls_connect_error)?;
            let (r, w) = tokio::io::split(tls_stream);
            (Box::new(r), Box::new(w))
        } else {
            let (r, w) = tokio::io::split(tcp);
            (Box::new(r), Box::new(w))
        };

        // Hello handshake
        write_frame(
            &mut writer,
            &Request::Hello {
                contract_version: CONTRACT_VERSION,
                node_id: self.node_id.clone(),
            },
        )
        .await?;

        let ack: Response = read_frame(&mut reader, self.max_frame_size).await?;
        match ack {
            Response::HelloAck { contract_version } => {
                if contract_version != CONTRACT_VERSION {
                    self.clear_cached_capabilities();
                    return Err(ProtocolError::VersionMismatch {
                        local: CONTRACT_VERSION,
                        remote: contract_version,
                    });
                }
            }
            Response::Error { message } => {
                return Err(ProtocolError::BackendUnavailable(message));
            }
            _ => {
                return Err(ProtocolError::UnexpectedResponse);
            }
        }

        Ok(Connection { reader, writer })
    }

    async fn exchange(
        &self,
        req: &Request,
        conn: &mut Connection,
    ) -> Result<Response, ProtocolError> {
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
        fresh_v2_negotiation: bool,
    ) -> BackendCapabilities {
        if !fresh_v2_negotiation || self.max_frame_size < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
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

    async fn capabilities(&self) -> BackendCapabilities {
        match self.send_request_with_retry(Request::Capabilities).await {
            Ok(Response::Capabilities(caps)) => {
                self.remember_capabilities(caps);
                self.capabilities_for_transport(caps, true)
            }
            Ok(_) => self.capabilities_after_probe_failure("unexpected_response"),
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
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
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
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
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
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
        }
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        match self
            .send_request_with_retry(Request::RefreshTtl {
                lease: lease.clone(),
                ttl,
            })
            .await?
        {
            Response::RefreshTtl(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
        }
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        match self.send_request_with_retry(Request::Batch { ops }).await? {
            Response::Batch(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
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
            _ => {
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
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
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
            _ => {
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
            Response::GetReplicationLog(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
        }
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        match self
            .send_request_with_retry(Request::ReplicateEntry { entry })
            .await?
        {
            Response::ReplicateEntry(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
        }
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        match self
            .send_request_with_retry(Request::RebuildReplicationState { entries })
            .await?
        {
            Response::RebuildReplicationState(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
        }
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<BoxStream<'static, Result<ReplicationEntry, StoreError>>, StoreError> {
        let target = self.target.clone();
        let tls_config = self.tls_config.clone();
        let max_frame_size = self.max_frame_size;
        let node_id = self.node_id.clone();
        let deadline = self.deadline;

        let (tx, rx) = tokio::sync::mpsc::channel(WATCH_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let result = watch_connect_and_read(
                target,
                tls_config,
                max_frame_size,
                node_id,
                start_sequence,
                deadline,
                tx,
            )
            .await;
            if let Err(e) = result {
                tracing::debug!(error = ?e, "watch stream ended");
            }
        });

        Ok(Box::pin(WatchStream { rx }))
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        match self.send_request_with_retry(Request::NextLeaseInfo).await? {
            Response::NextLeaseInfo(res) => res,
            Response::Error { message } => Err(StoreError::BackendUnavailable(message)),
            _ => Err(StoreError::BackendUnavailable("unexpected response".into())),
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
            _ => Err(LeaseError::Backend("unexpected response".into())),
        }
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        match self
            .send_lease_request_with_retry(Request::RenewLease {
                lease: lease.clone(),
                ttl,
            })
            .await?
        {
            Response::RenewLease(res) => res,
            Response::Error { message } => Err(LeaseError::Backend(message)),
            _ => Err(LeaseError::Backend("unexpected response".into())),
        }
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        match self
            .send_lease_request_with_retry(Request::ReleaseLease { lease })
            .await?
        {
            Response::ReleaseLease(res) => res,
            Response::Error { message } => Err(LeaseError::Backend(message)),
            _ => Err(LeaseError::Backend("unexpected response".into())),
        }
    }
}

async fn watch_connect_and_read(
    target: RemoteTarget,
    tls_config: Option<Arc<opc_tls::ClientConfig>>,
    max_frame_size: usize,
    node_id: String,
    start_sequence: u64,
    deadline: Duration,
    tx: tokio::sync::mpsc::Sender<Result<ReplicationEntry, StoreError>>,
) -> Result<(), ProtocolError> {
    // Bound connect + handshake by the client deadline. After the handshake,
    // bounded channel sends backpressure socket reads when consumers lag.
    let open = async {
        let addr = target.resolve().await.map_err(ProtocolError::Io)?;
        let tcp = TcpStream::connect(addr).await.map_err(ProtocolError::Io)?;

        let reader: Box<dyn tokio::io::AsyncRead + Unpin + Send> =
            if let Some(tls_config) = &tls_config {
                let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
                let server_name = target.tls_server_name(addr)?;
                let tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(classify_tls_connect_error)?;
                let (mut r, mut w) = tokio::io::split(tls_stream);
                watch_handshake(&mut r, &mut w, max_frame_size, &node_id, start_sequence).await?;
                Box::new(r)
            } else {
                let (mut r, mut w) = tokio::io::split(tcp);
                watch_handshake(&mut r, &mut w, max_frame_size, &node_id, start_sequence).await?;
                Box::new(r)
            };
        Ok::<_, ProtocolError>(reader)
    };
    let mut reader = match tokio::time::timeout(deadline, open).await {
        Ok(res) => res?,
        Err(_) => {
            let _ = tx
                .send(Err(StoreError::BackendUnavailable(format!(
                    "watch handshake to {target} timed out after {deadline:?}"
                ))))
                .await;
            return Err(ProtocolError::BackendUnavailable(
                "watch handshake timed out".into(),
            ));
        }
    };

    loop {
        match read_frame::<_, Response>(&mut reader, max_frame_size).await {
            Ok(Response::WatchEntry(item)) => {
                if tx.send(item).await.is_err() {
                    break;
                }
            }
            Ok(_) => {
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
                let _ = tx
                    .send(Err(StoreError::BackendUnavailable(e.to_string())))
                    .await;
                break;
            }
        }
    }

    Ok(())
}

async fn watch_handshake<R, W>(
    reader: &mut R,
    writer: &mut W,
    max_frame_size: usize,
    node_id: &str,
    start_sequence: u64,
) -> Result<(), ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    write_frame(
        writer,
        &Request::Hello {
            contract_version: CONTRACT_VERSION,
            node_id: node_id.to_string(),
        },
    )
    .await?;
    let ack: Response = read_frame(reader, max_frame_size).await?;
    match ack {
        Response::HelloAck { contract_version } => {
            if contract_version != CONTRACT_VERSION {
                return Err(ProtocolError::VersionMismatch {
                    local: CONTRACT_VERSION,
                    remote: contract_version,
                });
            }
        }
        _ => {
            return Err(ProtocolError::UnexpectedResponse);
        }
    }

    write_frame(writer, &Request::Watch { start_sequence }).await?;

    let ack: Response = read_frame(reader, max_frame_size).await?;
    match ack {
        Response::WatchStream => {}
        Response::Error { message } => {
            return Err(ProtocolError::BackendUnavailable(message));
        }
        _ => {
            return Err(ProtocolError::UnexpectedResponse);
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
    use futures_util::FutureExt;
    use opc_session_store::BackendCapabilities;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

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
            assert!(matches!(hello, Request::Hello { .. }));
            write_frame(
                &mut stream,
                &Response::HelloAck {
                    contract_version: CONTRACT_VERSION,
                },
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
    async fn explicit_version_mismatch_clears_cached_restore_capability() {
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

        let incompatible = backend.capabilities().await;
        assert!(
            !incompatible.restore_scan,
            "an explicitly incompatible protocol must not retain restore support"
        );
        let _ = incompatible_handle.await;
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

        let legacy = backend.capabilities().await;
        assert!(
            legacy.atomic_compare_and_set,
            "cached v1 operation was lost"
        );
        assert!(
            !legacy.restore_scan,
            "v2-only restore support must be masked when fresh negotiation fails"
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
            assert!(matches!(hello, Request::Hello { .. }));
            write_frame(
                &mut stream,
                &Response::HelloAck {
                    contract_version: CONTRACT_VERSION,
                },
            )
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
            assert!(matches!(hello, Request::Hello { .. }));
            write_frame(
                &mut stream,
                &Response::HelloAck {
                    contract_version: CONTRACT_VERSION,
                },
            )
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
