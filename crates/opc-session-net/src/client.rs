use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::Stream;
use opc_session_store::backend::{
    CompareAndSet, CompareAndSetResult, ReplicationEntry, SessionBackend, SessionOp,
    SessionOpResult, WATCH_CHANNEL_CAPACITY,
};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::error::{LeaseError, StoreError};
use opc_session_store::lease::{LeaseGuard, SessionLeaseManager};
use opc_session_store::model::{OwnerId, SessionKey};

use opc_session_store::record::StoredSessionRecord;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::error::ProtocolError;
use crate::protocol::{
    read_frame, write_frame, Request, Response, CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE,
};

/// Persistent transport connection to a remote session backend.
///
/// The v0 client keeps a single connection and allows one in-flight request at
/// a time; clones of [`RemoteSessionBackend`] share this connection.
struct Connection {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
}

/// Remote session backend client.
#[derive(Clone)]
pub struct RemoteSessionBackend {
    addr: SocketAddr,
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
            .field("addr", &self.addr)
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
        Self::from_transport(addr, Some(tls_config), deadline)
    }

    /// Create a plaintext remote backend client for tests.
    ///
    /// Production replication clients must use [`RemoteSessionBackend::new`].
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(addr: SocketAddr, deadline: Option<Duration>) -> Self {
        Self::from_transport(addr, None, deadline)
    }

    fn from_transport(
        addr: SocketAddr,
        tls_config: Option<Arc<opc_tls::ClientConfig>>,
        deadline: Option<Duration>,
    ) -> Self {
        Self {
            addr,
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

    async fn send_request_with_retry(&self, req: Request) -> Result<Response, StoreError> {
        let attempts = async {
            let mut backoff_ms = 100u64;
            loop {
                match self.do_request(&req).await {
                    Ok(resp) => return Ok(resp),
                    Err(ProtocolError::Io(_)) | Err(ProtocolError::BackendUnavailable(_)) => {
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(1000);
                    }
                    Err(e) => return Err(StoreError::BackendUnavailable(e.to_string())),
                }
            }
        };
        match tokio::time::timeout(self.deadline, attempts).await {
            Ok(res) => res,
            Err(_) => Err(StoreError::BackendUnavailable(format!(
                "remote session backend {} unreachable within {:?}",
                self.addr, self.deadline
            ))),
        }
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
        let tcp = TcpStream::connect(self.addr)
            .await
            .map_err(ProtocolError::Io)?;

        let (mut reader, mut writer): (
            Box<dyn AsyncRead + Unpin + Send>,
            Box<dyn AsyncWrite + Unpin + Send>,
        ) = if let Some(tls_config) = &self.tls_config {
            let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
            let server_name = rustls_pki_types::ServerName::IpAddress(self.addr.ip().into());
            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(ProtocolError::Io)?;
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
                return Err(ProtocolError::BackendUnavailable(
                    "expected HelloAck".into(),
                ));
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

    fn cached_capabilities(&self) -> Option<BackendCapabilities> {
        self.cached_capabilities
            .read()
            .ok()
            .and_then(|cached| *cached)
    }

    fn capabilities_after_probe_failure(&self, reason: &str) -> BackendCapabilities {
        if let Some(caps) = self.cached_capabilities() {
            tracing::warn!(
                addr = %self.addr,
                reason,
                "remote capabilities probe failed; using cached capabilities"
            );
            caps
        } else {
            tracing::warn!(
                addr = %self.addr,
                reason,
                "remote capabilities probe failed before any cached success; returning minimal capabilities"
            );
            BackendCapabilities::minimal()
        }
    }
}

#[async_trait]
impl SessionBackend for RemoteSessionBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        match self.send_request_with_retry(Request::Capabilities).await {
            Ok(Response::Capabilities(caps)) => {
                self.remember_capabilities(caps);
                caps
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
        let addr = self.addr;
        let tls_config = self.tls_config.clone();
        let max_frame_size = self.max_frame_size;
        let node_id = self.node_id.clone();
        let deadline = self.deadline;

        let (tx, rx) = tokio::sync::mpsc::channel(WATCH_CHANNEL_CAPACITY);

        tokio::spawn(async move {
            let result = watch_connect_and_read(
                addr,
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
    addr: SocketAddr,
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
        let tcp = TcpStream::connect(addr).await.map_err(ProtocolError::Io)?;

        let reader: Box<dyn tokio::io::AsyncRead + Unpin + Send> =
            if let Some(tls_config) = &tls_config {
                let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
                let server_name = rustls_pki_types::ServerName::IpAddress(addr.ip().into());
                let tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(ProtocolError::Io)?;
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
                    "watch handshake to {addr} timed out after {deadline:?}"
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
            return Err(ProtocolError::BackendUnavailable(
                "expected HelloAck".into(),
            ));
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
            return Err(ProtocolError::BackendUnavailable(
                "expected WatchStream".into(),
            ));
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
        StoreError::RestoreScanPageTooLarge { .. } => "restore_scan_page_too_large",
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
