use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::StreamExt;
use opc_session_store::backend::{
    validate_replication_page_owned, validate_replication_prefix_owned, CompareAndSetResult,
};
use opc_session_store::error::{LeaseError, StoreError};
use opc_session_store::quorum::SessionStoreBackend;
use opc_session_store::{
    validate_session_ttl, ReplicaId, RestoreScanCursor, RestoreScanPage, RestoreScanRequest,
};
use opc_types::SpiffeId;
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tracing;

use crate::error::ProtocolError;
use crate::identity::{LocalReplicaBinding, SessionClusterId};
use crate::protocol::{
    ensure_frame_fits, read_frame_within, write_frame, write_frame_within, HelloRejectReason,
    Request, Response, CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE, MAX_HANDSHAKE_FRAME_SIZE,
    MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE, SESSION_NET_ALPN,
};

/// Handle to a running [`SessionReplicationServer`].
#[derive(Debug)]
pub struct ServerHandle {
    accept_handle: tokio::task::JoinHandle<()>,
    _shutdown_tx: tokio::sync::mpsc::Sender<()>,
    connection_tasks: Arc<std::sync::Mutex<ConnectionTaskRegistry>>,
}

#[derive(Debug)]
struct ConnectionTaskRegistry {
    stopping: bool,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ServerHandle {
    /// Schedule immediate cancellation of the listener and every connection.
    ///
    /// This non-blocking compatibility method returns before cancellation has
    /// completed. Use [`Self::abort_and_wait`] when subsequent work must know
    /// that the listener and all registered handlers have stopped.
    pub fn abort(&self) {
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

    /// Abort the listener and every connection, then wait for all tasks to end.
    ///
    /// When this future returns, no handler registered by this server remains
    /// alive and the bound listener has been dropped. This is the deterministic
    /// lifecycle barrier for tests and callers that must restart or probe the
    /// endpoint immediately after teardown.
    pub async fn abort_and_wait(mut self) {
        // Abort every registered handler before the first await. If the caller
        // cancels this barrier, dropping JoinHandles can detach only tasks that
        // have already received cancellation. The shared `stopping` flag also
        // prevents an accept already in progress from registering a late task.
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

    /// Request graceful listener shutdown without waiting for completion.
    ///
    /// Existing connection handlers are allowed to finish independently. Use
    /// [`Self::abort_and_wait`] when a hard completion barrier is required.
    pub fn shutdown(self) {
        drop(self._shutdown_tx);
    }
}

/// Default per-frame read deadline for accepted connections.
const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const DEFAULT_RESTORE_SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const RESTORE_SCAN_CONCURRENCY: usize = 1;
const CAS_IDEMPOTENCY_CACHE_CAPACITY: usize = 4096;

#[derive(Clone)]
struct DispatchConfig {
    binding: LocalReplicaBinding,
    max_frame_size: usize,
    idle_timeout: std::time::Duration,
    restore_scan_timeout: std::time::Duration,
    restore_scan_slots: Arc<Semaphore>,
}

#[derive(Serialize)]
enum RestoreScanResponseRef<'a> {
    ScanRestoreRecords(Result<&'a RestoreScanPage, &'a StoreError>),
}

fn bounded_restore_scan_response(
    result: Result<RestoreScanPage, StoreError>,
    request: &RestoreScanRequest,
    max_response_frame_size: usize,
) -> Result<Response, ProtocolError> {
    let mut page = match result {
        Ok(page) => page,
        Err(error) => return bounded_restore_scan_error_response(error, max_response_frame_size),
    };

    if let Err(error) = page.validate_for_request(request) {
        return bounded_restore_scan_error_response(error, max_response_frame_size);
    }

    loop {
        let response = RestoreScanResponseRef::ScanRestoreRecords(Ok(&page));
        match ensure_frame_fits(&response, max_response_frame_size) {
            Ok(()) => return Ok(Response::ScanRestoreRecords(Ok(page))),
            Err(ProtocolError::FrameTooLarge(_)) if page.records.len() > 1 => {
                let retained = (page.records.len() / 2).max(1);
                page.records.truncate(retained);
                page.loaded_count = page.records.len();
                let start = request.cursor.map(RestoreScanCursor::offset).unwrap_or(0);
                let next = start.checked_add(page.records.len()).ok_or_else(|| {
                    ProtocolError::BackendUnavailable(
                        "restore scan cursor overflowed while fitting response".to_string(),
                    )
                })?;
                page.next_cursor = Some(RestoreScanCursor::from_offset(next));
                page.complete = false;
            }
            Err(ProtocolError::FrameTooLarge(_)) => {
                return bounded_restore_scan_error_response(
                    StoreError::RestoreScanResponseTooLarge {
                        max_bytes: max_response_frame_size,
                    },
                    max_response_frame_size,
                );
            }
            Err(other) => return Err(other),
        }
    }
}

fn discard_replication_payloads_from_request(request: Request) {
    match request {
        Request::ReplicateEntry { entry } => {
            drop(entry.into_validated());
        }
        Request::RebuildReplicationState { entries } => {
            drop(validate_replication_prefix_owned(entries));
        }
        _ => {}
    }
}

fn bounded_restore_scan_error_response(
    error: StoreError,
    max_response_frame_size: usize,
) -> Result<Response, ProtocolError> {
    let response = Response::ScanRestoreRecords(Err(sanitize_restore_scan_error(error)));
    match ensure_frame_fits(&response, max_response_frame_size) {
        Ok(()) => Ok(response),
        Err(ProtocolError::FrameTooLarge(_)) => {
            let fallback = Response::ScanRestoreRecords(Err(StoreError::BackendUnavailable(
                "restore scan error exceeded the response limit".to_string(),
            )));
            ensure_frame_fits(&fallback, max_response_frame_size)?;
            Ok(fallback)
        }
        Err(other) => Err(other),
    }
}

fn sanitize_restore_scan_error(error: StoreError) -> StoreError {
    match error {
        StoreError::CapabilityNotSupported(_) => {
            StoreError::CapabilityNotSupported("restore_scan".to_string())
        }
        StoreError::BackendUnavailable(_) => {
            StoreError::BackendUnavailable("restore scan backend unavailable".to_string())
        }
        StoreError::InvalidKey(_) => {
            StoreError::InvalidKey("restore scan backend rejected a record".to_string())
        }
        StoreError::Crypto(_) => {
            StoreError::Crypto("restore scan record cryptography failed".to_string())
        }
        StoreError::Serialization(_) => {
            StoreError::Serialization("restore scan record decoding failed".to_string())
        }
        StoreError::InvalidRestoreScanRequest(_) => {
            StoreError::InvalidRestoreScanRequest("restore scan request was rejected".to_string())
        }
        StoreError::InvalidRestoreScanResponse(_) => StoreError::InvalidRestoreScanResponse(
            "restore scan backend returned an invalid page".to_string(),
        ),
        other => other,
    }
}

#[derive(Debug, Default)]
struct CasIdempotencyCache {
    entries: HashMap<String, CompareAndSetResult>,
    order: VecDeque<String>,
}

impl CasIdempotencyCache {
    fn get(&self, request_id: &str) -> Option<CompareAndSetResult> {
        self.entries.get(request_id).cloned()
    }

    fn insert_success(&mut self, request_id: String, result: CompareAndSetResult) {
        if self.entries.contains_key(&request_id) {
            return;
        }

        while self.entries.len() >= CAS_IDEMPOTENCY_CACHE_CAPACITY {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }

        self.order.push_back(request_id.clone());
        self.entries.insert(request_id, result);
    }
}

/// Networked session replication server.
pub struct SessionReplicationServer {
    backend: Arc<dyn SessionStoreBackend>,
    tls_config: Option<Arc<opc_tls::ServerConfig>>,
    binding: LocalReplicaBinding,
    max_connections: usize,
    max_frame_size: usize,
    idle_timeout: std::time::Duration,
    restore_scan_timeout: std::time::Duration,
    cas_idempotency_cache: Arc<Mutex<CasIdempotencyCache>>,
}

impl fmt::Debug for SessionReplicationServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionReplicationServer")
            .field("tls_config", &self.tls_config.is_some())
            .field("binding", &self.binding)
            .field("max_connections", &self.max_connections)
            .field("max_frame_size", &self.max_frame_size)
            .field("restore_scan_timeout", &self.restore_scan_timeout)
            .finish()
    }
}

impl SessionReplicationServer {
    /// Create a new mTLS server.
    ///
    /// `binding` selects this server's exact stable replica ID and immutable
    /// authorized member manifest. Each accepted connection must present a
    /// canonical SPIFFE identity mapped to its claimed client `ReplicaId` and
    /// must agree on this server ID and manifest scope before backend dispatch.
    /// Session caches and tickets are disabled so every accepted connection
    /// performs a full mutual-TLS certificate exchange.
    ///
    /// Production session replication must run over authenticated TLS. Use
    /// [`SessionReplicationServer::new_insecure`] only in test builds that
    /// explicitly enable the `insecure-test` feature.
    pub fn new(
        backend: Arc<dyn SessionStoreBackend>,
        tls_config: opc_tls::AuthenticatedServerConfig,
        binding: LocalReplicaBinding,
    ) -> Self {
        Self {
            backend,
            tls_config: Some(session_server_tls_config(&tls_config)),
            binding,
            max_connections: 128,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            restore_scan_timeout: DEFAULT_RESTORE_SCAN_TIMEOUT,
            cas_idempotency_cache: Arc::new(Mutex::new(CasIdempotencyCache::default())),
        }
    }

    /// Create a new plaintext server (requires `insecure-test` feature).
    #[cfg(feature = "insecure-test")]
    pub fn new_insecure(backend: Arc<dyn SessionStoreBackend>) -> Self {
        Self {
            backend,
            tls_config: None,
            binding: crate::identity::insecure_test_server_binding(),
            max_connections: 128,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            restore_scan_timeout: DEFAULT_RESTORE_SCAN_TIMEOUT,
            cas_idempotency_cache: Arc::new(Mutex::new(CasIdempotencyCache::default())),
        }
    }

    /// Set the per-frame read deadline for accepted connections. A peer that
    /// does not deliver a complete frame within this window is disconnected,
    /// freeing its connection slot.
    pub fn with_idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum duration of one cancellable backend restore-scan
    /// request. Blocking backend implementations must enforce their own work
    /// bounds; bounded SQLite/quorum scan work remains tracked in #133.
    pub fn with_restore_scan_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.restore_scan_timeout = timeout;
        self
    }

    /// Set the maximum number of concurrent connections.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the maximum frame size in bytes.
    pub fn with_max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Bind and start accepting connections.
    pub async fn listen(
        self,
        bind_addr: SocketAddr,
    ) -> std::io::Result<(ServerHandle, SocketAddr)> {
        let listener = TcpListener::bind(bind_addr).await?;
        let bound_addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
        let sem = Arc::new(Semaphore::new(self.max_connections));
        let tls_config = self.tls_config.clone();
        let backend = self.backend.clone();
        let cas_idempotency_cache = self.cas_idempotency_cache.clone();
        let dispatch_config = DispatchConfig {
            binding: self.binding.clone(),
            max_frame_size: self.max_frame_size,
            idle_timeout: self.idle_timeout,
            restore_scan_timeout: self.restore_scan_timeout,
            restore_scan_slots: Arc::new(Semaphore::new(RESTORE_SCAN_CONCURRENCY)),
        };
        let connection_tasks = Arc::new(std::sync::Mutex::new(ConnectionTaskRegistry {
            stopping: false,
            handles: Vec::new(),
        }));
        let connection_tasks_clone = connection_tasks.clone();

        let handle = tokio::spawn(async move {
            loop {
                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };

                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => break,
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, peer)) => {
                                let backend = backend.clone();
                                let tls_config = tls_config.clone();
                                let cas_idempotency_cache = cas_idempotency_cache.clone();
                                let dispatch_config = dispatch_config.clone();
                                tracing::debug!(%peer, "accepted connection");
                                let mut registry = connection_tasks_clone
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                registry.handles.retain(|handle| !handle.is_finished());
                                if registry.stopping {
                                    break;
                                }
                                let conn_handle = tokio::spawn(async move {
                                    let _permit = permit;
                                    if let Err(e) = handle_connection(
                                        backend,
                                        stream,
                                        tls_config,
                                        cas_idempotency_cache,
                                        dispatch_config,
                                    )
                                    .await
                                    {
                                        tracing::debug!(%peer, error = ?e, "connection handler exited");
                                    }
                                });
                                registry.handles.push(conn_handle);
                            }
                            Err(e) => {
                                tracing::warn!(error = ?e, "accept failed");
                            }
                        }
                    }
                }
            }
        });

        Ok((
            ServerHandle {
                accept_handle: handle,
                _shutdown_tx: shutdown_tx,
                connection_tasks,
            },
            bound_addr,
        ))
    }
}

fn session_server_tls_config(
    config: &opc_tls::AuthenticatedServerConfig,
) -> Arc<opc_tls::ServerConfig> {
    let mut config = config.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    // A resumed session may authenticate from cached state rather than the
    // certificate currently selected by the reloadable SVID resolver. Disable
    // every server-side resumption mechanism so reconnect always observes and
    // verifies the live peer certificate.
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

enum ConnectionPeerIdentity {
    Authenticated(SpiffeId),
    InsecureTest,
}

async fn handle_connection(
    backend: Arc<dyn SessionStoreBackend>,
    stream: TcpStream,
    tls_config: Option<Arc<opc_tls::ServerConfig>>,
    cas_idempotency_cache: Arc<Mutex<CasIdempotencyCache>>,
    dispatch_config: DispatchConfig,
) -> Result<(), ProtocolError> {
    let idle_timeout = dispatch_config.idle_timeout;
    if let Some(tls_config) = tls_config {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let tls_stream = tokio::time::timeout(idle_timeout, acceptor.accept(stream))
            .await
            .map_err(|_| {
                ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                ))
            })?
            .map_err(ProtocolError::Io)?;
        if tls_stream.get_ref().1.alpn_protocol() != Some(SESSION_NET_ALPN) {
            return Err(ProtocolError::Authentication);
        }
        let peer_spiffe = opc_tls::peer_spiffe_id_from_server_connection(tls_stream.get_ref().1)
            .map_err(|_| ProtocolError::Authentication)?;
        let (mut r, mut w) = tokio::io::split(tls_stream);
        dispatch(
            backend,
            cas_idempotency_cache,
            &mut r,
            &mut w,
            ConnectionPeerIdentity::Authenticated(peer_spiffe),
            dispatch_config,
        )
        .await
    } else {
        let (mut r, mut w) = tokio::io::split(stream);
        dispatch(
            backend,
            cas_idempotency_cache,
            &mut r,
            &mut w,
            ConnectionPeerIdentity::InsecureTest,
            dispatch_config,
        )
        .await
    }
}

async fn dispatch<R, W>(
    backend: Arc<dyn SessionStoreBackend>,
    cas_idempotency_cache: Arc<Mutex<CasIdempotencyCache>>,
    reader: &mut R,
    writer: &mut W,
    peer_identity: ConnectionPeerIdentity,
    dispatch_config: DispatchConfig,
) -> Result<(), ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let DispatchConfig {
        binding,
        max_frame_size,
        idle_timeout,
        restore_scan_timeout,
        restore_scan_slots,
    } = dispatch_config;

    // Hello handshake — bounded so a peer that connects and stalls is reaped.
    let hello: Request = read_frame_within(
        reader,
        max_frame_size.min(MAX_HANDSHAKE_FRAME_SIZE),
        idle_timeout,
    )
    .await?;
    match hello {
        Request::Hello {
            contract_version,
            node_id,
            expected_server_replica_id,
            cluster_id,
            configuration_id,
            handshake_nonce,
        } => {
            if contract_version != CONTRACT_VERSION {
                write_frame_within(
                    writer,
                    &Response::HelloAck {
                        contract_version: CONTRACT_VERSION,
                        server_replica_id: None,
                        accepted_client_replica_id: None,
                        cluster_id: None,
                        configuration_id: None,
                        handshake_nonce: None,
                    },
                    idle_timeout,
                )
                .await?;
                return Err(ProtocolError::VersionMismatch {
                    local: CONTRACT_VERSION,
                    remote: contract_version,
                });
            }

            let Some(expected_server_replica_id) = expected_server_replica_id else {
                return reject_hello(writer, HelloRejectReason::Malformed, idle_timeout).await;
            };
            let Some(cluster_id) = cluster_id else {
                return reject_hello(writer, HelloRejectReason::Malformed, idle_timeout).await;
            };
            let Some(configuration_id) = configuration_id else {
                return reject_hello(writer, HelloRejectReason::Malformed, idle_timeout).await;
            };
            let Some(handshake_nonce) = handshake_nonce else {
                return reject_hello(writer, HelloRejectReason::Malformed, idle_timeout).await;
            };

            let client_replica_id = match ReplicaId::new(node_id) {
                Ok(replica_id) => replica_id,
                Err(_) => {
                    return reject_hello(writer, HelloRejectReason::Malformed, idle_timeout).await;
                }
            };
            let expected_server_replica_id = match ReplicaId::new(expected_server_replica_id) {
                Ok(replica_id) => replica_id,
                Err(_) => {
                    return reject_hello(writer, HelloRejectReason::Malformed, idle_timeout).await;
                }
            };
            if SessionClusterId::new(cluster_id.clone()).is_err()
                || !is_configuration_id(&configuration_id)
            {
                return reject_hello(writer, HelloRejectReason::Malformed, idle_timeout).await;
            }

            let configured_client_spiffe = binding.member_spiffe_id(&client_replica_id);
            let authenticated_client_matches = match (&peer_identity, configured_client_spiffe) {
                (ConnectionPeerIdentity::Authenticated(actual), Some(configured)) => {
                    actual.as_str() == configured.as_str()
                }
                (ConnectionPeerIdentity::InsecureTest, Some(_)) => true,
                _ => false,
            };
            let scope_matches = expected_server_replica_id == *binding.local_replica_id()
                && cluster_id == binding.cluster_id().as_str()
                && configuration_id == binding.configuration_id().to_hex();
            if !authenticated_client_matches || !scope_matches {
                return reject_hello(writer, HelloRejectReason::Authentication, idle_timeout).await;
            }

            write_frame_within(
                writer,
                &Response::HelloAck {
                    contract_version: CONTRACT_VERSION,
                    server_replica_id: Some(binding.local_replica_id().as_str().to_string()),
                    accepted_client_replica_id: Some(client_replica_id.as_str().to_string()),
                    cluster_id: Some(binding.cluster_id().as_str().to_string()),
                    configuration_id: Some(binding.configuration_id().to_hex()),
                    handshake_nonce: Some(handshake_nonce),
                },
                idle_timeout,
            )
            .await?;
        }
        request => {
            discard_replication_payloads_from_request(request);
            return reject_hello(writer, HelloRejectReason::Malformed, idle_timeout).await;
        }
    }

    // Dispatch loop
    loop {
        let req: Request = match read_frame_within(reader, max_frame_size, idle_timeout).await {
            Ok(r) => r,
            Err(ProtocolError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        match req {
            Request::Capabilities => {
                let mut caps = backend.capabilities().await;
                if max_frame_size < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
                    caps.restore_scan = false;
                }
                write_frame(writer, &Response::Capabilities(caps)).await?;
            }
            Request::Get { key } => {
                let res = backend.get(&key).await;
                write_frame(writer, &Response::Get(res)).await?;
            }
            Request::CompareAndSet { op, request_id } => {
                if let Some(request_id) = request_id {
                    let cached = { cas_idempotency_cache.lock().await.get(&request_id) };
                    if let Some(cached) = cached {
                        write_frame(writer, &Response::CompareAndSet(Ok(cached))).await?;
                        continue;
                    }

                    let res = backend.compare_and_set(op).await;
                    if matches!(res, Ok(CompareAndSetResult::Success)) {
                        cas_idempotency_cache
                            .lock()
                            .await
                            .insert_success(request_id, CompareAndSetResult::Success);
                    }
                    write_frame(writer, &Response::CompareAndSet(res)).await?;
                    continue;
                }

                let res = backend.compare_and_set(op).await;
                write_frame(writer, &Response::CompareAndSet(res)).await?;
            }
            Request::DeleteFenced { lease } => {
                let res = backend.delete_fenced(&lease).await;
                write_frame(writer, &Response::DeleteFenced(res)).await?;
            }
            Request::RefreshTtl { lease, ttl } => {
                let res = match validate_session_ttl(ttl) {
                    Ok(()) => backend.refresh_ttl(&lease, ttl).await,
                    Err(error) => Err(error),
                };
                write_frame(writer, &Response::RefreshTtl(res)).await?;
            }
            Request::Batch { ops } => {
                let res = match ops.iter().try_for_each(|op| op.validate_ttls()) {
                    Ok(()) => backend.batch(ops).await,
                    Err(error) => Err(error),
                };
                write_frame(writer, &Response::Batch(res)).await?;
            }
            Request::ScanRestoreRecords {
                request: wire_request,
                max_response_frame_size,
            } => {
                let client_max = usize::try_from(max_response_frame_size).map_err(|_| {
                    ProtocolError::BackendUnavailable(
                        "restore scan response limit is not representable".to_string(),
                    )
                })?;
                let effective_max = client_max.min(max_frame_size);
                if effective_max < MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE {
                    return Err(ProtocolError::FrameTooLarge(
                        MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
                    ));
                }

                let request = match RestoreScanRequest::try_from(wire_request) {
                    Ok(request) => request,
                    Err(error) => {
                        let response = bounded_restore_scan_error_response(error, effective_max)?;
                        write_frame_within(writer, &response, idle_timeout).await?;
                        continue;
                    }
                };

                let permit = match restore_scan_slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let response = bounded_restore_scan_error_response(
                            StoreError::BackendUnavailable(
                                "restore scan capacity exhausted".to_string(),
                            ),
                            effective_max,
                        )?;
                        write_frame_within(writer, &response, idle_timeout).await?;
                        continue;
                    }
                };
                let mut backend_request = request.clone();
                let frame_limited_records =
                    (effective_max / MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE).max(1);
                backend_request.limit = backend_request.limit.min(frame_limited_records);
                let result = match tokio::time::timeout(
                    restore_scan_timeout,
                    backend.scan_restore_records(backend_request),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_elapsed) => Err(StoreError::BackendUnavailable(
                        "restore scan exceeded the server deadline".to_string(),
                    )),
                };
                let response = bounded_restore_scan_response(result, &request, effective_max)?;
                drop(permit);
                write_frame_within(writer, &response, idle_timeout).await?;
            }
            Request::MaxReplicationSequence => {
                let res = backend.max_replication_sequence().await;
                write_frame(writer, &Response::MaxReplicationSequence(res)).await?;
            }
            Request::GetReplicationLog { start, limit } => {
                let res = match backend.get_replication_log(start, limit).await {
                    Ok(entries) => validate_replication_page_owned(entries),
                    Err(error) => Err(error),
                };
                write_frame(writer, &Response::GetReplicationLog(res)).await?;
            }
            Request::ReplicateEntry { entry } => {
                let res = match entry.into_validated() {
                    Ok(entry) => backend.replicate_entry(entry).await,
                    Err(error) => Err(error),
                };
                write_frame(writer, &Response::ReplicateEntry(res)).await?;
            }
            Request::RebuildReplicationState { entries } => {
                let res = match validate_replication_prefix_owned(entries) {
                    Ok(entries) => backend.rebuild_replication_state(entries).await,
                    Err(error) => Err(error),
                };
                write_frame(writer, &Response::RebuildReplicationState(res)).await?;
            }
            Request::Watch { start_sequence } => match backend.watch(start_sequence).await {
                Ok(mut stream) => {
                    write_frame(writer, &Response::WatchStream).await?;
                    while let Some(item) = stream.next().await {
                        let item =
                            item.and_then(opc_session_store::ReplicationEntry::into_validated);
                        if write_frame(writer, &Response::WatchEntry(item))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
                Err(e) => {
                    write_frame(writer, &Response::WatchEntry(Err(e))).await?;
                }
            },
            Request::NextLeaseInfo => {
                let res = backend.next_lease_info().await;
                write_frame(writer, &Response::NextLeaseInfo(res)).await?;
            }
            Request::AcquireLease { key, owner, ttl } => {
                let res = match validate_session_ttl(ttl) {
                    Ok(()) => backend.acquire(&key, owner, ttl).await,
                    Err(error) => Err(LeaseError::from(error)),
                };
                write_frame(writer, &Response::AcquireLease(res)).await?;
            }
            Request::RenewLease { lease, ttl } => {
                let res = match validate_session_ttl(ttl) {
                    Ok(()) => backend.renew(&lease, ttl).await,
                    Err(error) => Err(LeaseError::from(error)),
                };
                write_frame(writer, &Response::RenewLease(res)).await?;
            }
            Request::ReleaseLease { lease } => {
                let res = backend.release(lease).await;
                write_frame(writer, &Response::ReleaseLease(res)).await?;
            }
            Request::Hello { .. } => {
                return reject_hello(writer, HelloRejectReason::Malformed, idle_timeout).await;
            }
        }
    }

    Ok(())
}

fn is_configuration_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn reject_hello<W>(
    writer: &mut W,
    reason: HelloRejectReason,
    timeout: std::time::Duration,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    write_frame_within(writer, &Response::HelloRejected { reason }, timeout).await?;
    Err(ProtocolError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use opc_session_store::{
        EncryptedSessionPayload, FenceToken, Generation, OwnerId, SessionKey, SessionKeyType,
        StateClass, StateType, StoredSessionRecord,
    };
    use opc_types::{NetworkFunctionKind, TenantId};

    fn restore_record(stable_id: &'static [u8], payload_len: usize) -> StoredSessionRecord {
        StoredSessionRecord {
            key: SessionKey {
                tenant: TenantId::from_static("tenant-a"),
                nf_kind: NetworkFunctionKind::from_static("smf"),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(stable_id),
            },
            generation: Generation::new(1),
            owner: OwnerId::new("owner-a").expect("owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("pdu-session"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(vec![7; payload_len]),
        }
    }

    #[test]
    fn cas_idempotency_cache_retains_successes_with_bound() {
        let mut cache = CasIdempotencyCache::default();

        cache.insert_success("first".into(), CompareAndSetResult::Success);
        assert_eq!(cache.get("first"), Some(CompareAndSetResult::Success));

        for idx in 0..CAS_IDEMPOTENCY_CACHE_CAPACITY {
            cache.insert_success(format!("request-{idx}"), CompareAndSetResult::Success);
        }

        assert_eq!(cache.entries.len(), CAS_IDEMPOTENCY_CACHE_CAPACITY);
        assert_eq!(cache.get("first"), None);
        assert_eq!(cache.get("request-0"), Some(CompareAndSetResult::Success));
    }

    #[test]
    fn bounded_restore_scan_response_truncates_and_advances_cursor() {
        let request = RestoreScanRequest {
            scope: Default::default(),
            cursor: Some(RestoreScanCursor::from_offset(7)),
            limit: 2,
        };
        let first = restore_record(b"a", 64);
        let second = restore_record(b"b", 64);
        let full_page = RestoreScanPage::new(vec![first.clone(), second], 0, None);
        let expected_prefix =
            RestoreScanPage::new(vec![first], 0, Some(RestoreScanCursor::from_offset(8)));
        let budget = serde_json::to_vec(&Response::ScanRestoreRecords(Ok(expected_prefix.clone())))
            .expect("encode prefix")
            .len();
        assert!(
            serde_json::to_vec(&Response::ScanRestoreRecords(Ok(full_page.clone())))
                .expect("encode full page")
                .len()
                > budget
        );

        let response = bounded_restore_scan_response(Ok(full_page), &request, budget)
            .expect("bounded response");
        assert!(matches!(
            response,
            Response::ScanRestoreRecords(Ok(page)) if page == expected_prefix
        ));
    }

    #[test]
    fn borrowed_restore_response_has_the_owned_wire_shape() {
        let page = RestoreScanPage::new(vec![restore_record(b"a", 8)], 0, None);
        let borrowed = RestoreScanResponseRef::ScanRestoreRecords(Ok(&page));
        let owned = Response::ScanRestoreRecords(Ok(page.clone()));

        assert_eq!(
            serde_json::to_vec(&borrowed).expect("encode borrowed response"),
            serde_json::to_vec(&owned).expect("encode owned response")
        );
    }

    #[test]
    fn single_oversized_restore_record_returns_a_bounded_typed_error() {
        let request = RestoreScanRequest::all(1);
        let page = RestoreScanPage::new(vec![restore_record(b"large", 2048)], 0, None);

        let response =
            bounded_restore_scan_response(Ok(page), &request, MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE)
                .expect("bounded response");
        assert!(matches!(
            response,
            Response::ScanRestoreRecords(Err(StoreError::RestoreScanResponseTooLarge {
                max_bytes: MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE
            }))
        ));
    }

    #[test]
    fn backend_error_text_is_replaced_with_a_fixed_message() {
        let response = bounded_restore_scan_response(
            Err(StoreError::BackendUnavailable(
                "secret database path and schema details".to_string(),
            )),
            &RestoreScanRequest::all(1),
            MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
        )
        .expect("bounded error response");

        assert!(matches!(
            response,
            Response::ScanRestoreRecords(Err(StoreError::BackendUnavailable(message)))
                if message == "restore scan backend unavailable"
        ));
    }
}
