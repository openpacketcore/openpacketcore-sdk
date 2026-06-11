use crate::error::PersistError;
use crate::preflight::PersistCapabilities;
use crate::types::{AuditRecord, CommitRecord, ConfigStore, RollbackTarget, StoredConfig};
use async_trait::async_trait;
use opc_types::TxId;
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::prelude::*;

use super::identity::{
    build_client_tls_connector, extract_spiffe_id_from_cert_der, parse_local_spiffe_profile,
    parse_spiffe_id,
};
use super::{
    AppendEntriesRequest, AppendEntriesResponse, ConsensusConfigStore, ConsensusMetrics,
    ConsensusOp, ConsensusPeer, InstallSnapshotRequest, InstallSnapshotResponse, NodeIdentity,
    RequestVoteRequest, RequestVoteResponse, Role, TimeoutNowRequest, TimeoutNowResponse,
};

const MAX_RPC_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RpcRequest {
    RequestVote(RequestVoteRequest),
    AppendEntries(AppendEntriesRequest),
    InstallSnapshot(InstallSnapshotRequest),
    LoadLatest,
    LoadRollback(RollbackTarget),
    TimeoutNow(TimeoutNowRequest),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RpcResponse {
    RequestVote(Result<RequestVoteResponse, String>),
    AppendEntries(Result<AppendEntriesResponse, String>),
    InstallSnapshot(Result<InstallSnapshotResponse, String>),
    LoadLatest(Result<Option<StoredConfig>, String>),
    LoadRollback(Result<StoredConfig, String>),
    TimeoutNow(Result<TimeoutNowResponse, String>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    pub sender_node_id: usize,
    pub target_node_id: usize,
    pub cluster_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert_pem: Option<String>,
    pub request: RpcRequest,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatedResponse {
    pub response: RpcResponse,
}

#[derive(Debug, Clone)]
pub struct AuthInfo {
    pub local_node_id: usize,
    pub local_cluster_id: String,
    pub client_cert_pem: String,
}

pub struct TcpPeer {
    pub node_id: usize,
    pub addr: String,
    pub timeout: std::time::Duration,
    pub auth_info: Arc<tokio::sync::Mutex<Option<AuthInfo>>>,
    pub identity: Arc<tokio::sync::Mutex<Option<NodeIdentity>>>,
    pub tls_connector: Arc<tokio::sync::Mutex<Option<tokio_rustls::TlsConnector>>>,
}

impl std::fmt::Debug for TcpPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpPeer")
            .field("node_id", &self.node_id)
            .field("addr", &self.addr)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl TcpPeer {
    pub fn new(node_id: usize, addr: String, timeout: std::time::Duration) -> Self {
        Self {
            node_id,
            addr,
            timeout,
            auth_info: Arc::new(tokio::sync::Mutex::new(None)),
            identity: Arc::new(tokio::sync::Mutex::new(None)),
            tls_connector: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}

pub fn redact_error<E: std::fmt::Display>(e: E) -> PersistError {
    let err_str = e.to_string();
    let err_lower = err_str.to_lowercase();
    if err_str.contains('/')
        || err_str.contains('\\')
        || err_lower.contains("pem")
        || err_lower.contains("certificate")
        || err_lower.contains("cert")
        || err_lower.contains("key")
        || err_lower.contains("token")
        || err_lower.contains("db")
        || err_lower.contains("sqlite")
        || err_lower.contains("tls")
        || err_lower.contains("rustls")
        || err_lower.contains("handshake")
        || err_lower.contains("spiffe")
        || err_lower.contains("validity")
        || err_lower.contains("expired")
        || err_lower.contains("valid")
        || err_lower.contains("dns")
        || err_lower.contains("san")
        || err_lower.contains("unauthenticated")
    {
        PersistError::io("RPC operation failed with redacted safety error")
    } else {
        PersistError::io(format!("RPC operation failed: {}", err_str))
    }
}

async fn send_rpc(
    peer: &TcpPeer,
    req: RpcRequest,
    timeout_dur: std::time::Duration,
) -> Result<RpcResponse, PersistError> {
    let mut attempt = 0;
    let max_attempts = 3;
    let mut delay = std::time::Duration::from_millis(50);

    loop {
        attempt += 1;
        match send_rpc_once(peer, &req, timeout_dur).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                if attempt >= max_attempts {
                    return Err(redact_error(e));
                }
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
}

async fn send_rpc_once(
    peer: &TcpPeer,
    req: &RpcRequest,
    timeout_dur: std::time::Duration,
) -> Result<RpcResponse, PersistError> {
    let socket_future = tokio::net::TcpStream::connect(&peer.addr);
    let tcp_stream = tokio::time::timeout(timeout_dur, socket_future)
        .await
        .map_err(|_| redact_error(PersistError::io("connection timeout")))?
        .map_err(|e| redact_error(PersistError::io(e.to_string())))?;

    let connector = {
        let mut conn_guard = peer.tls_connector.lock().await;
        if let Some(ref conn) = *conn_guard {
            conn.clone()
        } else {
            let identity_guard = peer.identity.lock().await;
            let identity = identity_guard.as_ref().ok_or_else(|| {
                PersistError::inconsistent_state("peer identity not initialized for TLS")
            })?;
            let connector = build_client_tls_connector(identity, peer.node_id)?;
            *conn_guard = Some(connector.clone());
            connector
        }
    };

    let host = peer.addr.split(':').next().unwrap_or("127.0.0.1");
    let server_name = ServerName::try_from(host)
        .map_err(|e| redact_error(PersistError::io(format!("invalid server name: {}", e))))?
        .to_owned();

    let tls_stream_future = connector.connect(server_name, tcp_stream);
    let mut stream = tokio::time::timeout(timeout_dur, tls_stream_future)
        .await
        .map_err(|_| redact_error(PersistError::io("TLS handshake timeout")))?
        .map_err(|e| redact_error(PersistError::io(format!("TLS handshake failed: {}", e))))?;

    let auth_req = {
        let auth_guard = peer.auth_info.lock().await;
        let auth = auth_guard.as_ref().ok_or_else(|| {
            PersistError::inconsistent_state("peer auth credentials not initialized")
        })?;

        AuthenticatedRequest {
            sender_node_id: auth.local_node_id,
            target_node_id: peer.node_id,
            cluster_id: auth.local_cluster_id.clone(),
            spiffe_id: None,
            client_cert_pem: None,
            request: req.clone(),
        }
    };

    let bytes = serde_json::to_vec(&auth_req)
        .map_err(|e| redact_error(PersistError::inconsistent_state(e.to_string())))?;
    if bytes.len() > MAX_RPC_FRAME_BYTES {
        return Err(PersistError::io("RPC request frame exceeds maximum size"));
    }

    let mut payload = (bytes.len() as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&bytes);

    let write_fut = stream.write_all(&payload);
    tokio::time::timeout(timeout_dur, write_fut)
        .await
        .map_err(|_| redact_error(PersistError::io("write timeout")))?
        .map_err(|e| redact_error(PersistError::io(e.to_string())))?;

    let mut len_buf = [0u8; 4];
    let read_len_fut = stream.read_exact(&mut len_buf);
    tokio::time::timeout(timeout_dur, read_len_fut)
        .await
        .map_err(|_| redact_error(PersistError::io("read timeout for length")))?
        .map_err(|e| redact_error(PersistError::io(e.to_string())))?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_RPC_FRAME_BYTES {
        return Err(PersistError::io("RPC response frame exceeds maximum size"));
    }
    let mut resp_buf = vec![0u8; len];
    let read_payload_fut = stream.read_exact(&mut resp_buf);
    tokio::time::timeout(timeout_dur, read_payload_fut)
        .await
        .map_err(|_| redact_error(PersistError::io("read timeout for payload")))?
        .map_err(|e| redact_error(PersistError::io(e.to_string())))?;

    let auth_resp: AuthenticatedResponse = serde_json::from_slice(&resp_buf)
        .map_err(|e| redact_error(PersistError::inconsistent_state(e.to_string())))?;

    Ok(auth_resp.response)
}

#[async_trait]
impl ConsensusPeer for TcpPeer {
    fn node_id(&self) -> usize {
        self.node_id
    }

    async fn set_auth(
        &self,
        local_node_id: usize,
        local_cluster_id: String,
        client_cert_pem: String,
    ) -> Result<(), PersistError> {
        let mut guard = self.auth_info.lock().await;
        *guard = Some(AuthInfo {
            local_node_id,
            local_cluster_id,
            client_cert_pem,
        });
        Ok(())
    }

    async fn set_identity(&self, identity: NodeIdentity) -> Result<(), PersistError> {
        let mut guard = self.identity.lock().await;
        *guard = Some(identity);
        let mut conn_guard = self.tls_connector.lock().await;
        *conn_guard = None; // Reset cached connector
        Ok(())
    }

    async fn request_vote(
        &self,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, PersistError> {
        let resp = send_rpc(self, RpcRequest::RequestVote(req), self.timeout).await?;
        match resp {
            RpcResponse::RequestVote(res) => res.map_err(PersistError::io),
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn append_entries(
        &self,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, PersistError> {
        let resp = send_rpc(self, RpcRequest::AppendEntries(req), self.timeout).await?;
        match resp {
            RpcResponse::AppendEntries(res) => res.map_err(PersistError::io),
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn install_snapshot(
        &self,
        req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, PersistError> {
        let resp = send_rpc(self, RpcRequest::InstallSnapshot(req), self.timeout).await?;
        match resp {
            RpcResponse::InstallSnapshot(res) => res.map_err(PersistError::io),
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn load_latest_consensus_rpc(&self) -> Result<Option<StoredConfig>, PersistError> {
        let resp = send_rpc(self, RpcRequest::LoadLatest, self.timeout).await?;
        match resp {
            RpcResponse::LoadLatest(res) => res.map_err(PersistError::io),
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn load_rollback_consensus_rpc(
        &self,
        target: RollbackTarget,
    ) -> Result<StoredConfig, PersistError> {
        let resp = send_rpc(self, RpcRequest::LoadRollback(target), self.timeout).await?;
        match resp {
            RpcResponse::LoadRollback(res) => res.map_err(PersistError::io),
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn timeout_now(
        &self,
        req: TimeoutNowRequest,
    ) -> Result<TimeoutNowResponse, PersistError> {
        let resp = send_rpc(self, RpcRequest::TimeoutNow(req), self.timeout).await?;
        match resp {
            RpcResponse::TimeoutNow(res) => res.map_err(PersistError::io),
            _ => Err(PersistError::io("invalid response variant")),
        }
    }
}

pub struct ActiveConnectionGuard {
    metrics: Arc<ConsensusMetrics>,
}

impl ActiveConnectionGuard {
    pub fn new(metrics: Arc<ConsensusMetrics>) -> Self {
        metrics
            .server_active_connections
            .fetch_add(1, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.metrics
            .server_active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct TcpRpcServer {
    store: Arc<ConsensusConfigStore>,
    addr: String,
}

impl TcpRpcServer {
    pub fn new(store: Arc<ConsensusConfigStore>, addr: String) -> Self {
        Self { store, addr }
    }

    pub async fn start(&self) -> Result<tokio::task::JoinHandle<()>, PersistError> {
        let store = Arc::clone(&self.store);
        let addr = self.addr.clone();

        {
            let guard = self.store.server_shutdown.lock().await;
            if guard.is_some() {
                self.store
                    .metrics
                    .server_start_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PersistError::inconsistent_state(
                    "TCP RPC server already running",
                ));
            }
        }

        let socket = match tokio::net::TcpSocket::new_v4() {
            Ok(s) => s,
            Err(e) => {
                self.store
                    .metrics
                    .server_start_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PersistError::io(e.to_string()));
            }
        };
        if let Err(e) = socket.set_reuseaddr(true) {
            self.store
                .metrics
                .server_start_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::io(e.to_string()));
        }
        #[cfg(unix)]
        if let Err(e) = socket.set_reuseport(true) {
            self.store
                .metrics
                .server_start_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::io(e.to_string()));
        }
        let std_addr: std::net::SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                self.store
                    .metrics
                    .server_start_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PersistError::io(e.to_string()));
            }
        };
        if let Err(e) = socket.bind(std_addr) {
            self.store
                .metrics
                .server_start_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::io(e.to_string()));
        }
        let listener = match socket.listen(1024) {
            Ok(l) => l,
            Err(e) => {
                self.store
                    .metrics
                    .server_start_failures
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PersistError::io(e.to_string()));
            }
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut guard = self.store.server_shutdown.lock().await;
            *guard = Some(tx);
        }

        let handle = tokio::spawn(async move {
            let conn_semaphore = Arc::new(tokio::sync::Semaphore::new(100));
            let mut rx = rx;

            loop {
                tokio::select! {
                    res = listener.accept() => {
                        match res {
                            Ok((stream, _)) => {
                                let store = Arc::clone(&store);
                                let sem = Arc::clone(&conn_semaphore);
                                tokio::spawn(async move {
                                    let _permit = match sem.try_acquire() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            tracing::debug!("server concurrency limit reached");
                                            store.metrics.server_rejected_connections.fetch_add(1, Ordering::Relaxed);
                                            return;
                                        }
                                    };
                                    let _guard = ActiveConnectionGuard::new(Arc::clone(&store.metrics));
                                    let res = async {
                                        let acceptor = store.build_tls_acceptor().await?;
                                        let tls_stream = tokio::time::timeout(
                                            std::time::Duration::from_secs(5),
                                            acceptor.accept(stream)
                                        ).await
                                        .map_err(|_| {
                                            tracing::debug!("server TLS handshake timeout");
                                            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                                            store.metrics.server_rejected_connections.fetch_add(1, Ordering::Relaxed);
                                            redact_error(PersistError::io("TLS handshake timeout"))
                                        })?
                                        .map_err(|e| {
                                            tracing::debug!("server TLS handshake failed: {}", e);
                                            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                                            store.metrics.server_rejected_connections.fetch_add(1, Ordering::Relaxed);
                                            redact_error(PersistError::io(format!("TLS handshake failed: {}", e)))
                                        })?;

                                        Self::handle_connection(tls_stream, &store).await
                                    }.await;
                                    match res {
                                        Ok(()) => {}
                                        Err(e) => {
                                            tracing::debug!("Connection handler err: {:?}", e);
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::debug!("Accept error: {:?}", e);
                                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            }
                        }
                    }
                    _ = &mut rx => {
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }

    pub async fn shutdown(&self) {
        let mut guard = self.store.server_shutdown.lock().await;
        if let Some(tx) = guard.take() {
            if tx.send(()).is_err() {
                self.store
                    .metrics
                    .server_shutdown_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.store
                .metrics
                .server_shutdown_failures
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub async fn shutdown_server(&self) {
        self.shutdown().await;
    }

    async fn verify_peer_identity(
        req: &AuthenticatedRequest,
        store: &ConsensusConfigStore,
        extracted_spiffe_id: &str,
        cert_valid: bool,
    ) -> Result<(), PersistError> {
        let local_membership = match store.inner.consensus_get_active_membership().await {
            Ok(Some(m)) => m,
            _ => {
                store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                store
                    .metrics
                    .server_rejected_connections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PersistError::inconsistent_state(
                    "local membership not found",
                ));
            }
        };

        if !cert_valid {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "unauthenticated: expired or not-yet-valid certificate",
            ));
        }

        if req.cluster_id != local_membership.cluster_id {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "unauthenticated: wrong cluster",
            ));
        }

        if req.target_node_id != store.node_id {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "unauthenticated: target node ID mismatch",
            ));
        }

        let peer_spiffe = match parse_spiffe_id(extracted_spiffe_id) {
            Ok(parsed) => parsed,
            Err(e) => {
                store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                store
                    .metrics
                    .server_rejected_connections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };

        let local_spiffe = {
            let identity_guard = store.identity.read().await;
            let identity = identity_guard.as_ref().ok_or_else(|| {
                store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                store
                    .metrics
                    .server_rejected_connections
                    .fetch_add(1, Ordering::Relaxed);
                PersistError::inconsistent_state("local identity not initialized")
            })?;
            match parse_local_spiffe_profile(identity) {
                Ok(parsed) => parsed,
                Err(e) => {
                    store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                    store
                        .metrics
                        .server_rejected_connections
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            }
        };

        if !peer_spiffe.same_workload_profile(&local_spiffe) {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "unauthenticated: SPIFFE workload profile mismatch",
            ));
        }

        if peer_spiffe.instance_id != req.sender_node_id {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "unauthenticated: node_id mismatch",
            ));
        }

        let is_voter = local_membership
            .voting_members
            .contains(&req.sender_node_id)
            || local_membership
                .old_voting_members
                .as_ref()
                .map(|ov| ov.contains(&req.sender_node_id))
                .unwrap_or(false);
        let is_non_voter = local_membership
            .non_voting_members
            .contains(&req.sender_node_id);
        if !is_voter && !is_non_voter {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "unauthenticated: unknown node",
            ));
        }

        Ok(())
    }

    fn auth_error_response(req: &RpcRequest, message: String) -> RpcResponse {
        match req {
            RpcRequest::RequestVote(_) => RpcResponse::RequestVote(Err(message)),
            RpcRequest::AppendEntries(_) => RpcResponse::AppendEntries(Err(message)),
            RpcRequest::InstallSnapshot(_) => RpcResponse::InstallSnapshot(Err(message)),
            RpcRequest::LoadLatest => RpcResponse::LoadLatest(Err(message)),
            RpcRequest::LoadRollback(_) => RpcResponse::LoadRollback(Err(message)),
            RpcRequest::TimeoutNow(_) => RpcResponse::TimeoutNow(Err(message)),
        }
    }

    async fn handle_connection(
        mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        store: &ConsensusConfigStore,
    ) -> Result<(), PersistError> {
        let (_, conn) = stream.get_ref();
        let peer_certs = conn.peer_certificates().ok_or_else(|| {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            PersistError::inconsistent_state("unauthenticated: no client certificate presented")
        })?;

        if peer_certs.is_empty() {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "unauthenticated: empty client certificate chain",
            ));
        }

        let cert_der = &peer_certs[0];
        let (_, x509) = X509Certificate::from_der(cert_der.as_ref()).map_err(|e| {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            PersistError::inconsistent_state(format!("failed to parse client certificate: {}", e))
        })?;

        let cert_valid = x509.validity().is_valid();
        let spiffe_id = extract_spiffe_id_from_cert_der(cert_der.as_ref()).inspect_err(|_e| {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
        })?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(redact_error)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_RPC_FRAME_BYTES {
            return Err(PersistError::io("RPC request frame exceeds maximum size"));
        }

        let mut req_buf = vec![0u8; len];
        stream
            .read_exact(&mut req_buf)
            .await
            .map_err(redact_error)?;

        let auth_req: AuthenticatedRequest =
            serde_json::from_slice(&req_buf).map_err(redact_error)?;

        if let Err(e) = Self::verify_peer_identity(&auth_req, store, &spiffe_id, cert_valid).await {
            let redacted = redact_error(e);
            let resp = AuthenticatedResponse {
                response: Self::auth_error_response(&auth_req.request, redacted.to_string()),
            };
            let resp_bytes = serde_json::to_vec(&resp).unwrap_or_default();
            if resp_bytes.len() <= MAX_RPC_FRAME_BYTES {
                let mut payload = (resp_bytes.len() as u32).to_be_bytes().to_vec();
                payload.extend_from_slice(&resp_bytes);
                let _ = stream.write_all(&payload).await;
            }
            return Err(redacted);
        }

        let resp = match auth_req.request {
            RpcRequest::RequestVote(r) => {
                let res = store.request_vote(r).await.map_err(|e| e.to_string());
                RpcResponse::RequestVote(res)
            }
            RpcRequest::AppendEntries(r) => {
                let res = store.append_entries(r).await.map_err(|e| e.to_string());
                RpcResponse::AppendEntries(res)
            }
            RpcRequest::InstallSnapshot(r) => {
                let res = store.install_snapshot(r).await.map_err(|e| e.to_string());
                RpcResponse::InstallSnapshot(res)
            }
            RpcRequest::LoadLatest => {
                let res = store
                    .load_latest_consensus_rpc()
                    .await
                    .map_err(|e| e.to_string());
                RpcResponse::LoadLatest(res)
            }
            RpcRequest::LoadRollback(t) => {
                let res = store
                    .load_rollback_consensus_rpc(t)
                    .await
                    .map_err(|e| e.to_string());
                RpcResponse::LoadRollback(res)
            }
            RpcRequest::TimeoutNow(r) => {
                let res = store.handle_timeout_now(r).await.map_err(|e| e.to_string());
                RpcResponse::TimeoutNow(res)
            }
        };

        let auth_resp = AuthenticatedResponse { response: resp };

        let resp_bytes = serde_json::to_vec(&auth_resp).map_err(redact_error)?;
        if resp_bytes.len() > MAX_RPC_FRAME_BYTES {
            return Err(PersistError::io("RPC response frame exceeds maximum size"));
        }

        let mut payload = (resp_bytes.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(&resp_bytes);

        stream.write_all(&payload).await.map_err(redact_error)?;

        Ok(())
    }
}

#[async_trait]
impl ConsensusPeer for ConsensusConfigStore {
    fn node_id(&self) -> usize {
        self.node_id
    }

    async fn request_vote(
        &self,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, PersistError> {
        if !self.is_online().await {
            return Err(PersistError::io("peer offline"));
        }
        self.handle_request_vote(req).await
    }

    async fn append_entries(
        &self,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, PersistError> {
        if !self.is_online().await {
            return Err(PersistError::io("peer offline"));
        }
        self.handle_append_entries(req).await
    }

    async fn install_snapshot(
        &self,
        req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, PersistError> {
        if !self.is_online().await {
            return Err(PersistError::io("peer offline"));
        }
        self.handle_install_snapshot(req).await
    }

    async fn load_latest_consensus_rpc(&self) -> Result<Option<StoredConfig>, PersistError> {
        if !self.is_online().await {
            return Err(PersistError::io("peer offline"));
        }
        let is_leader = self.get_role().await == Role::Leader;
        if is_leader {
            self.verify_leadership().await?;
            self.inner.load_latest().await
        } else {
            let leader_id = self.get_leader_id().await;
            if let Some(lid) = leader_id {
                let peers_guard = self.peers.read().await;
                if let Some(leader_peer) = peers_guard.get(&lid) {
                    if lid == self.node_id {
                        return Err(PersistError::inconsistent_state("infinite loop detected"));
                    }
                    leader_peer.load_latest_consensus_rpc().await
                } else {
                    Err(PersistError::io("leader not reachable"))
                }
            } else {
                Err(PersistError::io("no leader active"))
            }
        }
    }

    async fn load_rollback_consensus_rpc(
        &self,
        target: RollbackTarget,
    ) -> Result<StoredConfig, PersistError> {
        if !self.is_online().await {
            return Err(PersistError::io("peer offline"));
        }
        let is_leader = self.get_role().await == Role::Leader;
        if is_leader {
            self.verify_leadership().await?;
            self.inner.load_rollback(target).await
        } else {
            let leader_id = self.get_leader_id().await;
            if let Some(lid) = leader_id {
                let peers_guard = self.peers.read().await;
                if let Some(leader_peer) = peers_guard.get(&lid) {
                    if lid == self.node_id {
                        return Err(PersistError::inconsistent_state("infinite loop detected"));
                    }
                    leader_peer.load_rollback_consensus_rpc(target).await
                } else {
                    Err(PersistError::io("leader not reachable"))
                }
            } else {
                Err(PersistError::io("no leader active"))
            }
        }
    }

    async fn timeout_now(
        &self,
        req: TimeoutNowRequest,
    ) -> Result<TimeoutNowResponse, PersistError> {
        if !self.is_online().await {
            return Err(PersistError::io("peer offline"));
        }
        self.handle_timeout_now(req).await
    }
}

#[async_trait]
impl ConfigStore for ConsensusConfigStore {
    async fn load_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        self.load_latest_consensus_rpc().await
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig, PersistError> {
        self.load_rollback_consensus_rpc(target).await
    }

    async fn append_commit(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
    ) -> Result<(), PersistError> {
        let op = ConsensusOp::AppendCommit { record, audit };
        self.replicate_and_commit(op).await
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), PersistError> {
        let op = ConsensusOp::MarkConfirmed { tx_id };
        self.replicate_and_commit(op).await
    }

    async fn create_rollback_point(
        &self,
        tx_id: TxId,
        label: Option<String>,
    ) -> Result<(), PersistError> {
        let op = ConsensusOp::CreateRollbackPoint { tx_id, label };
        self.replicate_and_commit(op).await
    }

    async fn preflight(&self) -> Result<PersistCapabilities, PersistError> {
        self.inner.preflight().await
    }
}
