use crate::backend::SqliteBackend;
use crate::error::{ConsensusRpcFamily, ConsensusRpcStage, PersistError};
use crate::preflight::PersistCapabilities;
use crate::types::{AuditRecord, CommitRecord, ConfigStore, RollbackTarget, StoredConfig};
use async_trait::async_trait;
use opc_types::TxId;
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::prelude::*;

use super::identity::{
    build_client_tls_connector, extract_spiffe_id_from_cert_der, parse_local_spiffe_profile,
    parse_spiffe_id,
};
use super::rpc_timing::{RPC_INITIAL_RETRY_DELAY, RPC_MAX_ATTEMPTS};
use super::{
    AppendEntriesRequest, AppendEntriesResponse, ConsensusConfigStore, ConsensusMetrics,
    ConsensusOp, ConsensusPeer, InstallSnapshotRequest, InstallSnapshotResponse, NodeIdentity,
    RequestVoteRequest, RequestVoteResponse, Role, TimeoutNowRequest, TimeoutNowResponse,
};

const MAX_RPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
const RPC_CODEC_DEADLINE_CHECK_BYTES: usize = 8 * 1024;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RpcRequest {
    RequestVote(RequestVoteRequest),
    AppendEntries(AppendEntriesRequest),
    InstallSnapshot(InstallSnapshotRequest),
    LoadLatest,
    LoadRollback(RollbackTarget),
    TimeoutNow(TimeoutNowRequest),
}

impl RpcRequest {
    fn family(&self) -> ConsensusRpcFamily {
        match self {
            Self::RequestVote(_) => ConsensusRpcFamily::RequestVote,
            Self::AppendEntries(_) => ConsensusRpcFamily::AppendEntries,
            Self::InstallSnapshot(_) => ConsensusRpcFamily::InstallSnapshot,
            Self::LoadLatest => ConsensusRpcFamily::LoadLatest,
            Self::LoadRollback(_) => ConsensusRpcFamily::LoadRollback,
            Self::TimeoutNow(_) => ConsensusRpcFamily::TimeoutNow,
        }
    }

    /// Whether replay is safe after the request may have reached the server.
    ///
    /// Vote, append, and snapshot requests carry Raft term/log coordinates and
    /// their handlers are idempotent for a duplicate request. Reads do not
    /// mutate state. `TimeoutNow` spawns a new campaign, so a lost response must
    /// not cause the transport to trigger a second campaign.
    fn permits_ambiguous_retry(&self) -> bool {
        !matches!(self, Self::TimeoutNow(_))
    }
}

fn rpc_identity_is_authorized(
    request: &RpcRequest,
    sender_node_id: usize,
    target_node_id: usize,
    sender_is_voter: bool,
    target_is_voter: bool,
) -> bool {
    match request {
        RpcRequest::RequestVote(request) => {
            sender_is_voter && request.candidate_id == sender_node_id
        }
        RpcRequest::AppendEntries(request) => {
            sender_is_voter && request.leader_id == sender_node_id
        }
        RpcRequest::InstallSnapshot(request) => {
            sender_is_voter && request.leader_id == sender_node_id
        }
        RpcRequest::TimeoutNow(request) => {
            sender_is_voter && target_is_voter && request.candidate_id == target_node_id
        }
        RpcRequest::LoadLatest | RpcRequest::LoadRollback(_) => true,
    }
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

/// Mutual-TLS consensus peer using a bounded logical deadline per RPC.
///
/// The configured [`Self::timeout`] is one end-to-end deadline, not a timeout
/// applied afresh to each I/O stage or retry. It includes authentication/TLS
/// configuration locks, request encoding, TCP connect, TLS handshake, request
/// write, response reads/decoding, and retry backoff.
///
/// Retried Raft vote/append/snapshot requests are replay-safe because their
/// term and log coordinates make duplicate handling idempotent; read RPCs are
/// side-effect free. `TimeoutNow` is not retried after its bytes may have
/// reached the server because delivery can launch a campaign even if the
/// response is lost.
pub struct TcpPeer {
    pub node_id: usize,
    pub addr: String,
    /// Maximum wall-clock budget for one complete logical RPC.
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
    /// Construct a peer with one end-to-end logical RPC deadline.
    ///
    /// Zero expires before setup or network I/O. A duration that cannot be
    /// represented by Tokio's monotonic clock fails closed when an RPC starts.
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
        PersistError::io(format!("RPC operation failed: {err_str}"))
    }
}

#[derive(Debug, Clone, Copy)]
struct RpcDeadline {
    at: tokio::time::Instant,
    family: ConsensusRpcFamily,
}

impl RpcDeadline {
    fn new(timeout: std::time::Duration, family: ConsensusRpcFamily) -> Result<Self, PersistError> {
        let now = tokio::time::Instant::now();
        let at = now.checked_add(timeout).ok_or_else(|| {
            PersistError::inconsistent_state(
                "RPC timeout exceeds the supported monotonic clock range",
            )
        })?;
        let deadline = Self { at, family };
        deadline.check(ConsensusRpcStage::DeadlineSetup)?;
        Ok(deadline)
    }

    fn timeout_error(self, stage: ConsensusRpcStage) -> PersistError {
        PersistError::consensus_rpc_timeout(self.family, stage)
    }

    fn check(self, stage: ConsensusRpcStage) -> Result<(), PersistError> {
        if tokio::time::Instant::now() >= self.at {
            Err(self.timeout_error(stage))
        } else {
            Ok(())
        }
    }

    async fn wait<T, F>(self, stage: ConsensusRpcStage, future: F) -> Result<T, PersistError>
    where
        F: Future<Output = T>,
    {
        self.check(stage)?;
        let output = tokio::time::timeout_at(self.at, future)
            .await
            .map_err(|_| self.timeout_error(stage))?;
        self.check(stage)?;
        Ok(output)
    }

    async fn backoff(self, delay: std::time::Duration) -> Result<(), PersistError> {
        self.wait(ConsensusRpcStage::RetryBackoff, tokio::time::sleep(delay))
            .await
    }
}

struct PreparedRpc {
    body: Vec<u8>,
    server_name: ServerName<'static>,
}

struct BoundedDeadlineWriter {
    body: Vec<u8>,
    deadline: RpcDeadline,
    limit: usize,
    timed_out: bool,
    limit_exceeded: bool,
    allocation_failed: bool,
}

impl BoundedDeadlineWriter {
    fn new(deadline: RpcDeadline, limit: usize) -> Self {
        Self {
            body: Vec::new(),
            deadline,
            limit,
            timed_out: false,
            limit_exceeded: false,
            allocation_failed: false,
        }
    }

    fn into_body(self) -> Vec<u8> {
        self.body
    }

    fn reserve_for(&mut self, additional: usize) -> std::io::Result<()> {
        let required = self.body.len().saturating_add(additional);
        if required <= self.body.capacity() {
            return Ok(());
        }
        let doubled = self.body.capacity().max(1024).saturating_mul(2);
        let target_capacity = doubled.max(required).min(self.limit);
        if self
            .body
            .try_reserve_exact(target_capacity.saturating_sub(self.body.len()))
            .is_err()
        {
            self.allocation_failed = true;
            return Err(std::io::Error::other("RPC request frame allocation failed"));
        }
        Ok(())
    }
}

impl std::io::Write for BoundedDeadlineWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .deadline
            .check(ConsensusRpcStage::RequestSerialization)
            .is_err()
        {
            self.timed_out = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "RPC serialization deadline exceeded",
            ));
        }
        if bytes.is_empty() {
            return Ok(0);
        }

        let remaining = self.limit.saturating_sub(self.body.len());
        if remaining == 0 {
            self.limit_exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RPC request frame exceeds maximum size",
            ));
        }
        let write_len = bytes
            .len()
            .min(remaining)
            .min(RPC_CODEC_DEADLINE_CHECK_BYTES);
        self.reserve_for(write_len)?;
        self.body.extend_from_slice(&bytes[..write_len]);

        if self
            .deadline
            .check(ConsensusRpcStage::RequestSerialization)
            .is_err()
        {
            self.timed_out = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "RPC serialization deadline exceeded",
            ));
        }
        Ok(write_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct DeadlineReader<'a> {
    body: &'a [u8],
    offset: usize,
    deadline: RpcDeadline,
    timed_out: bool,
}

impl<'a> DeadlineReader<'a> {
    fn new(body: &'a [u8], deadline: RpcDeadline) -> Self {
        Self {
            body,
            offset: 0,
            deadline,
            timed_out: false,
        }
    }
}

impl std::io::Read for DeadlineReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self
            .deadline
            .check(ConsensusRpcStage::ResponseDecode)
            .is_err()
        {
            self.timed_out = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "RPC response decode deadline exceeded",
            ));
        }
        if output.is_empty() || self.offset == self.body.len() {
            return Ok(0);
        }

        let read_len = output
            .len()
            .min(self.body.len() - self.offset)
            .min(RPC_CODEC_DEADLINE_CHECK_BYTES);
        output[..read_len].copy_from_slice(&self.body[self.offset..self.offset + read_len]);
        self.offset += read_len;

        if self
            .deadline
            .check(ConsensusRpcStage::ResponseDecode)
            .is_err()
        {
            self.timed_out = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "RPC response decode deadline exceeded",
            ));
        }
        Ok(read_len)
    }
}

fn serialize_request(
    request: &AuthenticatedRequest,
    deadline: RpcDeadline,
    limit: usize,
) -> Result<Vec<u8>, PersistError> {
    deadline.check(ConsensusRpcStage::RequestSerialization)?;
    let mut writer = BoundedDeadlineWriter::new(deadline, limit);
    let result = serde_json::to_writer(&mut writer, request);

    if writer.timed_out
        || deadline
            .check(ConsensusRpcStage::RequestSerialization)
            .is_err()
    {
        return Err(deadline.timeout_error(ConsensusRpcStage::RequestSerialization));
    }
    if writer.limit_exceeded {
        return Err(PersistError::io("RPC request frame exceeds maximum size"));
    }
    if writer.allocation_failed {
        return Err(PersistError::io("RPC request frame allocation failed"));
    }
    result.map_err(|_| PersistError::inconsistent_state("failed to serialize RPC request"))?;
    Ok(writer.into_body())
}

fn decode_response(
    body: &[u8],
    deadline: RpcDeadline,
) -> Result<AuthenticatedResponse, PersistError> {
    deadline.check(ConsensusRpcStage::ResponseDecode)?;
    let mut reader = DeadlineReader::new(body, deadline);
    let result = serde_json::from_reader(&mut reader);
    if reader.timed_out || deadline.check(ConsensusRpcStage::ResponseDecode).is_err() {
        return Err(deadline.timeout_error(ConsensusRpcStage::ResponseDecode));
    }
    result.map_err(|_| PersistError::inconsistent_state("failed to decode RPC response"))
}

#[derive(Debug)]
struct RpcAttemptFailure {
    error: PersistError,
    stage: ConsensusRpcStage,
    delivery_ambiguous: bool,
    retryable: bool,
}

impl RpcAttemptFailure {
    fn new(
        error: PersistError,
        stage: ConsensusRpcStage,
        delivery_ambiguous: bool,
        retryable: bool,
    ) -> Self {
        Self {
            error,
            stage,
            delivery_ambiguous,
            retryable,
        }
    }

    fn deadline(error: PersistError, stage: ConsensusRpcStage, delivery_ambiguous: bool) -> Self {
        Self::new(error, stage, delivery_ambiguous, false)
    }

    fn transport<E: std::fmt::Display>(
        error: E,
        stage: ConsensusRpcStage,
        delivery_ambiguous: bool,
    ) -> Self {
        Self::transport_with_retry(error, stage, delivery_ambiguous, true)
    }

    fn transport_with_retry<E: std::fmt::Display>(
        error: E,
        stage: ConsensusRpcStage,
        delivery_ambiguous: bool,
        retryable: bool,
    ) -> Self {
        Self::new(redact_error(error), stage, delivery_ambiguous, retryable)
    }

    fn protocol(error: PersistError, stage: ConsensusRpcStage) -> Self {
        Self::new(error, stage, true, false)
    }
}

fn peer_server_name(addr: &str) -> Result<ServerName<'static>, PersistError> {
    let host = addr
        .rsplit_once(':')
        .map_or(addr, |(host, _port)| host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    ServerName::try_from(host)
        .map(|name| name.to_owned())
        .map_err(|_| PersistError::io("RPC peer address has an invalid TLS server name"))
}

async fn prepare_rpc(
    peer: &TcpPeer,
    req: RpcRequest,
    deadline: RpcDeadline,
) -> Result<PreparedRpc, PersistError> {
    let auth_guard = deadline
        .wait(
            ConsensusRpcStage::AuthenticationSetup,
            peer.auth_info.lock(),
        )
        .await?;
    let auth = auth_guard
        .as_ref()
        .ok_or_else(|| PersistError::inconsistent_state("peer auth credentials not initialized"))?;
    let auth_req = AuthenticatedRequest {
        sender_node_id: auth.local_node_id,
        target_node_id: peer.node_id,
        cluster_id: auth.local_cluster_id.clone(),
        spiffe_id: None,
        client_cert_pem: None,
        request: req,
    };
    deadline.check(ConsensusRpcStage::AuthenticationSetup)?;
    drop(auth_guard);

    let body = serialize_request(&auth_req, deadline, MAX_RPC_FRAME_BYTES)?;

    deadline.check(ConsensusRpcStage::TlsConfiguration)?;
    let server_name = peer_server_name(&peer.addr)?;
    deadline.check(ConsensusRpcStage::TlsConfiguration)?;
    Ok(PreparedRpc { body, server_name })
}

async fn peer_tls_connector(
    peer: &TcpPeer,
    deadline: RpcDeadline,
) -> Result<tokio_rustls::TlsConnector, PersistError> {
    // Use the same identity -> connector lock order as `set_identity`. This
    // makes connector replacement atomic for new attempts and avoids the old
    // inverse-order deadlock during certificate rotation.
    let identity_guard = deadline
        .wait(ConsensusRpcStage::TlsConfiguration, peer.identity.lock())
        .await?;
    let mut connector_guard = deadline
        .wait(
            ConsensusRpcStage::TlsConfiguration,
            peer.tls_connector.lock(),
        )
        .await?;
    if let Some(connector) = connector_guard.as_ref() {
        return Ok(connector.clone());
    }

    let identity = identity_guard
        .as_ref()
        .ok_or_else(|| PersistError::inconsistent_state("peer identity not initialized for TLS"))?;
    deadline.check(ConsensusRpcStage::TlsConfiguration)?;
    let connector = build_client_tls_connector(identity, peer.node_id)?;
    deadline.check(ConsensusRpcStage::TlsConfiguration)?;
    *connector_guard = Some(connector.clone());
    Ok(connector)
}

async fn send_rpc(
    peer: &TcpPeer,
    req: RpcRequest,
    timeout_dur: std::time::Duration,
) -> Result<RpcResponse, PersistError> {
    let family = req.family();
    let permits_ambiguous_retry = req.permits_ambiguous_retry();
    let deadline = RpcDeadline::new(timeout_dur, family)?;
    let prepared = prepare_rpc(peer, req, deadline).await?;

    run_rpc_attempts(family, permits_ambiguous_retry, deadline, || {
        send_rpc_once(peer, &prepared, deadline)
    })
    .await
}

async fn run_rpc_attempts<T, F, Fut>(
    family: ConsensusRpcFamily,
    permits_ambiguous_retry: bool,
    deadline: RpcDeadline,
    mut attempt_rpc: F,
) -> Result<T, PersistError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, RpcAttemptFailure>>,
{
    let mut delay = RPC_INITIAL_RETRY_DELAY;

    for attempt in 1..=RPC_MAX_ATTEMPTS {
        deadline.check(ConsensusRpcStage::TcpConnect)?;
        match attempt_rpc().await {
            Ok(resp) => return Ok(resp),
            Err(failure) => {
                let deadline_exceeded = failure.error.is_consensus_rpc_timeout();
                tracing::debug!(
                    rpc_family = family.as_str(),
                    failure_stage = failure.stage.as_str(),
                    attempt,
                    deadline_exceeded,
                    delivery_ambiguous = failure.delivery_ambiguous,
                    "consensus RPC attempt failed"
                );

                if deadline_exceeded
                    || !failure.retryable
                    || attempt >= RPC_MAX_ATTEMPTS
                    || (failure.delivery_ambiguous && !permits_ambiguous_retry)
                {
                    return Err(failure.error);
                }
                deadline.backoff(delay).await?;
                delay = delay.saturating_mul(2);
            }
        }
    }

    unreachable!("the bounded RPC attempt loop always returns")
}

fn tls_handshake_error_is_retryable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::WouldBlock
    )
}

fn remote_rpc_error(family: ConsensusRpcFamily) -> PersistError {
    PersistError::io(format!(
        "remote consensus RPC failed family={}",
        family.as_str()
    ))
}

fn map_remote_rpc_result<T>(
    result: Result<T, String>,
    family: ConsensusRpcFamily,
) -> Result<T, PersistError> {
    // An authenticated peer is still an untrusted error-text source. Discard
    // its message at the transport boundary so it cannot reach Debug logs or
    // create attacker-controlled diagnostic cardinality.
    result.map_err(|_| remote_rpc_error(family))
}

async fn tcp_connect_with_deadline<T, F>(
    deadline: RpcDeadline,
    connect: F,
) -> Result<T, RpcAttemptFailure>
where
    F: Future<Output = std::io::Result<T>>,
{
    deadline
        .wait(ConsensusRpcStage::TcpConnect, connect)
        .await
        .map_err(|error| RpcAttemptFailure::deadline(error, ConsensusRpcStage::TcpConnect, false))?
        .map_err(|error| RpcAttemptFailure::transport(error, ConsensusRpcStage::TcpConnect, false))
}

async fn send_rpc_once(
    peer: &TcpPeer,
    prepared: &PreparedRpc,
    deadline: RpcDeadline,
) -> Result<RpcResponse, RpcAttemptFailure> {
    let connector = peer_tls_connector(peer, deadline).await.map_err(|error| {
        RpcAttemptFailure::new(error, ConsensusRpcStage::TlsConfiguration, false, false)
    })?;

    let tcp_stream =
        tcp_connect_with_deadline(deadline, tokio::net::TcpStream::connect(&peer.addr)).await?;

    let mut stream = deadline
        .wait(
            ConsensusRpcStage::TlsHandshake,
            connector.connect(prepared.server_name.clone(), tcp_stream),
        )
        .await
        .map_err(|error| {
            RpcAttemptFailure::deadline(error, ConsensusRpcStage::TlsHandshake, false)
        })?
        .map_err(|error| {
            let retryable = tls_handshake_error_is_retryable(&error);
            RpcAttemptFailure::transport_with_retry(
                error,
                ConsensusRpcStage::TlsHandshake,
                false,
                retryable,
            )
        })?;

    let request_len = (prepared.body.len() as u32).to_be_bytes();
    deadline
        .wait(
            ConsensusRpcStage::RequestWrite,
            stream.write_all(&request_len),
        )
        .await
        .map_err(|error| RpcAttemptFailure::deadline(error, ConsensusRpcStage::RequestWrite, true))?
        .map_err(|error| {
            RpcAttemptFailure::transport(error, ConsensusRpcStage::RequestWrite, true)
        })?;
    deadline
        .wait(
            ConsensusRpcStage::RequestWrite,
            stream.write_all(&prepared.body),
        )
        .await
        .map_err(|error| RpcAttemptFailure::deadline(error, ConsensusRpcStage::RequestWrite, true))?
        .map_err(|error| {
            RpcAttemptFailure::transport(error, ConsensusRpcStage::RequestWrite, true)
        })?;

    let mut len_buf = [0u8; 4];
    deadline
        .wait(
            ConsensusRpcStage::ResponseLength,
            stream.read_exact(&mut len_buf),
        )
        .await
        .map_err(|error| {
            RpcAttemptFailure::deadline(error, ConsensusRpcStage::ResponseLength, true)
        })?
        .map_err(|error| {
            RpcAttemptFailure::transport(error, ConsensusRpcStage::ResponseLength, true)
        })?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_RPC_FRAME_BYTES {
        return Err(RpcAttemptFailure::protocol(
            PersistError::io("RPC response frame exceeds maximum size"),
            ConsensusRpcStage::ResponseLength,
        ));
    }
    deadline
        .check(ConsensusRpcStage::ResponseBody)
        .map_err(|error| {
            RpcAttemptFailure::deadline(error, ConsensusRpcStage::ResponseBody, true)
        })?;
    let mut resp_buf = Vec::new();
    resp_buf.try_reserve_exact(len).map_err(|_| {
        RpcAttemptFailure::protocol(
            PersistError::io("RPC response frame allocation failed"),
            ConsensusRpcStage::ResponseBody,
        )
    })?;
    resp_buf.resize(len, 0);
    deadline
        .check(ConsensusRpcStage::ResponseBody)
        .map_err(|error| {
            RpcAttemptFailure::deadline(error, ConsensusRpcStage::ResponseBody, true)
        })?;
    deadline
        .wait(
            ConsensusRpcStage::ResponseBody,
            stream.read_exact(&mut resp_buf),
        )
        .await
        .map_err(|error| RpcAttemptFailure::deadline(error, ConsensusRpcStage::ResponseBody, true))?
        .map_err(|error| {
            RpcAttemptFailure::transport(error, ConsensusRpcStage::ResponseBody, true)
        })?;

    let auth_resp = decode_response(&resp_buf, deadline).map_err(|error| {
        if error.is_consensus_rpc_timeout() {
            RpcAttemptFailure::deadline(error, ConsensusRpcStage::ResponseDecode, true)
        } else {
            RpcAttemptFailure::protocol(error, ConsensusRpcStage::ResponseDecode)
        }
    })?;

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
        // Acquire both locks before changing either value. In addition to using
        // the same identity -> connector order as `peer_tls_connector`, this
        // keeps cancellation while waiting for the connector lock from pairing
        // a new identity with the old cached connector.
        let mut identity_guard = self.identity.lock().await;
        let mut conn_guard = self.tls_connector.lock().await;
        *identity_guard = Some(identity);
        *conn_guard = None;
        Ok(())
    }

    async fn request_vote(
        &self,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, PersistError> {
        let resp = send_rpc(self, RpcRequest::RequestVote(req), self.timeout).await?;
        match resp {
            RpcResponse::RequestVote(res) => {
                let response = map_remote_rpc_result(res, ConsensusRpcFamily::RequestVote)?;
                SqliteBackend::consensus_term_to_sqlite(response.term)?;
                Ok(response)
            }
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn append_entries(
        &self,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, PersistError> {
        let resp = send_rpc(self, RpcRequest::AppendEntries(req), self.timeout).await?;
        match resp {
            RpcResponse::AppendEntries(res) => {
                let response = map_remote_rpc_result(res, ConsensusRpcFamily::AppendEntries)?;
                SqliteBackend::consensus_term_to_sqlite(response.term)?;
                Ok(response)
            }
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn install_snapshot(
        &self,
        req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, PersistError> {
        let resp = send_rpc(self, RpcRequest::InstallSnapshot(req), self.timeout).await?;
        match resp {
            RpcResponse::InstallSnapshot(res) => {
                let response = map_remote_rpc_result(res, ConsensusRpcFamily::InstallSnapshot)?;
                SqliteBackend::consensus_term_to_sqlite(response.term)?;
                Ok(response)
            }
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn load_latest_consensus_rpc(&self) -> Result<Option<StoredConfig>, PersistError> {
        let resp = send_rpc(self, RpcRequest::LoadLatest, self.timeout).await?;
        match resp {
            RpcResponse::LoadLatest(res) => {
                map_remote_rpc_result(res, ConsensusRpcFamily::LoadLatest)
            }
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn load_rollback_consensus_rpc(
        &self,
        target: RollbackTarget,
    ) -> Result<StoredConfig, PersistError> {
        let resp = send_rpc(self, RpcRequest::LoadRollback(target), self.timeout).await?;
        match resp {
            RpcResponse::LoadRollback(res) => {
                map_remote_rpc_result(res, ConsensusRpcFamily::LoadRollback)
            }
            _ => Err(PersistError::io("invalid response variant")),
        }
    }

    async fn timeout_now(
        &self,
        req: TimeoutNowRequest,
    ) -> Result<TimeoutNowResponse, PersistError> {
        let resp = send_rpc(self, RpcRequest::TimeoutNow(req), self.timeout).await?;
        match resp {
            RpcResponse::TimeoutNow(res) => {
                let response = map_remote_rpc_result(res, ConsensusRpcFamily::TimeoutNow)?;
                SqliteBackend::consensus_term_to_sqlite(response.term)?;
                Ok(response)
            }
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
                                            tracing::debug!(
                                                error_kind = ?e.kind(),
                                                "server TLS handshake failed"
                                            );
                                            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                                            store.metrics.server_rejected_connections.fetch_add(1, Ordering::Relaxed);
                                            redact_error(PersistError::io(format!("TLS handshake failed: {e}")))
                                        })?;

                                        Self::handle_connection(tls_stream, &store).await
                                    }.await;
                                    match res {
                                        Ok(()) => {}
                                        Err(e) => {
                                            tracing::debug!(error = %e, "connection handler failed");
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

        let target_is_voter = local_membership
            .voting_members
            .contains(&req.target_node_id)
            || local_membership
                .old_voting_members
                .as_ref()
                .map(|old| old.contains(&req.target_node_id))
                .unwrap_or(false);
        if !rpc_identity_is_authorized(
            &req.request,
            req.sender_node_id,
            req.target_node_id,
            is_voter,
            target_is_voter,
        ) {
            store.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            store
                .metrics
                .server_rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            return Err(PersistError::inconsistent_state(
                "unauthenticated: consensus RPC authority mismatch",
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
            PersistError::inconsistent_state(format!("failed to parse client certificate: {e}"))
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
                    let result = leader_peer.load_latest_consensus_rpc().await;
                    if let Err(error) = &result {
                        self.metrics.record_rpc_failure(error);
                    }
                    result
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
                    let result = leader_peer.load_rollback_consensus_rpc(target).await;
                    if let Err(error) = &result {
                        self.metrics.record_rpc_failure(error);
                    }
                    result
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

#[cfg(test)]
mod timing_tests {
    use super::super::rpc_timing::{catch_up_rpc_deadline_budget, rpc_logical_deadline_budget};
    use super::{
        decode_response, map_remote_rpc_result, rpc_identity_is_authorized, run_rpc_attempts,
        send_rpc, serialize_request, tcp_connect_with_deadline, AuthInfo, AuthenticatedRequest,
        RpcAttemptFailure, RpcDeadline, RpcRequest, TcpPeer,
    };
    use crate::error::{ConsensusRpcFamily, ConsensusRpcStage, PersistErrorKind};
    use crate::{
        AuditKey, ClusterMembership, ConsensusClock, ConsensusConfigStore, ConsensusPeer,
        NodeIdentity, RollbackTarget, SqliteBackend,
    };
    use std::future::Future;
    use std::io::Write;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    struct PendingUntilDropped(Arc<AtomicBool>);

    impl Future for PendingUntilDropped {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingUntilDropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct PendingConnectUntilDropped(Arc<AtomicBool>);

    impl Future for PendingConnectUntilDropped {
        type Output = std::io::Result<()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingConnectUntilDropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    async fn initialize_auth(peer: &TcpPeer) {
        *peer.auth_info.lock().await = Some(AuthInfo {
            local_node_id: 1,
            local_cluster_id: "deadline-test".to_string(),
            client_cert_pem: String::new(),
        });
    }

    fn test_identity(label: &str) -> NodeIdentity {
        NodeIdentity {
            cert_chain_pem: format!("{label}-cert"),
            private_key_pem: format!("{label}-key"),
            ca_cert_pem: format!("{label}-ca"),
        }
    }

    fn placeholder_tls_connector() -> tokio_rustls::TlsConnector {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    #[test]
    fn rpc_budget_is_one_logical_deadline_including_retries_and_backoff() {
        assert_eq!(super::super::rpc_timing::RPC_CATCH_UP_MAX_ROUNDS, 64);
        assert_eq!(super::super::rpc_timing::RPC_CATCH_UP_MAX_RPCS_PER_ROUND, 2);
        assert_eq!(
            rpc_logical_deadline_budget(Duration::from_millis(500)),
            Duration::from_millis(500)
        );
        assert_eq!(
            catch_up_rpc_deadline_budget(Duration::from_millis(500)),
            Duration::from_secs(64)
        );
    }

    #[test]
    fn catch_up_rpc_budget_saturates_for_extreme_values() {
        assert_eq!(catch_up_rpc_deadline_budget(Duration::MAX), Duration::MAX);
    }

    #[tokio::test]
    async fn zero_timeout_expires_before_rpc_setup_or_network_io() {
        let peer = TcpPeer::new(2, "127.0.0.1:9".to_string(), Duration::ZERO);

        let error = send_rpc(&peer, RpcRequest::LoadLatest, Duration::ZERO)
            .await
            .unwrap_err();

        assert_eq!(
            error.consensus_rpc_timeout_context(),
            Some((
                ConsensusRpcFamily::LoadLatest,
                ConsensusRpcStage::DeadlineSetup,
            ))
        );
    }

    #[tokio::test]
    async fn follower_forwarded_read_deadlines_update_bounded_metrics() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let backend = Arc::new(
            SqliteBackend::open_with_audit_key(
                temp_dir.path().join("forwarding-metrics.db"),
                true,
                0,
                AuditKey::new([0x42; 32]).unwrap(),
            )
            .await
            .unwrap(),
        );
        let membership = ClusterMembership {
            cluster_id: "forwarding-metrics".to_string(),
            node_id: 1,
            voting_members: vec![1, 2],
            non_voting_members: vec![],
            old_voting_members: None,
            removed_members: vec![],
            epoch: 1,
        };
        let follower = ConsensusConfigStore::new(
            1,
            backend,
            Some(membership),
            Some(ConsensusClock {
                enable_timers: false,
                ..ConsensusClock::default()
            }),
        )
        .await
        .unwrap();
        follower
            .add_peer(
                2,
                Arc::new(TcpPeer::new(2, "127.0.0.1:9".to_string(), Duration::ZERO)),
            )
            .await;
        follower.state.lock().await.leader_id = Some(2);

        let latest_error = follower.load_latest_consensus_rpc().await.unwrap_err();
        assert_eq!(
            latest_error.consensus_rpc_timeout_context(),
            Some((
                ConsensusRpcFamily::LoadLatest,
                ConsensusRpcStage::DeadlineSetup,
            ))
        );

        let rollback_error = follower
            .load_rollback_consensus_rpc(RollbackTarget::Previous)
            .await
            .unwrap_err();
        assert_eq!(
            rollback_error.consensus_rpc_timeout_context(),
            Some((
                ConsensusRpcFamily::LoadRollback,
                ConsensusRpcStage::DeadlineSetup,
            ))
        );

        let metrics = follower.dump_metrics().await.unwrap();
        assert_eq!(metrics.rpc_failures, 2);
        assert_eq!(metrics.rpc_timeouts, 2);
        assert_eq!(metrics.rpc_timeouts_by_family["load_latest"], 1);
        assert_eq!(metrics.rpc_timeouts_by_family["load_rollback"], 1);
        assert_eq!(metrics.rpc_timeouts_by_stage["deadline_setup"], 2);
    }

    #[tokio::test]
    async fn unrepresentable_timeout_fails_without_panicking_or_connecting() {
        let peer = TcpPeer::new(2, "127.0.0.1:9".to_string(), Duration::MAX);

        let error = send_rpc(&peer, RpcRequest::LoadLatest, Duration::MAX)
            .await
            .unwrap_err();

        assert!(matches!(
            error.kind(),
            PersistErrorKind::InconsistentState(message)
                if message == "RPC timeout exceeds the supported monotonic clock range"
        ));
    }

    #[tokio::test]
    async fn authentication_lock_wait_uses_the_logical_deadline() {
        let peer = TcpPeer::new(2, "127.0.0.1:9".to_string(), Duration::from_millis(20));
        let _held_auth_lock = peer.auth_info.lock().await;

        let error = send_rpc(&peer, RpcRequest::LoadLatest, Duration::from_millis(20))
            .await
            .unwrap_err();

        assert_eq!(
            error.consensus_rpc_timeout_context(),
            Some((
                ConsensusRpcFamily::LoadLatest,
                ConsensusRpcStage::AuthenticationSetup,
            ))
        );
    }

    #[tokio::test]
    async fn tls_configuration_lock_wait_uses_the_logical_deadline() {
        let peer = TcpPeer::new(2, "127.0.0.1:9".to_string(), Duration::from_millis(20));
        initialize_auth(&peer).await;
        let _held_identity_lock = peer.identity.lock().await;

        let error = send_rpc(&peer, RpcRequest::LoadLatest, Duration::from_millis(20))
            .await
            .unwrap_err();

        assert_eq!(
            error.consensus_rpc_timeout_context(),
            Some((
                ConsensusRpcFamily::LoadLatest,
                ConsensusRpcStage::TlsConfiguration,
            ))
        );
    }

    #[tokio::test]
    async fn retry_backoff_cannot_extend_the_logical_deadline() {
        let timeout = Duration::from_millis(20);
        let deadline = RpcDeadline::new(timeout, ConsensusRpcFamily::LoadLatest).unwrap();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = tokio::time::Instant::now();
        let error = run_rpc_attempts(ConsensusRpcFamily::LoadLatest, true, deadline, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err::<(), _>(RpcAttemptFailure::new(
                crate::PersistError::io("retryable transport failure"),
                ConsensusRpcStage::TcpConnect,
                false,
                true,
            )))
        })
        .await
        .unwrap_err();
        let elapsed = started.elapsed();

        assert_eq!(
            error.consensus_rpc_timeout_context(),
            Some((
                ConsensusRpcFamily::LoadLatest,
                ConsensusRpcStage::RetryBackoff,
            ))
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(
            elapsed + Duration::from_millis(5) >= timeout
                && elapsed <= timeout + Duration::from_millis(200),
            "retry backoff exceeded one deadline plus tolerance: timeout={timeout:?} elapsed={elapsed:?}"
        );
    }

    #[tokio::test]
    async fn pending_tcp_connect_uses_one_deadline_and_is_cancelled_without_retry() {
        let timeout = Duration::from_millis(30);
        let deadline = RpcDeadline::new(timeout, ConsensusRpcFamily::LoadLatest).unwrap();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let started = tokio::time::Instant::now();

        let error = run_rpc_attempts(ConsensusRpcFamily::LoadLatest, true, deadline, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            tcp_connect_with_deadline(deadline, PendingConnectUntilDropped(Arc::clone(&dropped)))
        })
        .await
        .unwrap_err();
        let elapsed = started.elapsed();

        assert_eq!(
            error.consensus_rpc_timeout_context(),
            Some((
                ConsensusRpcFamily::LoadLatest,
                ConsensusRpcStage::TcpConnect,
            ))
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(
            elapsed + Duration::from_millis(5) >= timeout
                && elapsed <= timeout + Duration::from_millis(200),
            "pending connect exceeded one deadline plus tolerance: timeout={timeout:?} elapsed={elapsed:?}"
        );
    }

    #[tokio::test]
    async fn permanent_configuration_failure_is_not_retried_or_reclassified() {
        let deadline =
            RpcDeadline::new(Duration::from_millis(100), ConsensusRpcFamily::LoadLatest).unwrap();
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let error = run_rpc_attempts(ConsensusRpcFamily::LoadLatest, true, deadline, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Err::<(), _>(RpcAttemptFailure::new(
                crate::PersistError::inconsistent_state("invalid local identity"),
                ConsensusRpcStage::TlsConfiguration,
                false,
                false,
            )))
        })
        .await
        .unwrap_err();

        assert!(!error.is_consensus_rpc_timeout());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn remote_rpc_errors_discard_all_peer_controlled_text() {
        let hostile = format!(
            "token=peer-secret path=/var/lib/opc/private.db spiffe://tenant/workload\n{}TAIL_MARKER",
            "x".repeat(1024 * 1024)
        );

        for family in ConsensusRpcFamily::ALL {
            let error = map_remote_rpc_result::<()>(Err(hostile.clone()), family).unwrap_err();
            let display = error.to_string();
            let debug = format!("{error:?}");
            let expected = format!("remote consensus RPC failed family={}", family.as_str());

            assert!(matches!(
                error.kind(),
                PersistErrorKind::Io(message) if message == &expected
            ));
            assert!(display.ends_with(&expected));
            for leaked in [
                "peer-secret",
                "/var/lib/opc/private.db",
                "spiffe://tenant/workload",
                "TAIL_MARKER",
            ] {
                assert!(!display.contains(leaked), "Display leaked {leaked}");
                assert!(!debug.contains(leaked), "Debug leaked {leaked}");
            }
            assert!(
                debug.len() < 256,
                "peer error produced an unbounded Debug value"
            );
        }
    }

    #[tokio::test]
    async fn cancelled_identity_rotation_preserves_the_previous_connector_pair() {
        let peer = Arc::new(TcpPeer::new(
            2,
            "127.0.0.1:9".to_string(),
            Duration::from_secs(1),
        ));
        let old_identity = test_identity("old");
        let new_identity = test_identity("new");
        *peer.identity.lock().await = Some(old_identity.clone());
        *peer.tls_connector.lock().await = Some(placeholder_tls_connector());

        let connector_guard = peer.tls_connector.lock().await;
        let rotating_peer = Arc::clone(&peer);
        let attempted_identity = new_identity.clone();
        let rotation =
            tokio::spawn(async move { rotating_peer.set_identity(attempted_identity).await });

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if peer.identity.try_lock().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("identity rotation did not block on the held connector lock");

        rotation.abort();
        assert!(rotation.await.unwrap_err().is_cancelled());
        assert!(connector_guard.is_some());
        drop(connector_guard);

        let identity_guard = peer.identity.lock().await;
        let identity = identity_guard.as_ref().unwrap();
        assert_eq!(identity.cert_chain_pem, old_identity.cert_chain_pem);
        assert_eq!(identity.private_key_pem, old_identity.private_key_pem);
        assert_eq!(identity.ca_cert_pem, old_identity.ca_cert_pem);
        drop(identity_guard);
        assert!(peer.tls_connector.lock().await.is_some());

        peer.set_identity(new_identity.clone()).await.unwrap();
        let identity_guard = peer.identity.lock().await;
        let identity = identity_guard.as_ref().unwrap();
        assert_eq!(identity.cert_chain_pem, new_identity.cert_chain_pem);
        assert!(peer.tls_connector.lock().await.is_none());
    }

    #[test]
    fn retry_policy_distinguishes_replay_safe_and_triggering_rpcs() {
        use super::super::{
            AppendEntriesRequest, InstallSnapshotRequest, RequestVoteRequest, TimeoutNowRequest,
        };
        use crate::RollbackTarget;

        for request in [
            RpcRequest::RequestVote(RequestVoteRequest {
                term: 1,
                candidate_id: 1,
                last_log_index: 0,
                last_log_term: 0,
            }),
            RpcRequest::AppendEntries(AppendEntriesRequest {
                term: 1,
                leader_id: 1,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![],
                leader_commit: 0,
            }),
            RpcRequest::InstallSnapshot(InstallSnapshotRequest {
                term: 1,
                leader_id: 1,
                last_included_index: 0,
                last_included_term: 0,
                data: vec![],
            }),
            RpcRequest::LoadLatest,
            RpcRequest::LoadRollback(RollbackTarget::Previous),
        ] {
            assert!(request.permits_ambiguous_retry(), "{:?}", request.family());
        }
        assert!(!RpcRequest::TimeoutNow(TimeoutNowRequest {
            term: 1,
            candidate_id: 2,
        })
        .permits_ambiguous_retry());
    }

    #[test]
    fn mutating_rpc_identity_is_bound_to_the_authenticated_voter() {
        use super::super::{
            AppendEntriesRequest, InstallSnapshotRequest, RequestVoteRequest, TimeoutNowRequest,
        };

        let vote = RpcRequest::RequestVote(RequestVoteRequest {
            term: 1,
            candidate_id: 7,
            last_log_index: 0,
            last_log_term: 0,
        });
        let append = RpcRequest::AppendEntries(AppendEntriesRequest {
            term: 1,
            leader_id: 7,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        });
        let snapshot = RpcRequest::InstallSnapshot(InstallSnapshotRequest {
            term: 1,
            leader_id: 7,
            last_included_index: 0,
            last_included_term: 0,
            data: vec![],
        });
        let timeout_now = RpcRequest::TimeoutNow(TimeoutNowRequest {
            term: 1,
            candidate_id: 9,
        });

        for request in [&vote, &append, &snapshot] {
            assert!(rpc_identity_is_authorized(request, 7, 9, true, true));
            assert!(!rpc_identity_is_authorized(request, 8, 9, true, true));
            assert!(!rpc_identity_is_authorized(request, 7, 9, false, true));
        }
        assert!(rpc_identity_is_authorized(&timeout_now, 7, 9, true, true));
        assert!(!rpc_identity_is_authorized(&timeout_now, 7, 8, true, true));
        assert!(!rpc_identity_is_authorized(&timeout_now, 7, 9, true, false));
        assert!(rpc_identity_is_authorized(
            &RpcRequest::LoadLatest,
            7,
            9,
            false,
            true
        ));
    }

    #[test]
    fn tls_verification_errors_are_permanent_but_transport_loss_is_retryable() {
        let verification = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "certificate verification failed",
        );
        let connection_reset =
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "connection reset");

        assert!(!super::tls_handshake_error_is_retryable(&verification));
        assert!(super::tls_handshake_error_is_retryable(&connection_reset));
    }

    #[tokio::test]
    async fn expiry_cancels_every_awaited_transport_stage() {
        for stage in [
            ConsensusRpcStage::AuthenticationSetup,
            ConsensusRpcStage::RequestSerialization,
            ConsensusRpcStage::TlsConfiguration,
            ConsensusRpcStage::TcpConnect,
            ConsensusRpcStage::TlsHandshake,
            ConsensusRpcStage::RequestWrite,
            ConsensusRpcStage::ResponseLength,
            ConsensusRpcStage::ResponseBody,
            ConsensusRpcStage::ResponseDecode,
            ConsensusRpcStage::RetryBackoff,
        ] {
            let dropped = Arc::new(AtomicBool::new(false));
            let timeout = Duration::from_millis(10);
            let deadline = RpcDeadline::new(timeout, ConsensusRpcFamily::AppendEntries).unwrap();
            let started = tokio::time::Instant::now();

            let error = deadline
                .wait(stage, PendingUntilDropped(Arc::clone(&dropped)))
                .await
                .unwrap_err();
            let elapsed = started.elapsed();

            assert_eq!(
                error.consensus_rpc_timeout_context(),
                Some((ConsensusRpcFamily::AppendEntries, stage))
            );
            assert!(
                dropped.load(Ordering::SeqCst),
                "stage {stage} was not cancelled"
            );
            assert!(
                elapsed + Duration::from_millis(5) >= timeout
                    && elapsed <= timeout + Duration::from_millis(200),
                "stage {stage} exceeded one deadline plus tolerance: timeout={timeout:?} elapsed={elapsed:?}"
            );
        }
    }

    #[tokio::test]
    async fn request_serialization_is_capped_and_deadline_cooperative() {
        let cap_deadline =
            RpcDeadline::new(Duration::from_secs(1), ConsensusRpcFamily::InstallSnapshot).unwrap();
        let mut writer = super::BoundedDeadlineWriter::new(cap_deadline, 4);
        let error = writer.write_all(b"12345").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(writer.body, b"1234");
        assert!(writer.limit_exceeded);

        let request = AuthenticatedRequest {
            sender_node_id: 1,
            target_node_id: 2,
            cluster_id: "x".repeat(8 * 1024 * 1024),
            spiffe_id: None,
            client_cert_pem: None,
            request: RpcRequest::LoadLatest,
        };
        let deadline =
            RpcDeadline::new(Duration::from_micros(100), ConsensusRpcFamily::LoadLatest).unwrap();

        let error = serialize_request(&request, deadline, super::MAX_RPC_FRAME_BYTES).unwrap_err();
        assert_eq!(
            error.consensus_rpc_timeout_context(),
            Some((
                ConsensusRpcFamily::LoadLatest,
                ConsensusRpcStage::RequestSerialization,
            ))
        );
    }

    #[tokio::test]
    async fn response_decode_checks_the_deadline_cooperatively() {
        let mut response = vec![b' '; 8 * 1024 * 1024];
        response.extend_from_slice(br#"{"response":{"LoadLatest":{"Ok":null}}}"#);
        let deadline =
            RpcDeadline::new(Duration::from_micros(100), ConsensusRpcFamily::LoadLatest).unwrap();

        let error = decode_response(&response, deadline).unwrap_err();
        assert_eq!(
            error.consensus_rpc_timeout_context(),
            Some((
                ConsensusRpcFamily::LoadLatest,
                ConsensusRpcStage::ResponseDecode,
            ))
        );
    }
}
