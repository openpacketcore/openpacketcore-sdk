//! Read-only controller/observer calls never consume or return boot authority.
use super::{
    rpc_client::{
        batch::{batch_error, data_class, lookup_response},
        decode_committed, payload_error,
    },
    rpc_server::{authority_error, work_class},
    wire::*,
};
use super::{AuthenticationClock, ScopeRpcError};
use opc_session_store::{
    scope_authority::*,
    scope_batch::{ScopeBatchAttempt, ScopeBatchError, ScopeBatchLookup},
    scope_scheduler::{ScopeScheduler, ScopeWorkClass},
};
use opc_tls::{ChannelBindingPurpose, ScopeTlsConnection};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
    time::timeout,
};

/// Trusted installation configuration for a controller or observer connection.
pub struct ScopeReadClientConfig {
    /// Exact native scope; live server policy supplies the caller's role.
    pub scope: ScopeId,
    /// Constrained mutual-TLS credentials.
    pub tls: opc_tls::AuthenticatedClientConfig,
    /// Exact expected server SPIFFE identity.
    pub server: opc_types::SpiffeId,
    /// Distinct listeners in SafetyControl, Emergency, EmergencyClassification,
    /// Normal and Maintenance order. Read-only callers never use Emergency.
    pub addresses: [SocketAddr; 5],
    /// Trusted interval for certificate authentication.
    pub clock: Arc<dyn AuthenticationClock>,
    /// Owned scheduler read admission.
    pub scheduler: ScopeScheduler,
}
/// A read-only retained receipt; a stamp is not an effect capability.
pub struct ScopeAuthorityReceipt {
    pub(super) stamp: ScopeAuthorityStamp,
    pub(super) active: bool,
}
impl ScopeAuthorityReceipt {
    /// Exact stamp observed by a fresh quorum read.
    pub const fn stamp(&self) -> &ScopeAuthorityStamp {
        &self.stamp
    }
    /// Whether that receipt describes the active execution.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}
/// Authenticated read-only scope observer/controller.
pub struct ScopeReadClient {
    config: ScopeReadClientConfig,
    binding: ScopeBinding,
    connections: [Mutex<Option<ScopeTlsConnection<TcpStream>>>; 5],
    class_tls: [opc_tls::AuthenticatedClientConfig; 5],
}
impl ScopeReadClient {
    /// Configure reads without supplying a worker key or capability factory.
    pub fn new(config: ScopeReadClientConfig) -> Result<Self, ScopeRpcError> {
        config
            .tls
            .validate_scope_profile()
            .map_err(|_| ScopeRpcError::Invalid)?;
        if config.addresses.iter().any(|address| address.port() == 0) {
            return Err(ScopeRpcError::Invalid);
        }
        let binding =
            ScopeBinding::from_scope(&config.scope).map_err(|_| ScopeRpcError::Invalid)?;
        Ok(Self {
            class_tls: std::array::from_fn(|_| {
                config.tls.clone().with_independent_handshake_budget()
            }),
            config,
            binding,
            connections: std::array::from_fn(|_| Mutex::new(None)),
        })
    }
    /// Full-round native authority view.
    pub async fn current(&self, attempt: Duration) -> Result<ScopeAuthorityView, ScopeRpcError> {
        let payload = self.read(Method::Current, None, attempt).await?;
        if payload.status != ResultStatus::CurrentView {
            return Err(payload_error(&payload)?);
        }
        let view = ScopeAuthorityView::decode_canonical(&payload.body).map_err(authority_error)?;
        if view.scope() != &self.config.scope {
            return Err(ScopeRpcError::Invalid);
        }
        Ok(view)
    }
    /// Resolve an exact retained authority receipt, never minting a capability.
    pub async fn outcome(
        &self,
        id: [u8; 16],
        digest: [u8; 32],
        attempt: Duration,
    ) -> Result<ScopeAuthorityReceipt, ScopeRpcError> {
        if id == [0; 16] || digest == [0; 32] {
            return Err(ScopeRpcError::Invalid);
        }
        let payload = self
            .read(Method::Outcome, Some((id, digest)), attempt)
            .await?;
        if payload.status != ResultStatus::Committed {
            return Err(payload_error(&payload)?);
        }
        let (stamp, active) = decode_committed(&payload.body, &self.config.scope)?;
        Ok(ScopeAuthorityReceipt { stamp, active })
    }
    /// Resolve an exact batch attempt through a full quorum read. A predecessor
    /// query requires neither its boot key nor its original mutation payload.
    /// Normal, Maintenance and EmergencyClassification are the read-only classes.
    pub async fn batch_outcome(
        &self,
        target: &ScopeBatchAttempt,
        class: ScopeWorkClass,
        attempt: Duration,
    ) -> Result<ScopeBatchLookup, ScopeBatchError> {
        if target.stamp().scope() != &self.config.scope || class == ScopeWorkClass::Emergency {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        let payload = self
            .read_canonical(
                Method::BatchLookup,
                data_class(class)?,
                target.encode_canonical()?,
                attempt,
            )
            .await
            .map_err(batch_error)?;
        lookup_response(payload, target)
    }
    async fn read(
        &self,
        method: Method,
        target: Option<([u8; 16], [u8; 32])>,
        attempt: Duration,
    ) -> Result<ResultPayload, ScopeRpcError> {
        let mut canonical = self
            .config
            .scope
            .encode_canonical()
            .map_err(authority_error)?;
        if let Some((id, digest)) = target {
            canonical.extend_from_slice(&id);
            canonical.extend_from_slice(&digest);
        }
        self.read_canonical(method, Class::SafetyControl, canonical, attempt)
            .await
    }
    async fn read_canonical(
        &self,
        method: Method,
        class: Class,
        canonical: Vec<u8>,
        attempt: Duration,
    ) -> Result<ResultPayload, ScopeRpcError> {
        if attempt.is_zero() {
            return Err(ScopeRpcError::Invalid);
        }
        let reservation = self
            .config
            .scheduler
            .reserve(
                opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                    &self.config.scope,
                ),
                work_class(class),
            )
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        let _running = reservation
            .start()
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        let mut slot = self.connections[class.index()].lock().await;
        let mut connection = match slot.take() {
            Some(connection) => connection,
            None => {
                let handshake = self.class_tls[class.index()]
                    .begin_handshake()
                    .map_err(|_| ScopeRpcError::Retry)?;
                timeout(Duration::from_secs(5), async {
                    let socket = TcpStream::connect(self.config.addresses[class.index()])
                        .await
                        .map_err(|_| ScopeRpcError::Retry)?;
                    socket.set_nodelay(true).map_err(|_| ScopeRpcError::Retry)?;
                    handshake
                        .connect_scope(
                            socket,
                            self.binding
                                .tls_domain()
                                .map_err(|_| ScopeRpcError::Invalid)?,
                        )
                        .await
                        .map_err(|_| ScopeRpcError::Retry)
                })
                .await
                .map_err(|_| ScopeRpcError::Retry)??
            }
        };
        if connection.peer_identity().spiffe_id() != &self.config.server {
            return Err(ScopeRpcError::Unauthorized);
        }
        let result = timeout(attempt, async {
            let request_id = super::boot::random_nonzero().map_err(|_| ScopeRpcError::Retry)?;
            let nonce = super::boot::random_nonzero().map_err(|_| ScopeRpcError::Retry)?;
            let digest = transport_request_digest(method, &request_id, &canonical)
                .map_err(|_| ScopeRpcError::Invalid)?;
            let body = CallPayload { nonce, canonical }
                .encode(method)
                .map_err(|_| ScopeRpcError::Invalid)?;
            let call = Header {
                kind: FrameKind::Call,
                class,
                method,
                installation: *self.binding.installation(),
                scope: self.binding.commitment(),
                request_id,
                digest,
                payload_len: body.len(),
            };
            connection
                .channel_binding(
                    ChannelBindingPurpose::ScopeRequest,
                    self.config
                        .clock
                        .interval()
                        .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?,
                )
                .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?;
            connection
                .write_all(&call.encode().map_err(|_| ScopeRpcError::Invalid)?)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            connection
                .write_all(&body)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            connection.flush().await.map_err(|_| ScopeRpcError::Retry)?;
            let mut fixed = [0; HEADER_BYTES];
            connection
                .read_exact(&mut fixed)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            let header = Header::decode(&fixed).map_err(|_| ScopeRpcError::Invalid)?;
            if header.kind != FrameKind::Result || !header.matches_attempt(&call) {
                return Err(ScopeRpcError::Unauthorized);
            }
            let mut bytes = vec![0; header.payload_len];
            connection
                .read_exact(&mut bytes)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            let payload = ResultPayload::decode(&bytes).map_err(|_| ScopeRpcError::Invalid)?;
            if payload.nonce != nonce || payload.own_execution != [0; 32] {
                return Err(ScopeRpcError::Invalid);
            }
            let cb = connection
                .channel_binding(
                    ChannelBindingPurpose::ScopeResponse,
                    self.config
                        .clock
                        .interval()
                        .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?,
                )
                .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?;
            super::proof::response_binding_input(&header, &payload, cb.as_bytes())
                .map_err(|_| ScopeRpcError::Invalid)?;
            Ok(payload)
        })
        .await
        .map_err(|_| ScopeRpcError::Retry)?;
        if result.is_ok() {
            *slot = Some(connection);
        }
        result
    }
}
