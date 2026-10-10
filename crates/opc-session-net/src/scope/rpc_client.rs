//! Process-owned requests, supervised attempts and checked native capability delivery.
use super::{
    evidence::{LocalClosurePublication, LocalClosureRecord},
    proof::{response_binding_input, PossessionProof},
    rpc::*,
    rpc_server::{authority_error, work_class},
    wire::*,
};
use opc_session_store::{
    scope_authority::*, scope_scheduler::ScopeWorkReservation, SessionConsumerIdentity,
};
use opc_tls::{ChannelBindingPurpose, ScopeTlsAuthentication, ScopeTlsConnection};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, Notify},
    time::{timeout, timeout_at, Instant},
};

pub(super) mod batch;
#[cfg(test)]
mod batch_tests;

struct Inner {
    config: ScopeClientConfig,
    execution: ScopeExecution,
    connections: [Mutex<Option<PooledConnection>>; 5],
    class_tls: [opc_tls::AuthenticatedClientConfig; 5],
}
struct PooledConnection {
    stream: ScopeTlsConnection<TcpStream>,
    idle_since: Instant,
}
/// A typed worker client, permanently bound to one SDK-owned process and scope.
#[derive(Clone)]
pub struct ScopeClient(Arc<Inner>);
struct Pending {
    request: ScopeAuthorityRequest,
    canonical: Vec<u8>,
    client: Arc<Inner>,
    close: Option<LocalClosureRecord>,
    state: Mutex<AttemptState>,
    notify: Notify,
}
struct AttemptState {
    reservation: Option<ScopeWorkReservation>,
    running: bool,
    generation: u64,
    resolved: bool,
    completed: Option<(u64, Result<ScopeAuthorityReply, ScopeRpcError>)>,
}
/// Immutable request plus the scheduler entitlement retained through uncertain attempts.
pub struct PendingScopeAuthority(Arc<Pending>);
impl PendingScopeAuthority {
    /// The exact native request, suitable for durable caller-side retry retention.
    pub fn request(&self) -> &ScopeAuthorityRequest {
        &self.0.request
    }
}
impl ScopeClient {
    /// Bind the actual configured TLS identity and exact process ticket hints.
    pub fn new(config: ScopeClientConfig) -> Result<Self, ScopeRpcError> {
        config
            .tls
            .validate_scope_profile()
            .map_err(|_| ScopeRpcError::Invalid)?;
        let binding =
            ScopeBinding::from_scope(&config.scope).map_err(|_| ScopeRpcError::Invalid)?;
        let hint = &config.ticket.hint;
        if config.process.scope() != &binding
            || hint.boot.scope != binding
            || hint.boot.workload != config.process.workload
            || hint.boot.process != *config.process.boot.process_nonce()
            || hint.boot.key != config.process.boot.key_digest()
            || config.addresses.iter().any(|address| address.port() == 0)
        {
            return Err(ScopeRpcError::Invalid);
        }
        config
            .process
            .boot
            .check_protection()
            .map_err(|_| ScopeRpcError::Unauthorized)?;
        let handshake = config
            .tls
            .begin_handshake()
            .map_err(|_| ScopeRpcError::Retry)?;
        let identity = SessionConsumerIdentity::new(handshake.local_identity().as_str())
            .map_err(|_| ScopeRpcError::Invalid)?;
        let execution = ScopeExecution::new(
            identity,
            hint.generation,
            hint.boot.workload,
            hint.boot.process,
            hint.boot.key,
        )
        .map_err(authority_error)?;
        Ok(Self(Arc::new(Inner {
            class_tls: std::array::from_fn(|_| {
                config.tls.clone().with_independent_handshake_budget()
            }),
            config,
            execution,
            connections: std::array::from_fn(|_| Mutex::new(None)),
        })))
    }
    /// Reserve before allocating the immutable initial admission command.
    pub async fn prepare_initial(&self) -> Result<PendingScopeAuthority, ScopeRpcError> {
        self.prepare(
            0,
            ScopeAuthorityOperation::AdmitInitial {
                execution: self.0.execution.clone(),
            },
            None,
        )
        .await
    }
    /// Cite the positively closed predecessor that actually committed.
    pub async fn prepare_successor(
        &self,
        predecessor: &ScopeAuthorityStamp,
        evidence: ScopeClosureEvidence,
    ) -> Result<PendingScopeAuthority, ScopeRpcError> {
        if predecessor.scope() != &self.0.config.scope
            || !matches!(
                evidence.kind(),
                ScopeClosureKind::FinalTermination | ScopeClosureKind::CommittedClose
            )
        {
            return Err(ScopeRpcError::Invalid);
        }
        self.prepare(
            predecessor.revision(),
            ScopeAuthorityOperation::SucceedClosed {
                predecessor: predecessor.clone(),
                execution: self.0.execution.clone(),
                evidence,
            },
            None,
        )
        .await
    }
    /// Irreversibly close and drain local submissions, then publish SDK evidence.
    /// Installed forwarding remains outside this gate and is not torn down.
    pub async fn prepare_close(
        &self,
        authority: &CommittedScopeAuthority,
    ) -> Result<PendingScopeAuthority, ScopeRpcError> {
        authority
            .check_execution(&self.0.execution)
            .map_err(authority_error)?;
        if authority.stamp().scope() != &self.0.config.scope {
            return Err(ScopeRpcError::Unauthorized);
        }
        let fence = self
            .0
            .config
            .process
            .gate
            .quiesce()
            .await
            .map_err(|_| ScopeRpcError::Closed)?;
        let record = LocalClosureRecord::new(authority.stamp().clone(), *fence.fence_nonce())
            .map_err(|_| ScopeRpcError::Invalid)?;
        let digest = record.digest().map_err(|_| ScopeRpcError::Invalid)?;
        timeout(
            Duration::from_secs(5),
            self.0
                .config
                .local_closure
                .publish(&LocalClosurePublication {
                    record: record.clone(),
                }),
        )
        .await
        .map_err(|_| ScopeRpcError::Retry)?
        .map_err(|_| ScopeRpcError::Retry)?;
        self.prepare(
            authority.stamp().revision(),
            ScopeAuthorityOperation::Close {
                current: authority.stamp().clone(),
                evidence: ScopeClosureEvidence::new(ScopeClosureKind::LocalQuiescence, digest)
                    .map_err(authority_error)?,
            },
            Some(record),
        )
        .await
    }
    async fn prepare(
        &self,
        revision: u64,
        operation: ScopeAuthorityOperation,
        close: Option<LocalClosureRecord>,
    ) -> Result<PendingScopeAuthority, ScopeRpcError> {
        let reservation = self
            .0
            .config
            .scheduler
            .reserve(
                opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                    &self.0.config.scope,
                ),
                work_class(Class::SafetyControl),
            )
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        let request = ScopeAuthorityRequest::new(
            self.0.config.scope.clone(),
            super::boot::random_nonzero().map_err(|_| ScopeRpcError::Retry)?,
            revision,
            operation,
        )
        .map_err(authority_error)?;
        let canonical = request.encode_canonical().map_err(authority_error)?;
        Ok(PendingScopeAuthority(Arc::new(Pending {
            request,
            canonical,
            client: self.0.clone(),
            close,
            state: Mutex::new(AttemptState {
                reservation: Some(reservation),
                running: false,
                generation: 0,
                resolved: false,
                completed: None,
            }),
            notify: Notify::new(),
        })))
    }
    /// Start or join one supervised attempt. Cancelling this observer preserves
    /// both the request and its resident entitlement until that attempt completes.
    pub async fn submit(
        &self,
        request: &PendingScopeAuthority,
        attempt: Duration,
    ) -> Result<ScopeAuthorityReply, ScopeRpcError> {
        if !Arc::ptr_eq(&self.0, &request.0.client) || attempt.is_zero() {
            return Err(ScopeRpcError::Invalid);
        }
        let wanted = {
            let mut state = request.0.state.lock().await;
            if !state.running {
                state.generation = state
                    .generation
                    .checked_add(1)
                    .ok_or(ScopeRpcError::Invalid)?;
                state.running = true;
                let generation = state.generation;
                let reserved = state.reservation.take();
                let pending = request.0.clone();
                let client = self.clone();
                tokio::spawn(async move {
                    let reservation = match reserved {
                        Some(value) => Ok(value),
                        None => client
                            .0
                            .config
                            .scheduler
                            .reserve(
                                opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                                    &client.0.config.scope,
                                ),
                                work_class(Class::SafetyControl),
                            )
                            .await,
                    };
                    let (outcome, reservation) = match reservation {
                        Ok(reservation) => match reservation.start().await {
                            Ok(permit) => {
                                let outcome = client.authority_attempt(&pending, attempt).await;
                                let reservation = if outcome.is_err() {
                                    Some(permit.finish_unknown())
                                } else {
                                    None
                                };
                                (outcome, reservation)
                            }
                            Err(failure) => {
                                (Err(ScopeRpcError::Retry), Some(failure.into_reservation()))
                            }
                        },
                        Err(_) => (Err(ScopeRpcError::Retry), None),
                    };
                    let mut state = pending.state.lock().await;
                    state.resolved |= outcome.is_ok();
                    state.reservation = if state.resolved { None } else { reservation };
                    state.running = false;
                    state.completed = Some((generation, outcome));
                    drop(state);
                    pending.notify.notify_waiters();
                });
            }
            state.generation
        };
        loop {
            let changed = request.0.notify.notified();
            {
                let state = request.0.state.lock().await;
                if let Some((generation, result)) = &state.completed {
                    if *generation >= wanted {
                        return result.clone();
                    }
                }
            }
            changed.await;
        }
    }
    async fn authority_attempt(
        &self,
        pending: &Pending,
        attempt: Duration,
    ) -> Result<ScopeAuthorityReply, ScopeRpcError> {
        let request = &pending.request;
        let method = authority_method(request);
        let mut candidate = None;
        let mut active = None;
        if method != Method::Close {
            match self.0.config.process.gate.candidate().await {
                Ok(guard) => candidate = Some(guard),
                Err(_) => {
                    active = Some(
                        self.0
                            .config
                            .process
                            .gate
                            .enter()
                            .await
                            .map_err(|_| ScopeRpcError::Closed)?,
                    )
                }
            }
        }
        let response = self
            .roundtrip(
                method,
                Class::SafetyControl,
                *request.request_id(),
                request.digest().map_err(authority_error)?,
                &pending.canonical,
                pending.close.as_ref(),
                attempt,
            )
            .await?;
        drop(candidate);
        drop(active);
        if response.payload.status != ResultStatus::Committed {
            return Err(
                payload_error(&response.payload).map_err(|_| ScopeRpcError::OutcomeUnknown)?
            );
        }
        // Once submission was possible, malformed committed claims cannot prove
        // either no effect or supersession. Preserve exact retry material.
        let (stamp, active) = decode_committed(&response.payload.body, &self.0.config.scope)
            .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
        if method == Method::Close {
            if active
                || response.payload.own_execution != [0; 32]
                || stamp.execution() != &self.0.execution
                || Some(stamp.revision()) != request.expected_revision().checked_add(1)
                || !matches!(request.operation(), ScopeAuthorityOperation::Close { current, .. }
                    if stamp.incarnation() == current.incarnation())
            {
                return Err(ScopeRpcError::OutcomeUnknown);
            }
            return Ok(ScopeAuthorityReply::Closed(Box::new(stamp)));
        }
        if !active
            || response.payload.own_execution
                != self
                    .0
                    .execution
                    .transport_digest()
                    .map_err(authority_error)?
        {
            return Err(ScopeRpcError::OutcomeUnknown);
        }
        let verifier = Arc::new(CheckedReply {
            request: request.clone(),
            stamp,
            authentication: response.authentication,
            clock: self.0.config.clock.clone(),
            binding: response.binding,
        });
        let boundary = ScopeAuthorityRemote::new(
            self.0.config.scope.clone(),
            self.0.execution.clone(),
            verifier,
        )
        .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
        let authority = boundary
            .admit(request)
            .await
            .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
        self.0
            .config
            .process
            .gate
            .activate()
            .await
            .map_err(|_| ScopeRpcError::Closed)?;
        Ok(ScopeAuthorityReply::Admitted(Box::new(authority)))
    }
    /// Observe a current view without constructing an effect capability.
    pub async fn current(&self, attempt: Duration) -> Result<ScopeAuthorityView, ScopeRpcError> {
        let payload = self.read(Method::Current, None, attempt).await?;
        if payload.status != ResultStatus::CurrentView || payload.own_execution != [0; 32] {
            return Err(payload_error(&payload)?);
        }
        let view = ScopeAuthorityView::decode_canonical(&payload.body).map_err(authority_error)?;
        if view.scope() != &self.0.config.scope {
            return Err(ScopeRpcError::Invalid);
        }
        Ok(view)
    }
    /// Resolve an authority receipt through a fresh full-round read. An absent
    /// retained receipt is reported explicitly, never as proof of no old effect.
    pub async fn outcome(
        &self,
        request: &PendingScopeAuthority,
        attempt: Duration,
    ) -> Result<ScopeAuthorityStamp, ScopeRpcError> {
        if !Arc::ptr_eq(&self.0, &request.0.client) {
            return Err(ScopeRpcError::Unauthorized);
        }
        let payload = self
            .read(
                Method::Outcome,
                Some((
                    *request.0.request.request_id(),
                    request.0.request.digest().map_err(authority_error)?,
                )),
                attempt,
            )
            .await?;
        if payload.status != ResultStatus::Committed || payload.own_execution != [0; 32] {
            return Err(payload_error(&payload)?);
        }
        let (stamp, _) = decode_committed(&payload.body, &self.0.config.scope)?;
        let mut state = request.0.state.lock().await;
        state.resolved = true;
        state.reservation = None;
        Ok(stamp)
    }
    /// Resolve an exact authority request from a predecessor in this scope.
    /// This observation never creates a capability for another boot.
    pub async fn lookup_outcome(
        &self,
        request: &ScopeAuthorityRequest,
        attempt: Duration,
    ) -> Result<super::ScopeAuthorityReceipt, ScopeRpcError> {
        if request.scope() != &self.0.config.scope {
            return Err(ScopeRpcError::Unauthorized);
        }
        let payload = self
            .read(
                Method::Outcome,
                Some((
                    *request.request_id(),
                    request.digest().map_err(authority_error)?,
                )),
                attempt,
            )
            .await?;
        if payload.status != ResultStatus::Committed || payload.own_execution != [0; 32] {
            return Err(payload_error(&payload)?);
        }
        let (stamp, active) = decode_committed(&payload.body, &self.0.config.scope)?;
        Ok(super::ScopeAuthorityReceipt { stamp, active })
    }
    async fn read(
        &self,
        method: Method,
        target: Option<([u8; 16], [u8; 32])>,
        attempt: Duration,
    ) -> Result<ResultPayload, ScopeRpcError> {
        if attempt.is_zero() {
            return Err(ScopeRpcError::Invalid);
        }
        let reservation = self
            .0
            .config
            .scheduler
            .reserve(
                opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                    &self.0.config.scope,
                ),
                work_class(Class::SafetyControl),
            )
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        let _running = reservation
            .start()
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        let mut canonical = self
            .0
            .config
            .scope
            .encode_canonical()
            .map_err(authority_error)?;
        if let Some((id, digest)) = target {
            canonical.extend_from_slice(&id);
            canonical.extend_from_slice(&digest);
        }
        let id = super::boot::random_nonzero().map_err(|_| ScopeRpcError::Retry)?;
        let digest = transport_request_digest(method, &id, &canonical)
            .map_err(|_| ScopeRpcError::Invalid)?;
        Ok(self
            .roundtrip(
                method,
                Class::SafetyControl,
                id,
                digest,
                &canonical,
                None,
                attempt,
            )
            .await?
            .payload)
    }
    #[allow(clippy::too_many_arguments)]
    async fn roundtrip(
        &self,
        method: Method,
        class: Class,
        id: [u8; 16],
        digest: [u8; 32],
        canonical: &[u8],
        close: Option<&LocalClosureRecord>,
        attempt: Duration,
    ) -> Result<VerifiedResponse, ScopeRpcError> {
        let mut slot = self.0.connections[class.index()].lock().await;
        let deadline = Instant::now()
            .checked_add(attempt)
            .ok_or(ScopeRpcError::Invalid)?;
        for reconnect in [false, true] {
            // The server closes after five seconds without a new call. Leave a
            // margin, and retry a raced close only while no proof was transmitted.
            let cached = slot
                .take()
                .filter(|entry| entry.idle_since.elapsed() < Duration::from_secs(4));
            let mut proof_started = false;
            let result = timeout_at(
                deadline,
                self.exchange(
                    cached,
                    method,
                    class,
                    id,
                    digest,
                    canonical,
                    close,
                    &mut proof_started,
                ),
            )
            .await
            .unwrap_or_else(|_| {
                Err(if proof_started {
                    ScopeRpcError::OutcomeUnknown
                } else {
                    ScopeRpcError::Retry
                })
            });
            match result {
                Ok((reply, stream)) => {
                    *slot = Some(PooledConnection {
                        stream,
                        idle_since: Instant::now(),
                    });
                    return Ok(reply);
                }
                Err(ScopeRpcError::Retry | ScopeRpcError::AuthTimeUnavailable)
                    if !proof_started && !reconnect => {}
                Err(error) => return Err(error),
            }
        }
        Err(ScopeRpcError::Retry)
    }

    #[allow(clippy::too_many_arguments)]
    async fn exchange(
        &self,
        cached: Option<PooledConnection>,
        method: Method,
        class: Class,
        id: [u8; 16],
        digest: [u8; 32],
        canonical: &[u8],
        close: Option<&LocalClosureRecord>,
        proof_started: &mut bool,
    ) -> Result<(VerifiedResponse, ScopeTlsConnection<TcpStream>), ScopeRpcError> {
        let mut connection = match cached {
            Some(connection) => connection.stream,
            None => {
                let handshake = self.0.class_tls[class.index()]
                    .begin_handshake()
                    .map_err(|_| ScopeRpcError::Retry)?;
                timeout(Duration::from_secs(5), async {
                    let socket = TcpStream::connect(self.0.config.addresses[class.index()])
                        .await
                        .map_err(|_| ScopeRpcError::Retry)?;
                    socket.set_nodelay(true).map_err(|_| ScopeRpcError::Retry)?;
                    handshake
                        .connect_scope(
                            socket,
                            self.0
                                .config
                                .process
                                .scope
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
        if connection.peer_identity().spiffe_id() != &self.0.config.server
            || connection.local_identity().as_str() != self.0.execution.identity().as_str()
        {
            return Err(ScopeRpcError::Unauthorized);
        }
        let result = async {
            let nonce = super::boot::random_nonzero().map_err(|_| ScopeRpcError::Retry)?;
            let payload = CallPayload {
                nonce,
                canonical: canonical.to_vec(),
            };
            let bytes = payload.encode(method).map_err(|_| ScopeRpcError::Invalid)?;
            let call = Header {
                kind: FrameKind::Call,
                class,
                method,
                installation: *self.0.config.process.scope.installation(),
                scope: self.0.config.process.scope.commitment(),
                request_id: id,
                digest,
                payload_len: bytes.len(),
            };
            let interval = self
                .0
                .config
                .clock
                .interval()
                .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?;
            connection
                .channel_binding(ChannelBindingPurpose::ScopeRequest, interval)
                .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?;
            connection
                .write_all(&call.encode().map_err(|_| ScopeRpcError::Invalid)?)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            connection
                .write_all(&bytes)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            connection.flush().await.map_err(|_| ScopeRpcError::Retry)?;
            let mut fixed = [0; HEADER_BYTES];
            connection
                .read_exact(&mut fixed)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            let header = Header::decode(&fixed).map_err(|_| ScopeRpcError::Invalid)?;
            if !header.matches_attempt(&call) {
                return Err(ScopeRpcError::Invalid);
            }
            if header.kind == FrameKind::Result {
                // A pre-challenge refusal is correlated to this call, but can
                // never deliver a result or capability for an unproved request.
                if header.payload_len != 71 {
                    return Err(ScopeRpcError::Invalid);
                }
                let mut bytes = [0; 71];
                connection
                    .read_exact(&mut bytes)
                    .await
                    .map_err(|_| ScopeRpcError::Retry)?;
                let payload = ResultPayload::decode(&bytes).map_err(|_| ScopeRpcError::Invalid)?;
                if payload.nonce != nonce || payload.status != ResultStatus::ProvenNoEffect {
                    return Err(ScopeRpcError::Invalid);
                }
                connection
                    .authentication_state(
                        self.0
                            .config
                            .clock
                            .interval()
                            .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?,
                    )
                    .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?;
                return Err(payload_error(&payload)?);
            }
            if header.kind != FrameKind::Challenge
                || header.payload_len != 32
                || !header.matches_attempt(&call)
            {
                return Err(ScopeRpcError::Invalid);
            }
            let mut challenge = [0; 32];
            connection
                .read_exact(&mut challenge)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            let authority = matches!(method, Method::AdmitInitial | Method::SucceedClosed)
                .then(|| self.0.config.ticket.hint.authority.clone());
            let proof: PossessionProof = self.0.config.process.boot.scope_proof(
                &connection,
                self.0
                    .config
                    .clock
                    .interval()
                    .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?,
                &self.0.config.scope,
                &self.0.execution,
                &call,
                nonce,
                canonical,
                authority,
                challenge,
                close,
            )?;
            let bytes = proof.encode().map_err(|_| ScopeRpcError::Invalid)?;
            let header = call
                .response(FrameKind::Proof, bytes.len())
                .map_err(|_| ScopeRpcError::Invalid)?;
            let fixed_proof = header.encode().map_err(|_| ScopeRpcError::Invalid)?;
            // A failed/cancelled write can have exposed proof bytes. From this
            // point onward, transport failure conservatively retains uncertainty.
            *proof_started = true;
            connection
                .write_all(&fixed_proof)
                .await
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            connection
                .write_all(&bytes)
                .await
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            connection
                .flush()
                .await
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            connection
                .read_exact(&mut fixed)
                .await
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            let header = Header::decode(&fixed).map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            if header.kind != FrameKind::Result || !header.matches_attempt(&call) {
                return Err(ScopeRpcError::OutcomeUnknown);
            }
            let mut bytes = vec![0; header.payload_len];
            connection
                .read_exact(&mut bytes)
                .await
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            let payload =
                ResultPayload::decode(&bytes).map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            if payload.nonce != nonce {
                return Err(ScopeRpcError::OutcomeUnknown);
            }
            let interval = self
                .0
                .config
                .clock
                .interval()
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            let binding = *connection
                .channel_binding(ChannelBindingPurpose::ScopeResponse, interval)
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?
                .as_bytes();
            let correlation = hash(
                &response_binding_input(&header, &payload, &binding)
                    .map_err(|_| ScopeRpcError::OutcomeUnknown)?,
            );
            let authentication = connection
                .authentication_state(interval)
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            Ok(VerifiedResponse {
                payload,
                authentication,
                binding: correlation,
            })
        }
        .await?;
        Ok((result, connection))
    }
}
struct VerifiedResponse {
    payload: ResultPayload,
    authentication: ScopeTlsAuthentication,
    binding: [u8; 32],
}
struct CheckedReply {
    request: ScopeAuthorityRequest,
    stamp: ScopeAuthorityStamp,
    authentication: ScopeTlsAuthentication,
    clock: Arc<dyn super::AuthenticationClock>,
    binding: [u8; 32],
}
#[async_trait::async_trait]
impl ScopeAuthorityResponseVerifier for CheckedReply {
    async fn verify_own_current(
        &self,
        request: &ScopeAuthorityRequest,
        execution: &ScopeExecution,
    ) -> Result<ScopeAuthorityStamp, ScopeAuthorityError> {
        if request != &self.request
            || self.stamp.execution() != execution
            || self.binding == [0; 32]
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        self.authentication
            .revalidate(
                self.clock
                    .interval()
                    .map_err(|_| ScopeAuthorityError::Unavailable)?,
            )
            .map_err(|_| ScopeAuthorityError::Unavailable)?;
        Ok(self.stamp.clone())
    }
}
fn authority_method(request: &ScopeAuthorityRequest) -> Method {
    match request.operation() {
        ScopeAuthorityOperation::AdmitInitial { .. } => Method::AdmitInitial,
        ScopeAuthorityOperation::SucceedClosed { .. } => Method::SucceedClosed,
        ScopeAuthorityOperation::Close { .. } => Method::Close,
    }
}
pub(super) fn decode_committed(
    bytes: &[u8],
    scope: &ScopeId,
) -> Result<(ScopeAuthorityStamp, bool), ScopeRpcError> {
    let (active, body) = bytes.split_last().ok_or(ScopeRpcError::Invalid)?;
    if *active > 1 {
        return Err(ScopeRpcError::Invalid);
    }
    let stamp = ScopeAuthorityStamp::decode_canonical(body).map_err(authority_error)?;
    if stamp.scope() != scope {
        return Err(ScopeRpcError::Invalid);
    }
    Ok((stamp, *active == 1))
}
pub(super) fn payload_error(payload: &ResultPayload) -> Result<ScopeRpcError, ScopeRpcError> {
    if payload.own_execution != [0; 32] {
        return Err(ScopeRpcError::Invalid);
    }
    Ok(match (payload.status, payload.body.as_slice()) {
        (ResultStatus::OutcomeUnknown, []) => ScopeRpcError::OutcomeUnknown,
        (ResultStatus::Obsolete, [1]) => ScopeRpcError::Superseded,
        (ResultStatus::Obsolete, [2]) => ScopeRpcError::Closed,
        (ResultStatus::Obsolete, [3]) => ScopeRpcError::Retired,
        (ResultStatus::Obsolete, [4]) => ScopeRpcError::ReceiptUnavailable,
        (ResultStatus::ProvenNoEffect, [0, 1]) => ScopeRpcError::Invalid,
        (ResultStatus::ProvenNoEffect, [0, 2]) => ScopeRpcError::Unauthorized,
        (ResultStatus::ProvenNoEffect, [0, 3]) => ScopeRpcError::Retry,
        (ResultStatus::ProvenNoEffect, [0, 4]) => ScopeRpcError::AuthTimeUnavailable,
        (ResultStatus::ProvenNoEffect, [0, 5]) => ScopeRpcError::ProfileUnavailable,
        _ => return Err(ScopeRpcError::Invalid),
    })
}
