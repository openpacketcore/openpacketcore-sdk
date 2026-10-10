//! Scope server dispatch; only this module constructs verified native admission.
use super::{
    evidence::*,
    policy::{RoutedCall, ScopeRole},
    pool::{ProofPools, ProofShare},
    proof::{PossessionClaims, PossessionProof},
    rpc::*,
    wire::*,
};
use opc_session_store::{
    scope_authority::*,
    scope_batch::{ScopeBatchAttempt, ScopeBatchError, ScopeBatchRequest, ScopeBatchStore},
    scope_scheduler::ScopeWorkClass,
    SessionConsumerIdentity,
};
use opc_tls::{ChannelBindingPurpose, ScopeTlsAuthentication, ScopeTlsConnection};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    task::JoinHandle,
    time::{timeout, Instant},
};

const CLASSES: [Class; 5] = [
    Class::SafetyControl,
    Class::Emergency,
    Class::EmergencyClassification,
    Class::Normal,
    Class::Maintenance,
];
#[cfg(test)]
mod batch_tests;
mod listener;
#[cfg(test)]
mod scan_tests;
mod scans;
use scans::ScanViews;
/// Authenticated scope service with independent per-class connection/proof
/// capacity and native durable authority dispatch.
pub struct ScopeServer {
    config: ScopeServerConfig,
    scopes: BTreeMap<[u8; 32], ScopeId>,
    proofs: ProofPools,
    handshakes: [Arc<Semaphore>; 5],
    class_tls: [opc_tls::AuthenticatedServerConfig; 5],
    #[cfg(test)]
    drop_reply: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    drop_scan_reply: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    corrupt_reply: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    pause_reply: std::sync::Mutex<Option<Arc<ReplyPause>>>,
}
struct Deny;
#[async_trait::async_trait]
impl ScopeAuthorityAdmission for Deny {
    async fn authorize(
        &self,
        _: &SessionConsumerIdentity,
        _: &ScopeId,
        _: Option<&ScopeExecution>,
        _: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        Err(ScopeAuthorityError::Unauthorized)
    }
}
impl ScopeServer {
    /// Validate immutable scope bindings without conferring store readiness.
    pub fn new(config: ScopeServerConfig) -> Result<Self, ScopeRpcError> {
        config
            .tls
            .validate_scope_profile()
            .map_err(|_| ScopeRpcError::Invalid)?;
        if config.scopes.is_empty() {
            return Err(ScopeRpcError::Invalid);
        }
        let mut scopes = BTreeMap::new();
        for scope in &config.scopes {
            ScopeAuthorityStore::new(config.store.clone(), scope.clone(), Arc::new(Deny))
                .map_err(authority_error)?;
            let binding = ScopeBinding::from_scope(scope).map_err(|_| ScopeRpcError::Invalid)?;
            if scopes.insert(binding.commitment(), scope.clone()).is_some() {
                return Err(ScopeRpcError::Invalid);
            }
        }
        let proofs = ProofPools::new(config.proofs).map_err(|_| ScopeRpcError::Invalid)?;
        Ok(Self {
            class_tls: std::array::from_fn(|_| {
                config.tls.clone().with_independent_handshake_budget()
            }),
            config,
            scopes,
            proofs,
            handshakes: std::array::from_fn(|_| Arc::new(Semaphore::new(8))),
            #[cfg(test)]
            drop_reply: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            drop_scan_reply: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            corrupt_reply: std::sync::atomic::AtomicU8::new(0),
            #[cfg(test)]
            pause_reply: std::sync::Mutex::new(None),
        })
    }
    #[cfg(test)]
    pub(crate) fn lose_next_committed_reply_for_test(&self) {
        self.drop_reply
            .store(true, std::sync::atomic::Ordering::Release);
    }
    #[cfg(test)]
    pub(crate) fn unproven_proof_waiters_for_test(&self, class: Class) -> usize {
        self.proofs.waiting(class, ProofShare::WorkerUnproven)
    }
    #[cfg(test)]
    pub(crate) fn lose_next_scan_reply_for_test(&self) {
        self.drop_scan_reply
            .store(true, std::sync::atomic::Ordering::Release);
    }
    #[cfg(test)]
    pub(crate) fn corrupt_next_committed_reply_for_test(&self, kind: u8) {
        self.corrupt_reply
            .store(kind, std::sync::atomic::Ordering::Release);
    }
    #[cfg(test)]
    pub(crate) fn pause_next_committed_reply_for_test(&self) -> Arc<ReplyPause> {
        let pause = Arc::new(ReplyPause {
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        *self.pause_reply.lock().unwrap() = Some(pause.clone());
        pause
    }
    /// Bind distinct pre-TLS listeners and supervise a bounded set of connections
    /// for every class. Saturation waits before accept; it never refuses a session.
    pub async fn serve(
        self: Arc<Self>,
        addresses: [SocketAddr; 5],
    ) -> Result<ScopeServerHandle, ScopeRpcError> {
        let mut bound = addresses;
        let mut listeners = Vec::with_capacity(5);
        for (index, address) in addresses.into_iter().enumerate() {
            let listener = TcpListener::bind(address)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            bound[index] = listener.local_addr().map_err(|_| ScopeRpcError::Retry)?;
            listeners.push(listener);
        }
        let views = Arc::new(ScanViews::default());
        let (stop, receive) = watch::channel(false);
        let tasks: Vec<_> = listeners
            .into_iter()
            .zip(CLASSES)
            .map(|(listener, class)| {
                let server = self.clone();
                let views = views.clone();
                let stop = receive.clone();
                tokio::spawn(async move {
                    listener::supervise(
                        || async { listener.accept().await.map(|(stream, _)| stream) },
                        move |stream| {
                            let server = server.clone();
                            let views = views.clone();
                            async move {
                                let _ = server.connection(class, stream, views).await;
                            }
                        },
                        stop,
                    )
                    .await;
                })
            })
            .collect();
        let cleanup = views.clone();
        let supervisor = tokio::spawn(async move {
            let mut stop = receive;
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    biased;
                    _ = stop.changed() => break,
                    _ = interval.tick() => cleanup.reap(),
                }
            }
            cleanup.begin_close();
            // Cancel connection work before freeing capacity: a queued open
            // must not be admitted during listener shutdown.
            for task in tasks {
                let _ = task.await;
            }
            cleanup.shutdown().await;
        });
        Ok(ScopeServerHandle {
            addresses: bound,
            stop,
            tasks: vec![supervisor],
            views,
        })
    }
    async fn connection(
        &self,
        class: Class,
        io: TcpStream,
        views: Arc<ScanViews>,
    ) -> Result<(), ScopeRpcError> {
        super::socket::configure(&io).map_err(|_| ScopeRpcError::Retry)?;
        let handshake_slot = self.handshakes[class.index()]
            .acquire()
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        let handshake = self.class_tls[class.index()]
            .begin_handshake()
            .map_err(|_| ScopeRpcError::Retry)?;
        let (connection, first, scope) = timeout(Duration::from_secs(5), async {
            let mut connection = handshake
                .accept_scope_unbound(io)
                .await
                .map_err(|_| ScopeRpcError::Unauthorized)?;
            let mut fixed = [0; HEADER_BYTES];
            connection
                .read_exact(&mut fixed)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            let header = Header::decode(&fixed).map_err(|_| ScopeRpcError::Invalid)?;
            if header.kind != FrameKind::Call || header.class != class {
                return Err(ScopeRpcError::Invalid);
            }
            // Bind a configured scope before the live role check so that a
            // revoked policy can receive a correlated no-effect refusal. This
            // lookup itself confers no authorization and reads no command body.
            let scope = self
                .scopes
                .get(&header.scope)
                .map(ScopeBinding::from_scope)
                .transpose()
                .map_err(|_| ScopeRpcError::Invalid)?
                .or_else(|| {
                    self.config
                        .policy
                        .resolve_scope(
                            connection.peer_identity().spiffe_id(),
                            &header.installation,
                            &header.scope,
                        )
                        .ok()
                })
                .ok_or(ScopeRpcError::Unauthorized)?;
            let connection = connection
                .bind_scope(scope.tls_domain().map_err(|_| ScopeRpcError::Invalid)?)
                .map_err(|_| ScopeRpcError::Invalid)?;
            Ok((connection, header, scope))
        })
        .await
        .map_err(|_| ScopeRpcError::Retry)??;
        drop(handshake_slot);
        let mut connection = connection;
        let mut header = first;
        let mut promoted = None;
        loop {
            if header.kind != FrameKind::Call
                || header.class != class
                || header.scope != scope.commitment()
                || header.installation != *scope.installation()
            {
                return Err(ScopeRpcError::Invalid);
            }
            self.call(&mut connection, &header, &scope, &mut promoted, &views)
                .await?;
            let mut fixed = [0; HEADER_BYTES];
            timeout(Duration::from_secs(5), connection.read_exact(&mut fixed))
                .await
                .map_err(|_| ScopeRpcError::Retry)?
                .map_err(|_| ScopeRpcError::Retry)?;
            header = Header::decode(&fixed).map_err(|_| ScopeRpcError::Invalid)?;
        }
    }
    async fn call(
        &self,
        connection: &mut ScopeTlsConnection<TcpStream>,
        header: &Header,
        binding: &ScopeBinding,
        promoted: &mut Option<ScopeAuthorityStamp>,
        views: &ScanViews,
    ) -> Result<(), ScopeRpcError> {
        let prepared = async {
            let route = Arc::new(
                self.config
                    .policy
                    .authorize(
                        connection.peer_identity().spiffe_id(),
                        binding,
                        header.method,
                        header.class,
                    )
                    .map_err(|_| ScopeRpcError::Unauthorized)?,
            );
            let scope = self
                .scopes
                .get(&header.scope)
                .cloned()
                .ok_or(ScopeRpcError::Unauthorized)?;
            let authentication = connection
                .authentication_state(
                    self.config
                        .clock
                        .interval()
                        .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?,
                )
                .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?;
            if let Some(stamp) = promoted.clone() {
                let context = Context {
                    route: route.clone(),
                    scope: scope.clone(),
                    authentication: authentication.clone(),
                    clock: self.config.clock.clone(),
                };
                let still_current = if header.method.is_scan() {
                    self.scan_current(&context, &stamp, header.method == Method::ScanClassify)
                        .await
                        .is_ok()
                } else {
                    let store = ScopeAuthorityStore::new(
                        self.config.store.clone(),
                        scope.clone(),
                        Arc::new(Routing(context.clone())),
                    )
                    .map_err(authority_error)?;
                    let view = store
                        .current(&context.identity()?)
                        .await
                        .map_err(authority_error)?;
                    view.is_active() && view.stamp() == Some(&stamp)
                };
                if !still_current {
                    *promoted = None;
                }
            }
            Ok::<_, ScopeRpcError>((route, scope, authentication))
        }
        .await;
        let (route, scope, authentication) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                refuse_before_dispatch(connection, header, RefusalReply::AwaitNonce, error).await?;
                return Err(error);
            }
        };
        let share = match route.role {
            ScopeRole::Controller => ProofShare::Controller,
            ScopeRole::Worker if promoted.is_some() => ProofShare::WorkerCurrent,
            ScopeRole::Worker
                if matches!(header.method, Method::AdmitInitial | Method::SucceedClosed) =>
            {
                ProofShare::Candidate
            }
            _ => ProofShare::WorkerUnproven,
        };
        // An unproven principal cannot spend established-emergency proof capacity.
        let proof_class = if header.class == Class::Emergency && promoted.is_none() {
            Class::EmergencyClassification
        } else {
            header.class
        };
        let credit = self
            .proofs
            .reserve(
                proof_class,
                share,
                &route.principal,
                route.scope.commitment(),
            )
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        let connection_ref = &mut *connection;
        let promoted_ref = &mut *promoted;
        let mut refusal_reply = RefusalReply::AwaitNonce;
        let reply_ref = &mut refusal_reply;
        let verified = credit
            .verify_then_retain(
                Instant::now() + Duration::from_secs(5),
                |challenge| async move {
                    Ok(self
                        .verify_call(
                            connection_ref,
                            header,
                            Context {
                                route,
                                scope,
                                authentication,
                                clock: self.config.clock.clone(),
                            },
                            challenge,
                            promoted_ref,
                            reply_ref,
                        )
                        .await)
                },
            )
            .await
            .map_err(|_| ScopeRpcError::Retry);
        let (verified, _proof_credit) = match verified {
            Ok(verified) => verified,
            Err(error) => {
                refuse_before_dispatch(connection, header, refusal_reply, error).await?;
                return Err(error);
            }
        };
        let (call, admission, nonce) = match verified {
            Ok(verified) => verified,
            Err(error) => {
                refuse_before_dispatch(connection, header, refusal_reply, error).await?;
                return Err(error);
            }
        };
        let _running = if header.method.is_scan() {
            // Scan execution is owned by the store's actual workers. In
            // particular, retention queueing must not hold a second permit.
            None
        } else {
            Some(
                self.config
                    .scheduler
                    .reserve(
                        opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                            &admission.context.scope,
                        ),
                        work_class(admission.dispatch_class()),
                    )
                    .await
                    .map_err(|_| ScopeRpcError::Retry)?
                    .start()
                    .await
                    .map_err(|_| ScopeRpcError::Retry)?,
            )
        };
        let outcome = match call {
            Ok(call) if header.method.is_scan() => {
                // Requests are sequential on this channel. EOF cancels a
                // waiting admission promptly; pipelining is not a valid next
                // call before its response. The caller owns the scan deadline.
                tokio::select! {
                    biased;
                    _ = connection.read_u8() => return Err(ScopeRpcError::Retry),
                    outcome = self.dispatch(&call, admission.clone(), views) => outcome,
                }
            }
            Ok(call) => timeout(
                Duration::from_secs(5),
                self.dispatch(&call, admission.clone(), views),
            )
            .await
            .map_err(|_| ScopeRpcError::OutcomeUnknown)
            .and_then(|v| v),
            Err(refusal) => Err(refusal),
        };
        let (status, own, body, current) = match outcome {
            Ok(value) => value,
            Err(error) => (error_status(error).0, [0; 32], error_status(error).1, None),
        };
        admission.check().map_err(authority_error)?;
        #[cfg(test)]
        if status == ResultStatus::ScanObservation
            && self
                .drop_scan_reply
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(ScopeRpcError::OutcomeUnknown);
        }
        #[cfg(test)]
        if status == ResultStatus::Committed
            && self
                .drop_reply
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(ScopeRpcError::OutcomeUnknown);
        }
        #[cfg(test)]
        if status == ResultStatus::Committed {
            let pause = self.pause_reply.lock().unwrap().take();
            if let Some(pause) = pause {
                pause.entered.notify_one();
                pause.release.notified().await;
            }
        }
        if let Some(stamp) = current {
            *promoted = Some(stamp);
        }
        if header.method == Method::Close && status == ResultStatus::Committed {
            *promoted = None;
        }
        #[cfg(test)]
        let (nonce, own, body) = {
            let (mut nonce, mut own, mut body) = (nonce, own, body);
            if status == ResultStatus::Committed {
                match self
                    .corrupt_reply
                    .swap(0, std::sync::atomic::Ordering::AcqRel)
                {
                    1 => nonce[0] ^= 1,
                    2 => own[0] ^= 1,
                    3 => body = vec![0],
                    4 => *body.last_mut().unwrap() = 0,
                    5 => {
                        let original =
                            ScopeAuthorityStamp::decode_canonical(&body[..body.len() - 1]).unwrap();
                        let last_stamp_byte = body.len() - 2;
                        body[last_stamp_byte] ^= 2;
                        let changed =
                            ScopeAuthorityStamp::decode_canonical(&body[..body.len() - 1]).unwrap();
                        assert_ne!(
                            original, changed,
                            "the malformed claim remains a valid canonical stamp"
                        );
                    }
                    _ => {}
                }
            }
            (nonce, own, body)
        };
        let payload =
            ResultPayload::new(nonce, status, own, body).map_err(|_| ScopeRpcError::Invalid)?;
        let bytes = payload.encode().map_err(|_| ScopeRpcError::Invalid)?;
        let reply = header
            .response(FrameKind::Result, bytes.len())
            .map_err(|_| ScopeRpcError::Invalid)?;
        timeout(Duration::from_secs(5), async {
            connection
                .write_all(&reply.encode().map_err(|_| ScopeRpcError::Invalid)?)
                .await
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            connection
                .write_all(&bytes)
                .await
                .map_err(|_| ScopeRpcError::OutcomeUnknown)?;
            connection
                .flush()
                .await
                .map_err(|_| ScopeRpcError::OutcomeUnknown)
        })
        .await
        .map_err(|_| ScopeRpcError::OutcomeUnknown)??;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    async fn verify_call(
        &self,
        connection: &mut ScopeTlsConnection<TcpStream>,
        header: &Header,
        context: Context,
        challenge: [u8; 32],
        promoted: &mut Option<ScopeAuthorityStamp>,
        refusal_reply: &mut RefusalReply,
    ) -> Result<
        (
            Result<NativeCall, ScopeRpcError>,
            Arc<VerifiedScopeCall>,
            [u8; 32],
        ),
        ScopeRpcError,
    > {
        context.check().map_err(authority_error)?;
        // A partial read or invalid proof must never cause an attempted reply
        // using bytes at an unknown offset or claims supplied by another stream.
        *refusal_reply = RefusalReply::Silent;
        let mut body = vec![0; header.payload_len];
        connection
            .read_exact(&mut body)
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        let payload =
            CallPayload::decode(header.method, &body).map_err(|_| ScopeRpcError::Invalid)?;
        *refusal_reply = RefusalReply::Allowed(payload.nonce);
        let call = NativeCall::decode(header, &payload.canonical, &context.scope)?;
        let mut execution = None;
        let mut public_key = None;
        let mut reference = None;
        let mut current = false;
        let mut scan_failure = None;
        if context.route.requires_worker_proof() {
            *refusal_reply = RefusalReply::Silent;
            let challenge_bytes = challenge.to_vec();
            let reply = header
                .response(FrameKind::Challenge, challenge_bytes.len())
                .map_err(|_| ScopeRpcError::Invalid)?;
            connection
                .write_all(&reply.encode().map_err(|_| ScopeRpcError::Invalid)?)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            connection
                .write_all(&challenge_bytes)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            connection.flush().await.map_err(|_| ScopeRpcError::Retry)?;
            let mut fixed = [0; HEADER_BYTES];
            connection
                .read_exact(&mut fixed)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            let proof_header = Header::decode(&fixed).map_err(|_| ScopeRpcError::Invalid)?;
            if proof_header.kind != FrameKind::Proof || !proof_header.matches_attempt(header) {
                return Err(ScopeRpcError::Invalid);
            }
            let mut bytes = vec![0; proof_header.payload_len];
            connection
                .read_exact(&mut bytes)
                .await
                .map_err(|_| ScopeRpcError::Retry)?;
            let proof = PossessionProof::decode(&bytes).map_err(|_| ScopeRpcError::Invalid)?;
            let claims = PossessionClaims {
                call: header.clone(),
                caller_nonce: payload.nonce,
                execution: call
                    .execution()
                    .map(ScopeExecution::transport_digest)
                    .transpose()
                    .map_err(authority_error)?
                    .unwrap_or(proof.claims.execution),
                public_key: proof.claims.public_key,
                authority: proof.claims.authority.clone(),
                challenge,
                binding: *connection
                    .channel_binding(
                        ChannelBindingPurpose::ScopeRequest,
                        self.config
                            .clock
                            .interval()
                            .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?,
                    )
                    .map_err(|_| ScopeRpcError::AuthTimeUnavailable)?
                    .as_bytes(),
            };
            proof
                .verify_against(&claims)
                .map_err(|_| ScopeRpcError::Unauthorized)?;
            *refusal_reply = RefusalReply::Allowed(payload.nonce);
            public_key = Some(claims.public_key);
            reference = claims.authority;
            execution = call.execution().cloned();
            if let Some(value) = &execution {
                if value.identity().as_str() != context.route.principal.as_str()
                    || value.boot_key() != &hash(&claims.public_key)
                {
                    return Err(ScopeRpcError::Unauthorized);
                }
            }
            if let NativeCall::Scan(request) = &call {
                match self
                    .scan_current(
                        &context,
                        request.stamp(),
                        header.method == Method::ScanClassify,
                    )
                    .await
                {
                    Ok(()) => {
                        current = true;
                        *promoted = Some(request.stamp().clone());
                    }
                    Err(error) => {
                        scan_failure = Some(error);
                        *promoted = None;
                    }
                }
            } else {
                let routing = Arc::new(Routing(context.clone()));
                let store = ScopeAuthorityStore::new(
                    self.config.store.clone(),
                    context.scope.clone(),
                    routing,
                )
                .map_err(authority_error)?;
                let view = store
                    .current(&context.identity()?)
                    .await
                    .map_err(authority_error)?;
                if promoted.as_ref() != view.stamp() || !view.is_active() {
                    *promoted = None;
                }
                if execution.is_none() {
                    execution = view
                        .stamp()
                        .filter(|stamp| {
                            stamp.execution().transport_digest() == Ok(claims.execution)
                                && stamp.execution().boot_key() == &hash(&claims.public_key)
                        })
                        .map(|stamp| stamp.execution().clone());
                    if execution.is_none() {
                        let known = self
                            .config
                            .boots
                            .read_known(&context.route.scope, hash(&claims.public_key))
                            .await
                            .map_err(evidence_error)?;
                        if known.scope != context.route.scope
                            || known.public_key != claims.public_key
                            || known
                                .execution
                                .transport_digest()
                                .map_err(authority_error)?
                                != claims.execution
                        {
                            return Err(ScopeRpcError::Unauthorized);
                        }
                        execution = Some(known.execution);
                    }
                }
                let value = execution.as_ref().ok_or(ScopeRpcError::Unauthorized)?;
                if value.identity().as_str() != context.route.principal.as_str()
                    || value.boot_key() != &hash(&claims.public_key)
                {
                    return Err(ScopeRpcError::Unauthorized);
                }
                if view.is_active() && view.stamp().is_some_and(|stamp| stamp.execution() == value)
                {
                    current = true;
                    *promoted = view.stamp().cloned();
                } else {
                    *promoted = None;
                }
            }
        }
        let mut ticket = None;
        let mut refusal = None;
        if let NativeCall::Authority(request) = &call {
            let routing = Arc::new(Routing(context.clone()));
            let store =
                ScopeAuthorityStore::new(self.config.store.clone(), context.scope.clone(), routing)
                    .map_err(authority_error)?;
            let retained = store
                .outcome(
                    &context.identity()?,
                    *request.request_id(),
                    request.digest().map_err(authority_error)?,
                )
                .await
                .map_err(authority_error)?;
            if let ScopeAuthorityOutcome::ReceiptUnavailable(view) = retained {
                refusal = obsolete_request(&view, request);
                if refusal.is_none()
                    && matches!(
                        request.operation(),
                        ScopeAuthorityOperation::AdmitInitial { .. }
                            | ScopeAuthorityOperation::SucceedClosed { .. }
                    )
                {
                    match super::evidence::verify_current_ticket(
                        &*self.config.boots,
                        &context.route.scope,
                        execution.as_ref().ok_or(ScopeRpcError::Unauthorized)?,
                        &public_key.ok_or(ScopeRpcError::Unauthorized)?,
                        reference.as_ref().ok_or(ScopeRpcError::Unauthorized)?,
                    )
                    .await
                    {
                        Ok(record) => ticket = Some(record),
                        Err(error) => refusal = Some(evidence_error(error)),
                    }
                }
            }
        }
        context.check().map_err(authority_error)?;
        Ok((
            refusal.map_or(Ok(call), Err),
            Arc::new(VerifiedScopeCall {
                context,
                execution,
                ticket,
                boots: self.config.boots.clone(),
                closures: self.config.closures.clone(),
                digest: header.digest,
                current,
                scan_failure,
            }),
            payload.nonce,
        ))
    }
    async fn dispatch(
        &self,
        call: &NativeCall,
        admission: Arc<VerifiedScopeCall>,
        views: &ScanViews,
    ) -> Result<(ResultStatus, [u8; 32], Vec<u8>, Option<ScopeAuthorityStamp>), ScopeRpcError> {
        admission.check().map_err(authority_error)?;
        let store = ScopeAuthorityStore::new(
            self.config.store.clone(),
            admission.context.scope.clone(),
            admission.clone(),
        )
        .map_err(authority_error)?;
        let identity = admission.context.identity()?;
        match call {
            NativeCall::Authority(request) => match request.operation() {
                ScopeAuthorityOperation::AdmitInitial { .. }
                | ScopeAuthorityOperation::SucceedClosed { .. } => {
                    let authority = store
                        .admit(&identity, request)
                        .await
                        .map_err(authority_error)?;
                    let stamp = authority.stamp().clone();
                    let mut body = stamp.encode_canonical().map_err(authority_error)?;
                    body.push(1);
                    Ok((
                        ResultStatus::Committed,
                        stamp
                            .execution()
                            .transport_digest()
                            .map_err(authority_error)?,
                        body,
                        Some(stamp),
                    ))
                }
                ScopeAuthorityOperation::Close { .. } => {
                    let view = store
                        .execute(&identity, request)
                        .await
                        .map_err(authority_error)?;
                    Ok((
                        ResultStatus::Committed,
                        [0; 32],
                        committed_body(&view)?,
                        None,
                    ))
                }
            },
            NativeCall::Current => {
                let view = store.current(&identity).await.map_err(authority_error)?;
                Ok((
                    ResultStatus::CurrentView,
                    [0; 32],
                    view.encode_canonical().map_err(authority_error)?,
                    None,
                ))
            }
            NativeCall::Outcome { id, digest } => match store
                .outcome(&identity, *id, *digest)
                .await
                .map_err(authority_error)?
            {
                ScopeAuthorityOutcome::Committed(view) => Ok((
                    ResultStatus::Committed,
                    [0; 32],
                    committed_body(&view)?,
                    None,
                )),
                ScopeAuthorityOutcome::ReceiptUnavailable(_) => {
                    Err(ScopeRpcError::ReceiptUnavailable)
                }
            },
            NativeCall::Scan(request) => self.dispatch_scan(request, admission, views).await,
            NativeCall::Batch(_)
            | NativeCall::BatchCancel(_)
            | NativeCall::BatchReopen(_)
            | NativeCall::BatchLookup(_) => self.dispatch_batch(call, admission).await,
        }
    }

    async fn dispatch_batch(
        &self,
        call: &NativeCall,
        admission: Arc<VerifiedScopeCall>,
    ) -> Result<(ResultStatus, [u8; 32], Vec<u8>, Option<ScopeAuthorityStamp>), ScopeRpcError> {
        let namespace = match call {
            NativeCall::Batch(request) => request.stamp().namespace(),
            NativeCall::BatchCancel(target) | NativeCall::BatchLookup(target) => {
                target.stamp().namespace()
            }
            NativeCall::BatchReopen(stamp) => stamp.namespace(),
            _ => return Err(ScopeRpcError::Invalid),
        };
        let identity = admission.context.identity()?;
        let result: Result<_, ScopeBatchError> = async {
            let store = ScopeBatchStore::new(
                self.config.store.clone(),
                namespace.clone(),
                admission.clone(),
            )?;
            let class = work_class(admission.dispatch_class());
            let (status, own, body) = match call {
                NativeCall::Batch(request) => {
                    let outcome = store.execute_classified(&identity, request, class).await?;
                    (
                        ResultStatus::Committed,
                        request.stamp().execution().transport_digest()?,
                        outcome.encode_canonical()?,
                    )
                }
                NativeCall::BatchCancel(target) => {
                    let receipt = store.cancel_classified(&identity, target, class).await?;
                    (
                        ResultStatus::Committed,
                        target.stamp().execution().transport_digest()?,
                        receipt.encode_canonical()?,
                    )
                }
                NativeCall::BatchReopen(_) => (
                    ResultStatus::CurrentView,
                    [0; 32],
                    store.reopen(&identity).await?.encode_canonical()?,
                ),
                NativeCall::BatchLookup(target) => (
                    ResultStatus::CurrentView,
                    [0; 32],
                    store.lookup(&identity, target).await?.encode_canonical()?,
                ),
                _ => return Err(ScopeBatchError::InvalidRequest),
            };
            Ok((status, own, body, None))
        }
        .await;
        match result {
            Ok(value) => Ok(value),
            Err(error) => Ok((
                ResultStatus::BatchError,
                [0; 32],
                error
                    .encode_canonical()
                    .map_err(|_| ScopeRpcError::OutcomeUnknown)?,
                None,
            )),
        }
    }
}
#[cfg(test)]
pub(crate) struct ReplyPause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[cfg(test)]
impl ReplyPause {
    pub(crate) async fn entered(&self) {
        self.entered.notified().await;
    }
    pub(crate) fn release(&self) {
        self.release.notify_one();
    }
}
fn committed_body(view: &ScopeAuthorityView) -> Result<Vec<u8>, ScopeRpcError> {
    let mut body = view
        .stamp()
        .ok_or(ScopeRpcError::Invalid)?
        .encode_canonical()
        .map_err(authority_error)?;
    body.push(u8::from(view.is_active()));
    Ok(body)
}
fn obsolete_request(
    view: &ScopeAuthorityView,
    request: &ScopeAuthorityRequest,
) -> Option<ScopeRpcError> {
    let named = match request.operation() {
        ScopeAuthorityOperation::Close { current, .. } => Some(current),
        ScopeAuthorityOperation::SucceedClosed { predecessor, .. } => Some(predecessor),
        _ => None,
    };
    if named.is_some_and(|stamp| stamp.incarnation().get() <= view.retired_through()) {
        return Some(ScopeRpcError::Retired);
    }
    let execution = request.operation().execution();
    if view
        .stamp()
        .is_some_and(|stamp| stamp.execution() == execution)
    {
        if !view.is_active() {
            return Some(ScopeRpcError::Closed);
        }
        // The exact receipt was checked first. A different admission request
        // from this still-current boot cannot claim that the boot was replaced.
        if matches!(
            request.operation(),
            ScopeAuthorityOperation::AdmitInitial { .. }
                | ScopeAuthorityOperation::SucceedClosed { .. }
        ) {
            return Some(ScopeRpcError::Invalid);
        }
    }
    match request.operation() {
        ScopeAuthorityOperation::Close { current, .. } if view.stamp() != Some(current) => {
            Some(ScopeRpcError::Superseded)
        }
        ScopeAuthorityOperation::AdmitInitial { .. }
        | ScopeAuthorityOperation::SucceedClosed { .. }
            if execution.admission_generation() <= view.admission_generation_floor() =>
        {
            Some(ScopeRpcError::Superseded)
        }
        _ => None,
    }
}
#[derive(Clone)]
struct Context {
    route: Arc<RoutedCall>,
    scope: ScopeId,
    authentication: ScopeTlsAuthentication,
    clock: Arc<dyn super::AuthenticationClock>,
}
impl Context {
    fn check(&self) -> Result<(), ScopeAuthorityError> {
        self.route
            .revalidate()
            .map_err(|_| ScopeAuthorityError::Unauthorized)?;
        self.authentication
            .revalidate(
                self.clock
                    .interval()
                    .map_err(|_| ScopeAuthorityError::Unavailable)?,
            )
            .map_err(|_| ScopeAuthorityError::Unavailable)
    }
    fn identity(&self) -> Result<SessionConsumerIdentity, ScopeRpcError> {
        SessionConsumerIdentity::new(self.route.principal.as_str())
            .map_err(|_| ScopeRpcError::Unauthorized)
    }
    fn role(&self) -> ScopeAuthorityRole {
        match self.route.role {
            ScopeRole::Worker => ScopeAuthorityRole::Worker,
            ScopeRole::Controller => ScopeAuthorityRole::ScopeController,
            ScopeRole::Observer => ScopeAuthorityRole::Observer,
        }
    }
}
struct Routing(Context);
#[async_trait::async_trait]
impl ScopeAuthorityAdmission for Routing {
    async fn authorize(
        &self,
        identity: &SessionConsumerIdentity,
        scope: &ScopeId,
        _: Option<&ScopeExecution>,
        action: ScopeAuthorityAction,
        _: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        self.0.check()?;
        if scope != &self.0.scope
            || identity.as_str() != self.0.route.principal.as_str()
            || !matches!(
                action,
                ScopeAuthorityAction::Read | ScopeAuthorityAction::Recover
            )
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        Ok(self.0.role())
    }
}
struct VerifiedScopeCall {
    context: Context,
    execution: Option<ScopeExecution>,
    ticket: Option<BootAuthorityRecord>,
    boots: Arc<dyn ScopeBootAuthority>,
    closures: Arc<dyn ScopeClosureSource>,
    digest: [u8; 32],
    current: bool,
    scan_failure: Option<opc_session_store::scope_scan::ScopeScanError>,
}
impl VerifiedScopeCall {
    fn check(&self) -> Result<(), ScopeAuthorityError> {
        self.context.check()
    }
    fn dispatch_class(&self) -> Class {
        // Key possession by a known boot does not prove that it still owns the
        // scope. Its resolution reads remain available without spending the
        // established worker's Emergency running credits.
        if self.context.route.class == Class::Emergency && !self.current {
            Class::EmergencyClassification
        } else {
            self.context.route.class
        }
    }
}
#[async_trait::async_trait]
impl ScopeAuthorityAdmission for VerifiedScopeCall {
    async fn authorize(
        &self,
        identity: &SessionConsumerIdentity,
        scope: &ScopeId,
        execution: Option<&ScopeExecution>,
        action: ScopeAuthorityAction,
        digest: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError> {
        self.check()?;
        if scope != &self.context.scope
            || identity.as_str() != self.context.route.principal.as_str()
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        if action == ScopeAuthorityAction::Read {
            if self.context.route.method.is_scan()
                && (!self.current
                    || self.context.route.role != ScopeRole::Worker
                    || execution != self.execution.as_ref())
            {
                return Err(ScopeAuthorityError::Unauthorized);
            }
            return Ok(self.context.role());
        }
        if action == ScopeAuthorityAction::Recover && self.context.route.method == Method::Outcome {
            return Ok(self.context.role());
        }
        if self.context.route.role != ScopeRole::Worker
            || execution != self.execution.as_ref()
            || digest != Some(self.digest)
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        let allowed = matches!(
            (action, self.context.route.method),
            (
                ScopeAuthorityAction::Recover,
                Method::AdmitInitial | Method::SucceedClosed | Method::Close
            ) | (ScopeAuthorityAction::AdmitInitial, Method::AdmitInitial)
                | (ScopeAuthorityAction::SucceedClosed, Method::SucceedClosed)
                | (ScopeAuthorityAction::Close, Method::Close)
                | (
                    ScopeAuthorityAction::Mutate,
                    Method::ApplyBatch | Method::BatchCancel
                )
        );
        if !allowed
            || (action == ScopeAuthorityAction::Mutate
                && self.context.route.class == Class::Emergency
                && !self.current)
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        if matches!(
            action,
            ScopeAuthorityAction::AdmitInitial | ScopeAuthorityAction::SucceedClosed
        ) {
            let expected = self
                .ticket
                .as_ref()
                .ok_or(ScopeAuthorityError::Unauthorized)?;
            let current = self
                .boots
                .read_current(&self.context.route.scope)
                .await
                .map_err(|_| ScopeAuthorityError::Unavailable)?;
            if current != *expected {
                return Err(ScopeAuthorityError::Unauthorized);
            }
        }
        self.check()?;
        Ok(ScopeAuthorityRole::Worker)
    }
    async fn verify_closure(
        &self,
        identity: &SessionConsumerIdentity,
        predecessor: &ScopeAuthorityStamp,
        evidence: &ScopeClosureEvidence,
        digest: [u8; 32],
    ) -> Result<(), ScopeAuthorityError> {
        self.check()?;
        if identity.as_str() != self.context.route.principal.as_str()
            || predecessor.scope() != &self.context.scope
            || digest != self.digest
        {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        super::evidence::verify_closure(&*self.closures, predecessor, evidence)
            .await
            .map_err(|_| ScopeAuthorityError::ClosureRequired)?;
        self.check()
    }
}
pub(super) enum NativeCall {
    Authority(Box<ScopeAuthorityRequest>),
    Current,
    Outcome { id: [u8; 16], digest: [u8; 32] },
    Batch(Box<ScopeBatchRequest>),
    BatchCancel(Box<ScopeBatchAttempt>),
    BatchReopen(Box<ScopeAuthorityStamp>),
    BatchLookup(Box<ScopeBatchAttempt>),
    Scan(Box<opc_session_store::scope_scan::ScopeScanRequest>),
}
impl NativeCall {
    pub(super) fn execution(&self) -> Option<&ScopeExecution> {
        match self {
            Self::Authority(request) => Some(request.operation().execution()),
            Self::Batch(request) => Some(request.stamp().execution()),
            Self::BatchCancel(attempt) => Some(attempt.stamp().execution()),
            Self::Scan(request) => Some(request.stamp().execution()),
            _ => None,
        }
    }
    pub(super) fn decode(
        header: &Header,
        bytes: &[u8],
        scope: &ScopeId,
    ) -> Result<Self, ScopeRpcError> {
        match header.method {
            method if method.is_scan() => {
                let request =
                    opc_session_store::scope_scan::ScopeScanRequest::decode_canonical(bytes)
                        .map_err(|_| ScopeRpcError::Invalid)?;
                if request.stamp().scope() != scope
                    || Method::for_scan(&request) != method
                    || transport_request_digest(method, &header.request_id, bytes)
                        .map_err(|_| ScopeRpcError::Invalid)?
                        != header.digest
                {
                    return Err(ScopeRpcError::Invalid);
                }
                Ok(Self::Scan(Box::new(request)))
            }
            Method::ApplyBatch => {
                let request = ScopeBatchRequest::decode_canonical(bytes)
                    .map_err(|_| ScopeRpcError::Invalid)?;
                if request.stamp().scope() != scope
                    || request.request_id() != &header.request_id
                    || request.digest().map_err(|_| ScopeRpcError::Invalid)? != header.digest
                {
                    return Err(ScopeRpcError::Invalid);
                }
                Ok(Self::Batch(Box::new(request)))
            }
            Method::BatchCancel => {
                let attempt = ScopeBatchAttempt::decode_canonical(bytes)
                    .map_err(|_| ScopeRpcError::Invalid)?;
                if attempt.stamp().scope() != scope
                    || attempt.request_id() != &header.request_id
                    || attempt
                        .cancellation_digest()
                        .map_err(|_| ScopeRpcError::Invalid)?
                        != header.digest
                {
                    return Err(ScopeRpcError::Invalid);
                }
                Ok(Self::BatchCancel(Box::new(attempt)))
            }
            Method::BatchReopen | Method::BatchLookup => {
                if transport_request_digest(header.method, &header.request_id, bytes)
                    .map_err(|_| ScopeRpcError::Invalid)?
                    != header.digest
                {
                    return Err(ScopeRpcError::Invalid);
                }
                if header.method == Method::BatchReopen {
                    let stamp =
                        ScopeAuthorityStamp::decode_canonical(bytes).map_err(authority_error)?;
                    if stamp.scope() != scope {
                        return Err(ScopeRpcError::Invalid);
                    }
                    Ok(Self::BatchReopen(Box::new(stamp)))
                } else {
                    let attempt = ScopeBatchAttempt::decode_canonical(bytes)
                        .map_err(|_| ScopeRpcError::Invalid)?;
                    if attempt.stamp().scope() != scope {
                        return Err(ScopeRpcError::Invalid);
                    }
                    Ok(Self::BatchLookup(Box::new(attempt)))
                }
            }
            Method::AdmitInitial | Method::SucceedClosed | Method::Close => {
                let value =
                    ScopeAuthorityRequest::decode_canonical(bytes).map_err(authority_error)?;
                if value.scope() != scope
                    || value.request_id() != &header.request_id
                    || value.digest().map_err(authority_error)? != header.digest
                {
                    return Err(ScopeRpcError::Invalid);
                }
                let method = match value.operation() {
                    ScopeAuthorityOperation::AdmitInitial { .. } => Method::AdmitInitial,
                    ScopeAuthorityOperation::SucceedClosed { .. } => Method::SucceedClosed,
                    ScopeAuthorityOperation::Close { .. } => Method::Close,
                };
                if method != header.method {
                    return Err(ScopeRpcError::Invalid);
                }
                Ok(Self::Authority(Box::new(value)))
            }
            Method::Current | Method::Outcome => {
                if transport_request_digest(header.method, &header.request_id, bytes)
                    .map_err(|_| ScopeRpcError::Invalid)?
                    != header.digest
                {
                    return Err(ScopeRpcError::Invalid);
                }
                let encoded = scope.encode_canonical().map_err(authority_error)?;
                if header.method == Method::Current {
                    if bytes != encoded {
                        return Err(ScopeRpcError::Invalid);
                    }
                    Ok(Self::Current)
                } else {
                    if bytes.len() != encoded.len() + 48 || !bytes.starts_with(&encoded) {
                        return Err(ScopeRpcError::Invalid);
                    }
                    let mut tail = Reader::new(&bytes[encoded.len()..]);
                    let id = tail.array().map_err(|_| ScopeRpcError::Invalid)?;
                    let digest = tail.array().map_err(|_| ScopeRpcError::Invalid)?;
                    if id == [0; 16] || digest == [0; 32] {
                        return Err(ScopeRpcError::Invalid);
                    }
                    Ok(Self::Outcome { id, digest })
                }
            }
            _ => Err(ScopeRpcError::Invalid),
        }
    }
}
pub(super) fn work_class(class: Class) -> ScopeWorkClass {
    match class {
        Class::SafetyControl => ScopeWorkClass::SafetyControl,
        Class::Emergency => ScopeWorkClass::Emergency,
        Class::EmergencyClassification => ScopeWorkClass::EmergencyClassification,
        Class::Normal => ScopeWorkClass::Normal,
        Class::Maintenance => ScopeWorkClass::Maintenance,
    }
}
pub(super) fn authority_error(error: ScopeAuthorityError) -> ScopeRpcError {
    match error {
        ScopeAuthorityError::Unauthorized => ScopeRpcError::Unauthorized,
        ScopeAuthorityError::Retired => ScopeRpcError::Retired,
        ScopeAuthorityError::Superseded | ScopeAuthorityError::StaleAuthority => {
            ScopeRpcError::Superseded
        }
        ScopeAuthorityError::OutcomeUnknown => ScopeRpcError::OutcomeUnknown,
        ScopeAuthorityError::Unavailable => ScopeRpcError::Retry,
        ScopeAuthorityError::ProfileNotActivated
        | ScopeAuthorityError::FreshInstallationRequired => ScopeRpcError::ProfileUnavailable,
        _ => ScopeRpcError::Invalid,
    }
}
fn evidence_error(error: ScopeEvidenceError) -> ScopeRpcError {
    match error {
        ScopeEvidenceError::Unavailable => ScopeRpcError::Retry,
        _ => ScopeRpcError::Unauthorized,
    }
}
#[derive(Clone, Copy)]
enum RefusalReply {
    AwaitNonce,
    Allowed([u8; 32]),
    Silent,
}

async fn refuse_before_dispatch(
    connection: &mut ScopeTlsConnection<TcpStream>,
    header: &Header,
    reply: RefusalReply,
    error: ScopeRpcError,
) -> Result<(), ScopeRpcError> {
    let (status, body) = error_status(error);
    if matches!(reply, RefusalReply::Silent) || status != ResultStatus::ProvenNoEffect {
        return Ok(());
    }
    timeout(Duration::from_secs(5), async {
        let nonce = match reply {
            RefusalReply::AwaitNonce => {
                // Only the fixed correlation nonce is read on a role/policy
                // refusal. Never allocate or read the forbidden command body.
                if header.payload_len < 36 {
                    return Err(ScopeRpcError::Invalid);
                }
                let mut nonce = [0; 32];
                connection
                    .read_exact(&mut nonce)
                    .await
                    .map_err(|_| ScopeRpcError::Retry)?;
                nonce
            }
            RefusalReply::Allowed(nonce) => nonce,
            RefusalReply::Silent => return Ok(()),
        };
        let payload = ResultPayload::new(nonce, status, [0; 32], body)
            .and_then(|payload| payload.encode())
            .map_err(|_| ScopeRpcError::Invalid)?;
        let response = header
            .response(FrameKind::Result, payload.len())
            .and_then(|header| header.encode())
            .map_err(|_| ScopeRpcError::Invalid)?;
        connection
            .write_all(&response)
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        connection
            .write_all(&payload)
            .await
            .map_err(|_| ScopeRpcError::Retry)?;
        connection.flush().await.map_err(|_| ScopeRpcError::Retry)
    })
    .await
    .map_err(|_| ScopeRpcError::Retry)?
}

fn error_status(error: ScopeRpcError) -> (ResultStatus, Vec<u8>) {
    match error {
        ScopeRpcError::OutcomeUnknown => (ResultStatus::OutcomeUnknown, Vec::new()),
        ScopeRpcError::Superseded => (ResultStatus::Obsolete, vec![1]),
        ScopeRpcError::Closed => (ResultStatus::Obsolete, vec![2]),
        ScopeRpcError::Retired => (ResultStatus::Obsolete, vec![3]),
        ScopeRpcError::ReceiptUnavailable => (ResultStatus::Obsolete, vec![4]),
        error => (
            ResultStatus::ProvenNoEffect,
            vec![
                0,
                match error {
                    ScopeRpcError::Unauthorized => 2,
                    ScopeRpcError::Retry => 3,
                    ScopeRpcError::AuthTimeUnavailable => 4,
                    ScopeRpcError::ProfileUnavailable => 5,
                    _ => 1,
                },
            ],
        ),
    }
}
/// Supervised class listeners; drop requests shutdown, explicit shutdown joins.
pub struct ScopeServerHandle {
    addresses: [SocketAddr; 5],
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    views: Arc<ScanViews>,
}
impl ScopeServerHandle {
    /// Separate SC/E/classification/Normal/Maintenance bound addresses.
    pub const fn addresses(&self) -> [SocketAddr; 5] {
        self.addresses
    }
    /// Stop accepting and join every bounded connection supervisor.
    pub async fn shutdown(mut self) {
        self.views.begin_close();
        let _ = self.stop.send(true);
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}
impl Drop for ScopeServerHandle {
    fn drop(&mut self) {
        self.views.begin_close();
        let _ = self.stop.send(true);
    }
}
