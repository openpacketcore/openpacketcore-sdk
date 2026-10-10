//! Process-owned authenticated observations of a positively handed-over cohort.
use super::*;
use opc_session_store::scope_scan::*;

/// Scan transport permanently bound to one worker, succession and serving endpoint.
/// Opens prefer this endpoint on every retry; existing captures never move nodes.
#[derive(Clone)]
pub struct ScopeScanPort {
    client: ScopeClient,
    authority: CommittedScopeAuthority,
    succession: ScopeAuthorityRequest,
}

/// Read-only remote capture, kept alive only by active paging at its serving node.
/// Dropping it leaves only the server's bounded idle retention.
pub struct ScopeScanRemoteView {
    owner: std::sync::Weak<Inner>,
    reply: ScopeScanOpenReply,
    token: ScopeScanViewToken,
}
impl std::fmt::Debug for ScopeScanRemoteView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopeScanRemoteView(<redacted>)")
    }
}

impl ScopeClient {
    /// Bind a restore port to the original request that issued this successor.
    /// The serving store rechecks the exact committed request in the captured cut.
    pub fn scans(
        &self,
        authority: &CommittedScopeAuthority,
        succession: &PendingScopeAuthority,
    ) -> Result<ScopeScanPort, ScopeScanError> {
        if !Arc::ptr_eq(&self.0, &succession.0.client)
            || authority.stamp().scope() != &self.0.config.scope
            || authority.check_execution(&self.0.execution).is_err()
        {
            return Err(ScopeScanError::Unauthorized);
        }
        ScopeScanOpenRequest::new(
            authority,
            succession.request(),
            ScopeScanPageLimits::default(),
        )?;
        Ok(ScopeScanPort {
            client: self.clone(),
            authority: authority.clone(),
            succession: succession.request().clone(),
        })
    }
}

impl ScopeScanClientView for ScopeScanRemoteView {
    fn cut(&self) -> &ScopeCut {
        self.reply.cut()
    }
    fn authority(&self) -> &ScopeAuthorityView {
        self.reply.authority()
    }
    fn checkpoint(&self) -> &ScopeScanCheckpoint {
        self.reply.checkpoint()
    }
    fn initial_cursor(&self) -> &ScopeScanCursor {
        self.reply.initial_cursor()
    }
}

impl ScopeScanPort {
    fn token(
        &self,
        view: &ScopeScanRemoteView,
    ) -> Result<ScopeScanViewToken, ScopeScanRequestFailure> {
        if !view.owner.ptr_eq(&Arc::downgrade(&self.client.0))
            || view.authority().stamp() != Some(self.authority.stamp())
            || view.cut().namespace() != self.authority.stamp().namespace()
        {
            return Err(ScopeScanRequestFailure::Final(ScopeScanError::Unauthorized));
        }
        Ok(view.token.clone())
    }

    /// Inspect one item at the same retained cut with the Normal budget.
    pub async fn lookup(
        &self,
        view: &ScopeScanRemoteView,
        key: ScopeScanLookupKey,
    ) -> Result<ScopeScanLookup, ScopeScanRequestFailure> {
        self.point(view, key, false).await
    }
    /// Inspect one item using the independent classification budget.
    pub async fn classify(
        &self,
        view: &ScopeScanRemoteView,
        key: ScopeScanLookupKey,
    ) -> Result<ScopeScanLookup, ScopeScanRequestFailure> {
        self.point(view, key, true).await
    }
    async fn point(
        &self,
        view: &ScopeScanRemoteView,
        key: ScopeScanLookupKey,
        classification: bool,
    ) -> Result<ScopeScanLookup, ScopeScanRequestFailure> {
        let token = self.token(view)?;
        let request = if classification {
            ScopeScanRequest::Classify { view: token, key }
        } else {
            ScopeScanRequest::Lookup { view: token, key }
        };
        match self.request(request).await? {
            ScopeScanResponse::Lookup(lookup)
                if lookup.cut() == view.cut() && lookup.matches_key(key) =>
            {
                Ok(lookup)
            }
            _ => Err(unavailable()),
        }
    }

    async fn request(
        &self,
        request: ScopeScanRequest,
    ) -> Result<ScopeScanResponse, ScopeScanRequestFailure> {
        self.client
            .0
            .config
            .process
            .gate
            .observe(async {
                // The restore owns the deadline. Keep resident admission and the
                // serving node's queue position until that deadline or cancellation.
                let method = Method::for_scan(&request);
                let class = if method == Method::ScanClassify {
                    Class::EmergencyClassification
                } else {
                    Class::Normal
                };
                // The remote wait owns bounded resident memory only. The serving
                // store owns execution credit inside its actual read workers.
                let _resident = self
                    .client
                    .0
                    .config
                    .scheduler
                    .reserve(
                        opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                            &self.client.0.config.scope,
                        ),
                        work_class(class),
                    )
                    .await
                    .map_err(|_| unavailable())?;
                let canonical = request.encode_canonical().map_err(|_| unavailable())?;
                let id = super::super::boot::random_nonzero().map_err(|_| unavailable())?;
                let digest =
                    transport_request_digest(method, &id, &canonical).map_err(|_| unavailable())?;
                let payload = self
                    .client
                    .roundtrip(
                        method,
                        class,
                        id,
                        digest,
                        &canonical,
                        None,
                        opc_session_store::DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                    )
                    .await
                    .map_err(rpc_failure)?
                    .payload;
                if payload.status != ResultStatus::ScanObservation
                    || payload.own_execution != [0; 32]
                {
                    return Err(payload_error(&payload)
                        .map(rpc_failure)
                        .unwrap_or_else(|_| unavailable()));
                }
                match ScopeScanResponse::decode_canonical(&payload.body)
                    .map_err(|_| unavailable())?
                {
                    ScopeScanResponse::Failure(failure) => Err(failure),
                    response => Ok(response),
                }
            })
            .await
            .map_err(|_| ScopeScanRequestFailure::Final(ScopeScanError::StaleAuthority))?
    }
}

#[async_trait::async_trait]
impl ScopeScanTransport for ScopeScanPort {
    type View = ScopeScanRemoteView;
    async fn open(
        &self,
        _preferred: Option<opc_session_store::SessionConsensusNodeId>,
        limits: ScopeScanPageLimits,
    ) -> Result<Self::View, ScopeScanRequestFailure> {
        let limits = limits
            .for_transport(MAX_SCOPE_SCAN_REPLY_BYTES)
            .map_err(ScopeScanRequestFailure::Final)?;
        let claim = ScopeScanOpenRequest::new(&self.authority, &self.succession, limits)
            .map_err(ScopeScanRequestFailure::Final)?;
        match self
            .request(ScopeScanRequest::Open(Box::new(claim)))
            .await?
        {
            ScopeScanResponse::Open(reply)
                if reply.authority().stamp() == Some(self.authority.stamp())
                    && reply.cut().namespace() == self.authority.stamp().namespace() =>
            {
                let token = ScopeScanViewToken::new(self.authority.stamp(), reply.cut())
                    .map_err(ScopeScanRequestFailure::Final)?;
                Ok(ScopeScanRemoteView {
                    owner: Arc::downgrade(&self.client.0),
                    reply,
                    token,
                })
            }
            _ => Err(unavailable()),
        }
    }
    async fn page(
        &self,
        view: &Self::View,
        cursor: &ScopeScanCursor,
    ) -> Result<Arc<ScopeScanReply>, ScopeScanRequestFailure> {
        let token = self.token(view)?;
        match self
            .request(ScopeScanRequest::Page {
                view: token,
                cursor: cursor.clone(),
            })
            .await?
        {
            ScopeScanResponse::Page(reply) if reply.cut() == view.cut() => Ok(reply),
            _ => Err(unavailable()),
        }
    }
    async fn close(&self, view: Self::View) {
        if let Ok(token) = self.token(&view) {
            let _ = self.request(ScopeScanRequest::Close(token)).await;
        }
    }
}

fn unavailable() -> ScopeScanRequestFailure {
    ScopeScanRequestFailure::Retryable(ScopeScanRetryCause::Unavailable)
}
fn rpc_failure(error: ScopeRpcError) -> ScopeScanRequestFailure {
    match error {
        ScopeRpcError::Closed | ScopeRpcError::Superseded => {
            ScopeScanRequestFailure::Final(ScopeScanError::StaleAuthority)
        }
        ScopeRpcError::Retired => ScopeScanRequestFailure::Final(ScopeScanError::Retired),
        ScopeRpcError::Unauthorized => ScopeScanRequestFailure::Final(ScopeScanError::Unauthorized),
        ScopeRpcError::ProfileUnavailable => {
            ScopeScanRequestFailure::Final(ScopeScanError::FreshInstallationRequired)
        }
        _ => unavailable(),
    }
}
