//! Local client adapter, using the same authenticated facade as the wire server.

use super::activity::{ViewInvalidation, ViewState};
use super::*;
use crate::{
    scope_authority::{CommittedScopeAuthority, ScopeAuthorityView},
    SessionConsensusNodeId, SessionConsumerIdentity,
};
use async_trait::async_trait;
use std::{sync::Arc, time::Instant};

/// Client transport fixed to one local serving store and one own-boot grant.
/// A routing preference cannot move an existing view to another node.
pub struct ScopeScanLocalTransport {
    store: ScopeScanStore,
    authenticated: SessionConsumerIdentity,
    authority: CommittedScopeAuthority,
}
impl ScopeScanStore {
    /// Create a streaming restore client bound to this node and own boot.
    /// Authorization and positive handover are rechecked when opening.
    pub fn client(
        &self,
        authenticated: SessionConsumerIdentity,
        authority: CommittedScopeAuthority,
    ) -> ScopeScanClient<ScopeScanLocalTransport> {
        ScopeScanClient::new(ScopeScanLocalTransport {
            store: self.clone(),
            authenticated,
            authority,
        })
    }
}
impl ScopeScanClientView for ScopeRestoreView {
    fn cut(&self) -> &ScopeCut {
        self.cut()
    }
    fn authority(&self) -> &ScopeAuthorityView {
        self.authority()
    }
    fn checkpoint(&self) -> &ScopeScanCheckpoint {
        self.checkpoint()
    }
    fn initial_cursor(&self) -> &ScopeScanCursor {
        self.initial_cursor()
    }
}
impl ScopeRestoreView {
    /// Observe the end of a local view without extending its idle retention.
    /// A live view still needs all normal per-operation authority checks.
    pub fn retry_cause(&self) -> Option<ScopeScanRetryCause> {
        match self.registered.runtime.expire_idle(Instant::now()) {
            ViewState::Retained => None,
            ViewState::IdleExpired => Some(ScopeScanRetryCause::IdleExpired),
            ViewState::Invalidated(reason) => Some(match reason {
                ViewInvalidation::BackendRestarted => ScopeScanRetryCause::BackendRestarted,
                ViewInvalidation::SnapshotInstalled => ScopeScanRetryCause::SnapshotInstalled,
                ViewInvalidation::ConfigurationChanged => ScopeScanRetryCause::ConfigurationChanged,
                ViewInvalidation::Closed => ScopeScanRetryCause::ViewEnded,
            }),
        }
    }
}
pub(crate) fn request_failure(
    error: ScopeScanError,
    view: Option<&ScopeRestoreView>,
) -> ScopeScanRequestFailure {
    match error {
        ScopeScanError::Unavailable => {
            ScopeScanRequestFailure::Retryable(ScopeScanRetryCause::Unavailable)
        }
        ScopeScanError::RestartRequired => ScopeScanRequestFailure::Retryable(
            view.and_then(ScopeRestoreView::retry_cause)
                .unwrap_or(ScopeScanRetryCause::ViewEnded),
        ),
        error => ScopeScanRequestFailure::Final(error),
    }
}
#[async_trait]
impl ScopeScanTransport for ScopeScanLocalTransport {
    type View = ScopeRestoreView;
    async fn open(
        &self,
        _preferred: Option<SessionConsensusNodeId>,
        limits: ScopeScanPageLimits,
    ) -> Result<Self::View, ScopeScanRequestFailure> {
        self.store
            .open_restore_with_limits(&self.authenticated, &self.authority, limits)
            .await
            .map_err(|error| request_failure(error, None))
    }
    async fn page(
        &self,
        view: &Self::View,
        cursor: &ScopeScanCursor,
    ) -> Result<Arc<ScopeScanReply>, ScopeScanRequestFailure> {
        self.store
            .page(&self.authenticated, view, cursor)
            .await
            .map_err(|error| request_failure(error, Some(view)))
    }
    async fn close(&self, view: Self::View) {
        view.close().await;
    }
}
