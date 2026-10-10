//! Authenticated restore of an exact, positively closed cohort.

use super::{
    activity::{ViewInvalidation, ViewState},
    backend::{CapturedScope, ScopeRead, ScopeReadResult},
    registry::RegisteredView,
};
use crate::scope_authority::{
    CommittedScopeAuthority, ScopeAuthorityAction, ScopeAuthorityAdmission, ScopeAuthorityRole,
    ScopeAuthorityStamp, ScopeAuthorityView, ScopeNamespace,
};
use crate::{
    ConsensusSessionStore, SessionConsumerIdentity, SessionPersistenceMode,
    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};
use std::fmt;
use std::sync::Arc;

/// An operation-level outcome; item failures are returned inside the inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeScanError {
    /// The channel, boot or namespace is not authorized for this view.
    #[error("scope restore is unauthorized")]
    Unauthorized,
    /// Initial admission carries no positively closed predecessor.
    #[error("scope restore requires a committed closed predecessor")]
    HandoverRequired,
    /// The committed execution has been closed or superseded.
    #[error("scope restore authority is stale")]
    StaleAuthority,
    /// The namespace has been permanently retired.
    #[error("scope restore incarnation is retired")]
    Retired,
    /// The backend or its quorum cannot presently admit an open.
    #[error("scope restore is unavailable")]
    Unavailable,
    /// The retained view has ended; the client must discard its staged cut.
    #[error("scope restore requires a new view")]
    RestartRequired,
    /// The requested per-view limits are outside the fixed SDK bounds.
    #[error("scope restore page limits are invalid")]
    InvalidPageLimits,
    /// The continuation is malformed, forged, acknowledged or bound elsewhere.
    #[error("scope restore continuation is invalid")]
    InvalidCursor,
    /// A required header is absent or corrupt; no empty inventory is inferred.
    #[error("scope restore header is invalid: {0:?}")]
    ScopeFault(ScopeScanHeaderFault),
    /// A previous incompatible stored profile cannot be read by this build.
    #[error("scope restore requires a fresh installation")]
    FreshInstallationRequired,
    /// Restoring a handed-over cohort requires strictly durable consensus.
    #[error("scope restore requires durable consensus")]
    DurableConsensusRequired,
    /// This view cannot fit the configured retention capacity. Waiting or
    /// reopening cannot resolve this permanent admission refusal.
    #[error("scope restore exceeds configured retention capacity")]
    CapacityRefused,
}

/// The scope-level header that prevents a coherent inventory from opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeScanHeaderFault {
    /// The authority row is absent or cannot be canonically decoded.
    Authority,
    /// The stable-scope batch checkpoint is absent or invalid.
    Checkpoint,
    /// The captured header belongs to another namespace.
    Namespace,
}

/// Immutable observation identity. This is not mutation or effect authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeCut {
    pub(crate) namespace: ScopeNamespace,
    pub(crate) authority_revision: u64,
    pub(crate) batch_revision: u64,
    pub(crate) applied: opc_consensus::engine::LogId<crate::SessionConsensusNodeId>,
    pub(crate) epoch: u64,
    pub(crate) capture_id: [u8; 16],
    pub(crate) serving_node: crate::SessionConsensusNodeId,
}
impl ScopeCut {
    /// Exact namespace retained by this observation.
    pub fn namespace(&self) -> &ScopeNamespace {
        &self.namespace
    }
    /// Authority revision in the retained cut.
    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }
    /// Independent stable-scope batch revision in the retained cut.
    pub fn batch_revision(&self) -> u64 {
        self.batch_revision
    }
    /// Applied consensus position that fixed this cut.
    pub fn applied_log_index(&self) -> u64 {
        self.applied.index
    }
    /// Node that owns the process-local retained resources.
    pub fn serving_node(&self) -> crate::SessionConsensusNodeId {
        self.serving_node
    }
}
impl fmt::Debug for ScopeCut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeCut(<redacted>)")
    }
}

/// Stable-scope checkpoint observed atomically with the authority and inventory.
#[derive(Clone)]
pub struct ScopeScanCheckpoint {
    pub(crate) revision: u64,
    pub(crate) birth_floor: u64,
    pub(crate) counters: [u64; crate::scope_batch::SCOPE_COUNTERS],
}
impl From<crate::scope_batch::ScopeBatchCheckpoint> for ScopeScanCheckpoint {
    fn from(checkpoint: crate::scope_batch::ScopeBatchCheckpoint) -> Self {
        Self {
            revision: checkpoint.revision,
            birth_floor: checkpoint.birth_floor,
            counters: checkpoint.counters,
        }
    }
}
impl ScopeScanCheckpoint {
    /// Exact batch revision, including canonical zero before any batch.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Retained child-birth floor, never reset by view lifecycle.
    pub fn birth_floor(&self) -> u64 {
        self.birth_floor
    }
    /// All sixteen retained counters at this cut.
    pub fn counters(&self) -> &[u64; crate::scope_batch::SCOPE_COUNTERS] {
        &self.counters
    }
}
impl fmt::Debug for ScopeScanCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanCheckpoint(<redacted>)")
    }
}

/// Local ownership of one retained view. Dropping it revokes detached work and
/// releases the cut when accepted workers drain. It is not serializable.
pub struct ScopeRestoreView {
    pub(crate) registered: RegisteredView<Option<CapturedScope>>,
    pub(crate) configuration: crate::SessionConsumerScope,
    pub(crate) cut: ScopeCut,
    pub(crate) authority: ScopeAuthorityView,
    pub(crate) checkpoint: ScopeScanCheckpoint,
    pub(crate) initial_cursor: super::ScopeScanCursor,
}
impl ScopeRestoreView {
    /// Whether the local capture is still retained. This observation does not
    /// keep it alive or replace current-authority checks on each operation.
    pub fn is_retained(&self) -> bool {
        self.registered
            .runtime
            .expire_idle(std::time::Instant::now())
            == ViewState::Retained
    }
    /// Input cursor for the first inventory page; retry it if that reply is lost.
    pub fn initial_cursor(&self) -> &super::ScopeScanCursor {
        &self.initial_cursor
    }
    /// Immutable cut bound to every item and continuation.
    pub fn cut(&self) -> &ScopeCut {
        &self.cut
    }
    /// Current successor as observed in the same retained cut.
    pub fn authority(&self) -> &ScopeAuthorityView {
        &self.authority
    }
    /// Stable-scope checkpoint from the same retained cut.
    pub fn checkpoint(&self) -> &ScopeScanCheckpoint {
        &self.checkpoint
    }
    /// Revoke and drain accepted work; repeating close is harmless.
    pub async fn close(&self) {
        self.registered
            .runtime
            .close_and_drain(ViewInvalidation::Closed)
            .await;
    }
}
impl fmt::Debug for ScopeRestoreView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeRestoreView(<redacted>)")
    }
}

/// Authenticated scope service sharing the serving node's retention limits.
#[derive(Clone)]
pub struct ScopeScanStore {
    pub(crate) store: Arc<ConsensusSessionStore>,
    pub(crate) namespace: ScopeNamespace,
    pub(crate) admission: Arc<dyn ScopeAuthorityAdmission>,
}
impl fmt::Debug for ScopeScanStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanStore(<redacted>)")
    }
}
impl ScopeScanStore {
    /// Authenticate and compare an exact worker stamp against local committed
    /// headers, using the Normal budget without opening a view or quorum read.
    pub async fn validate_current(
        &self,
        authenticated: &SessionConsumerIdentity,
        stamp: &ScopeAuthorityStamp,
    ) -> Result<(), ScopeScanError> {
        self.authorize_stamp(authenticated, stamp).await?;
        self.store
            .validate_scope_scan_current(self.namespace.clone(), stamp.clone(), false)
            .await
    }

    /// Perform the same bounded local guard using the fixed classification budget.
    pub async fn validate_classification_current(
        &self,
        authenticated: &SessionConsumerIdentity,
        stamp: &ScopeAuthorityStamp,
    ) -> Result<(), ScopeScanError> {
        self.authorize_stamp(authenticated, stamp).await?;
        self.store
            .validate_scope_scan_current(self.namespace.clone(), stamp.clone(), true)
            .await
    }

    /// Node-wide resource observations for this store's backend generation.
    pub fn metrics(&self) -> super::ScopeScanMetrics {
        self.store.scope_scan_metrics()
    }

    /// Bind a durable installation, exact namespace and trusted boot admission.
    pub fn new(
        store: Arc<ConsensusSessionStore>,
        namespace: ScopeNamespace,
        admission: Arc<dyn ScopeAuthorityAdmission>,
    ) -> Result<Self, ScopeScanError> {
        if store.persistence_mode() != SessionPersistenceMode::Durable {
            return Err(ScopeScanError::DurableConsensusRequired);
        }
        if store.scope_authority_cluster_id() != namespace.scope().store() {
            return Err(ScopeScanError::Unauthorized);
        }
        Ok(Self {
            store,
            namespace,
            admission,
        })
    }

    /// Perform a full quorum barrier and retain one coherent successor cut.
    /// Retention pressure waits fairly without an execution permit or backend
    /// capture. Dropping the opening future cancels that wait.
    pub async fn open_restore(
        &self,
        authenticated: &SessionConsumerIdentity,
        authority: &CommittedScopeAuthority,
    ) -> Result<ScopeRestoreView, ScopeScanError> {
        self.open_restore_with_limits(
            authenticated,
            authority,
            super::ScopeScanPageLimits::default(),
        )
        .await
    }

    /// Open a retained cut with fixed, validated row and payload maxima.
    pub async fn open_restore_with_limits(
        &self,
        authenticated: &SessionConsumerIdentity,
        authority: &CommittedScopeAuthority,
        limits: super::ScopeScanPageLimits,
    ) -> Result<ScopeRestoreView, ScopeScanError> {
        self.authorize_stamp(authenticated, authority.stamp())
            .await?;
        let predecessor = authority
            .closed_predecessor()
            .ok_or(ScopeScanError::HandoverRequired)?;
        if predecessor.namespace() != &self.namespace {
            return Err(ScopeScanError::Unauthorized);
        }
        self.store
            .open_scope_restore(
                self.namespace.clone(),
                authority.stamp().clone(),
                limits.0,
                None,
            )
            .await
    }

    /// Authenticate the worker and verify the original succession against the
    /// committed authority row in the captured cut. Decoded claims issue no authority.
    pub async fn open_restore_request(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &super::ScopeScanOpenRequest,
    ) -> Result<ScopeRestoreView, ScopeScanError> {
        self.authorize_stamp(authenticated, request.stamp()).await?;
        request.validate_shape()?;
        self.store
            .open_scope_restore(
                self.namespace.clone(),
                request.stamp().clone(),
                request.limits().0,
                Some(request.succession().clone()),
            )
            .await
    }

    /// Fetch or exactly replay one bounded page after checking current local authority.
    pub async fn page(
        &self,
        authenticated: &SessionConsumerIdentity,
        view: &ScopeRestoreView,
        cursor: &super::ScopeScanCursor,
    ) -> Result<Arc<super::ScopeScanReply>, ScopeScanError> {
        self.authorize_view(authenticated, view).await?;
        match self
            .store
            .read_scope_restore(view, ScopeRead::Page(cursor.clone()), false)
            .await?
        {
            ScopeReadResult::Page(reply) => Ok(reply),
            ScopeReadResult::Lookup(_) => Err(ScopeScanError::Unavailable),
        }
    }

    /// Read one child or claim at the retained cut using the Normal budget.
    pub async fn lookup(
        &self,
        authenticated: &SessionConsumerIdentity,
        view: &ScopeRestoreView,
        key: super::ScopeScanLookupKey,
    ) -> Result<super::ScopeScanLookup, ScopeScanError> {
        self.lookup_with_class(authenticated, view, key, false)
            .await
    }

    /// Classify one unknown item using the bounded Emergency classification budget.
    /// Missing and corrupt results are final at this cut and do not loop in that budget.
    pub async fn classify(
        &self,
        authenticated: &SessionConsumerIdentity,
        view: &ScopeRestoreView,
        key: super::ScopeScanLookupKey,
    ) -> Result<super::ScopeScanLookup, ScopeScanError> {
        self.lookup_with_class(authenticated, view, key, true).await
    }

    async fn lookup_with_class(
        &self,
        authenticated: &SessionConsumerIdentity,
        view: &ScopeRestoreView,
        key: super::ScopeScanLookupKey,
        classification: bool,
    ) -> Result<super::ScopeScanLookup, ScopeScanError> {
        self.authorize_view(authenticated, view).await?;
        match self
            .store
            .read_scope_restore(view, ScopeRead::Lookup(key), classification)
            .await?
        {
            ScopeReadResult::Lookup(reply) => Ok(*reply),
            ScopeReadResult::Page(_) => Err(ScopeScanError::Unavailable),
        }
    }

    async fn authorize_view(
        &self,
        authenticated: &SessionConsumerIdentity,
        view: &ScopeRestoreView,
    ) -> Result<(), ScopeScanError> {
        if view.cut.namespace() != &self.namespace {
            return Err(ScopeScanError::Unauthorized);
        }
        self.authorize_stamp(
            authenticated,
            view.authority.stamp().ok_or(ScopeScanError::Unauthorized)?,
        )
        .await
    }

    pub(crate) async fn authorize_stamp(
        &self,
        authenticated: &SessionConsumerIdentity,
        stamp: &ScopeAuthorityStamp,
    ) -> Result<(), ScopeScanError> {
        if stamp.namespace() != &self.namespace || stamp.execution().identity() != authenticated {
            return Err(ScopeScanError::Unauthorized);
        }
        let role = tokio::time::timeout(
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
            self.admission.authorize(
                authenticated,
                self.namespace.scope(),
                Some(stamp.execution()),
                ScopeAuthorityAction::Read,
                None,
            ),
        )
        .await
        .map_err(|_| ScopeScanError::Unavailable)?
        .map_err(super::headers::authority_error)?;
        if role != ScopeAuthorityRole::Worker {
            return Err(ScopeScanError::Unauthorized);
        }
        Ok(())
    }
}
