//! Protected V2 prepared fenced-transition consumer facade (#982).
//!
//! This composes the existing `/2` capability, history-state, singleton
//! transition, and status operations over an opaque exact voter roster. It
//! adds no wire operation. The SDK protection wrapper selects the active V2
//! epoch, seals once, and journals the sealed request under the caller's
//! stable [`FencedTransitionRequestId`] before any dispatch; this module owns
//! only exact-voter routing, the affine execute handle, and receipt-only
//! recovery. The physical adapter below never leaves this module.

use super::*;
use opc_session_store::fenced_transition::FencedTransitionV2Effect;
use opc_session_store::scope_scheduler::ScopeWorkClass;
use opc_session_store::{
    FencedTransitionV2Capability, FencedTransitionV2HistoryEpoch, FencedTransitionV2HistoryState,
    FencedTransitionV2JournalScope, FencedTransitionV2RecoveryJournal, FencedTransitionV2Request,
    FencedTransitionV2Status, PreparedFencedTransitionV2, PreparedFencedTransitionV2Lookup,
    ProtectedFencedTransitionV2Backend, SessionConsumerV2FencedTransitionStatus,
    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES, FENCED_TRANSITION_V2_RECOVERY_RECLAIM_BATCH_MAX,
};

const PREPARED_FENCED_V2_DEADLINE: &str = "prepared fenced transition V2 deadline elapsed";
const PREPARED_FENCED_V2_RECEIPT_UNAVAILABLE: &str =
    "prepared fenced transition V2 receipt unavailable";
const PREPARED_FENCED_V2_HISTORY_UNAVAILABLE: &str =
    "prepared fenced transition V2 history state unavailable";
const PREPARED_FENCED_V2_RECLAIM_LIMIT_INVALID: &str =
    "prepared_fenced_transition_v2_reclaim_limit_invalid";

fn prepared_fenced_v2_deadline() -> StoreError {
    StoreError::BackendUnavailable(PREPARED_FENCED_V2_DEADLINE.into())
}

fn default_fenced_v2_operation_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now()
        .checked_add(DEFAULT_CONSUMER_OPERATION_TIMEOUT)
        .unwrap_or_else(tokio::time::Instant::now)
}

/// Check the absolute authority before polling queued journal work. Tokio's
/// timer rounds wakeups to a millisecond and polls the inner future first;
/// neither may admit another journal step when this caller is already expired.
async fn journal_before_deadline<F: std::future::Future>(
    deadline: tokio::time::Instant,
    future: F,
) -> Result<F::Output, ()> {
    let wait = tokio::time::timeout_at(deadline, future);
    tokio::pin!(wait);
    std::future::poll_fn(|context| {
        if tokio::time::Instant::now() >= deadline {
            std::task::Poll::Ready(Err(()))
        } else {
            std::future::Future::poll(wait.as_mut(), context).map(|result| result.map_err(|_| ()))
        }
    })
    .await
}

fn prepared_fenced_v2_readiness_unavailable() -> StoreError {
    StoreError::BackendUnavailable(
        "authenticated consumer V2 activation readiness unavailable".into(),
    )
}

/// Redacted construction failure for the protected V2 fenced-transition
/// facade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("prepared fenced V2 voter roster is not an activated exact V2 authority")]
pub struct SessionConsumerPreparedFencedTransitionV2BackendError;

/// Opaque exact voter set produced only after every persistent voter proved
/// a V2 capability over a prewarmed `/2` lane. Void support is negotiated
/// separately without changing the original capability reply.
pub struct ActivatedSessionConsumerFencedTransitionV2Voters {
    router: Arc<PreparedConsumerRouter>,
    history: Option<FencedTransitionV2HistoryState>,
    capability: FencedTransitionV2Capability,
}

impl fmt::Debug for ActivatedSessionConsumerFencedTransitionV2Voters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActivatedSessionConsumerFencedTransitionV2Voters(<redacted>)")
    }
}

/// Redaction-safe failure to release a retained protected V2 transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerFencedTransitionV2ReleaseError {
    /// The handle has not observed a resolution that permits removal.
    #[error("protected fenced transition V2 is not resolved")]
    NotResolved,
    /// The recovery journal could not remove the exact retained row.
    #[error("protected fenced transition V2 recovery journal is unavailable")]
    Unavailable,
}

/// Redaction-safe failure to abandon a never-executed protected V2 transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerFencedTransitionV2AbandonError {
    /// Only the original handle, before execution has ever started, may abandon.
    #[error("protected fenced transition V2 has no unused dispatch authority")]
    NotAllowed,
    /// Dispatch is permanently disabled, but local deletion must be retried.
    #[error("protected fenced transition V2 recovery journal is unavailable")]
    Unavailable,
}

/// Value-free stage at which one prepared V2 fenced-transition execution
/// failed.
///
/// The vocabulary is closed, fixed-label and bounded. It carries no request
/// ID, endpoint, identity, scope, owner, fence, credential, key or payload
/// value, so it is safe for logs and low-cardinality metrics. It explains a
/// failure that the effect classification cannot distinguish: a cold setup
/// that never dispatched, a physical attempt that was admitted but wrote
/// nothing, a request whose reply was still outstanding when the attempt
/// budget expired, or a reply path that ended without an exact completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionConsumerPreparedFencedTransitionV2FailureStage {
    /// No physical attempt was admitted: local preflight/journal state,
    /// dispatch authority, or the attempt budget expired before dispatch.
    Setup,
    /// A physical attempt was admitted, but no request byte was accepted for
    /// transmission.
    Send,
    /// Request bytes were accepted and the physical attempt budget expired
    /// while awaiting a matching reply (for example a held or late refusal).
    AwaitingReply,
    /// The reply path ended, or a reply arrived that was not an exact
    /// completion, before the physical attempt budget expired.
    ReplyLost,
}

impl SessionConsumerPreparedFencedTransitionV2FailureStage {
    /// Fixed, value-free label for logs and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Send => "send",
            Self::AwaitingReply => "awaiting_reply",
            Self::ReplyLost => "reply_lost",
        }
    }
}

/// Value-free diagnostic attached to one failed prepared V2 execution.
///
/// It contains only the closed failure stage and the remaining original
/// caller budget in milliseconds. No value, request ID, identity, scope,
/// endpoint, owner, fence, credential, key or payload byte is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionConsumerPreparedFencedTransitionV2FailureDiagnostic {
    stage: SessionConsumerPreparedFencedTransitionV2FailureStage,
    remaining_budget_millis: u64,
}

impl SessionConsumerPreparedFencedTransitionV2FailureDiagnostic {
    const fn new(
        stage: SessionConsumerPreparedFencedTransitionV2FailureStage,
        remaining_budget_millis: u64,
    ) -> Self {
        Self {
            stage,
            remaining_budget_millis,
        }
    }

    /// The closed, value-free stage of the failed execution attempt.
    pub const fn stage(&self) -> SessionConsumerPreparedFencedTransitionV2FailureStage {
        self.stage
    }

    /// Remaining original caller budget when the failure was observed,
    /// truncated to whole milliseconds and never negative.
    pub const fn remaining_budget_millis(&self) -> u64 {
        self.remaining_budget_millis
    }

    /// Fixed, value-free stage label, identical to [`Self::stage`]'s label.
    pub const fn as_str(self) -> &'static str {
        self.stage.as_str()
    }
}

/// Diagnostic-only wrapper around one failed prepared V2 execution.
///
/// The effect-boundary classification, dispatch authority and ownership are
/// exactly those of [`SessionConsumerPreparedFencedTransitionV2::execute_once`].
/// [`Self::into_error`] yields precisely the [`opc_session_store::FencedTransitionExecuteError`]
/// that method would have returned, so a caller may treat the result exactly
/// as before and use the diagnostic for logging and metrics only. The
/// diagnostic is present for a `NotTransmitted` or `OutcomeUnknown` result
/// and absent for a resolved rejection or deferral.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionConsumerPreparedFencedTransitionV2Failure {
    error: FencedTransitionExecuteError,
    diagnostic: Option<SessionConsumerPreparedFencedTransitionV2FailureDiagnostic>,
}

impl SessionConsumerPreparedFencedTransitionV2Failure {
    /// Exact existing effect-boundary classification for this failed call.
    pub const fn error(&self) -> &FencedTransitionExecuteError {
        &self.error
    }

    /// Value-free diagnostic for a `NotTransmitted` or `OutcomeUnknown`
    /// result. `None` means the outcome was a resolved rejection or deferral,
    /// for which no transport stage exists.
    pub const fn diagnostic(
        &self,
    ) -> Option<&SessionConsumerPreparedFencedTransitionV2FailureDiagnostic> {
        self.diagnostic.as_ref()
    }

    /// Discard the diagnostic and recover today's exact error result.
    pub fn into_error(self) -> FencedTransitionExecuteError {
        self.error
    }

    fn error_kind(&self) -> &'static str {
        match &self.error {
            FencedTransitionExecuteError::NotTransmitted => "not_transmitted",
            FencedTransitionExecuteError::OutcomeUnknown { .. } => "outcome_unknown",
            FencedTransitionExecuteError::Rejected(_) => "rejected",
            FencedTransitionExecuteError::LeaseDeferred => "lease_deferred",
            // The store crate owns this non-exhaustive classification; an
            // unknown future variant stays a value-free fixed label here.
            _ => "other",
        }
    }
}

impl fmt::Debug for SessionConsumerPreparedFencedTransitionV2Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SessionConsumerPreparedFencedTransitionV2Failure");
        debug.field("error_kind", &self.error_kind());
        match &self.diagnostic {
            Some(diagnostic) => debug
                .field("stage", &diagnostic.stage().as_str())
                .field(
                    "remaining_budget_millis",
                    &diagnostic.remaining_budget_millis(),
                )
                .finish_non_exhaustive(),
            None => debug.field("stage", &"none").finish_non_exhaustive(),
        }
    }
}

impl fmt::Display for SessionConsumerPreparedFencedTransitionV2Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for SessionConsumerPreparedFencedTransitionV2Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Fixed numeric result of one bounded reclamation sweep.
///
/// It contains no identity, epoch, key, or payload value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionConsumerFencedTransitionV2ReclaimReport {
    examined: usize,
    reclaimed: usize,
    retained: usize,
    interrupted: bool,
    voided: usize,
    unsupported: usize,
    waiting_callers: usize,
}

impl SessionConsumerFencedTransitionV2ReclaimReport {
    /// Retained rows whose exact status this sweep read.
    pub const fn examined(&self) -> usize {
        self.examined
    }

    /// Rows removed because their transition can no longer bind or its
    /// exact result window elapsed, including rows at or below the retired
    /// floor.
    pub const fn reclaimed(&self) -> usize {
        self.reclaimed
    }

    /// Examined rows retained for an original receipt, a waiting caller,
    /// unsupported void, `RequestConflict`, or another unresolved status.
    pub const fn retained(&self) -> usize {
        self.retained
    }

    /// Whether the sweep stopped early at an unavailable status or at the
    /// caller's deadline. A later sweep resumes from the same position.
    /// Unavailable and unknown voids retain their rows but advance the cursor.
    pub const fn interrupted(&self) -> bool {
        self.interrupted
    }
    /// Rows with an exact terminal void receipt observed by this sweep.
    pub const fn voided(&self) -> usize {
        self.voided
    }

    /// NotFound rows retained because the journal or a voter lacks void support.
    pub const fn unsupported(&self) -> usize {
        self.unsupported
    }

    /// NotFound rows retained for a current caller within its original deadline.
    pub const fn waiting_callers(&self) -> usize {
        self.waiting_callers
    }
}

/// Retained transition found by caller-stable recovery.
///
/// Both variants have receipt authority only.
#[non_exhaustive]
pub enum SessionConsumerRecoveredFencedTransition {
    /// A protected V2 transition retained by the recovery journal.
    V2(SessionConsumerRecoveredFencedTransitionV2Status),
    /// A #701 protected V1 transition retained from before the upgrade.
    LegacyV1(SessionConsumerRecoveredFencedTransitionStatus),
}

impl fmt::Debug for SessionConsumerRecoveredFencedTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::V2(_) => "v2",
            Self::LegacyV1(_) => "legacy_v1",
        };
        formatter
            .debug_struct("SessionConsumerRecoveredFencedTransition")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// Private construction boundary for an erased SDK protection wrapper that
/// implements the sealed protected V2 port.
trait PreparedFencedTransitionV2WrapperFactory: Send + Sync {
    fn journal(&self) -> Arc<FencedTransitionV2RecoveryJournal>;

    fn wrap(
        &self,
        physical: Arc<dyn SessionBackend>,
        class: ScopeWorkClass,
    ) -> Arc<dyn ProtectedFencedTransitionV2Backend>;

    fn with_legacy_journal(
        &self,
        journal: Arc<PreparedFencedTransitionJournal>,
    ) -> Arc<dyn PreparedFencedTransitionV2WrapperFactory>;
}

struct LocalAeadPreparedFencedTransitionV2Wrapper<P: ?Sized> {
    provider: Arc<P>,
    backend_namespace: Arc<str>,
    journal: Arc<FencedTransitionV2RecoveryJournal>,
    scope: FencedTransitionV2JournalScope,
    legacy_journal: Option<Arc<PreparedFencedTransitionJournal>>,
}

impl<P> PreparedFencedTransitionV2WrapperFactory for LocalAeadPreparedFencedTransitionV2Wrapper<P>
where
    P: KeyProvider + Send + Sync + 'static + ?Sized,
{
    fn journal(&self) -> Arc<FencedTransitionV2RecoveryJournal> {
        Arc::clone(&self.journal)
    }

    fn wrap(
        &self,
        physical: Arc<dyn SessionBackend>,
        class: ScopeWorkClass,
    ) -> Arc<dyn ProtectedFencedTransitionV2Backend> {
        let wrapper = EncryptingSessionBackend::new(
            physical,
            Arc::clone(&self.provider),
            self.backend_namespace.to_string(),
        )
        .with_fenced_transition_v2_recovery_journal(Arc::new(
            self.journal.with_operation_class(class),
        ))
        .with_fenced_transition_v2_journal_scope(self.scope);
        Arc::new(match &self.legacy_journal {
            Some(legacy) => wrapper.with_fenced_transition_journal(Arc::clone(legacy)),
            None => wrapper,
        })
    }

    fn with_legacy_journal(
        &self,
        journal: Arc<PreparedFencedTransitionJournal>,
    ) -> Arc<dyn PreparedFencedTransitionV2WrapperFactory> {
        Arc::new(Self {
            provider: Arc::clone(&self.provider),
            backend_namespace: Arc::clone(&self.backend_namespace),
            journal: Arc::clone(&self.journal),
            scope: self.scope,
            legacy_journal: Some(journal),
        })
    }
}

struct RemoteSealPreparedFencedTransitionV2Wrapper<S: ?Sized> {
    provider: Arc<S>,
    backend_namespace: Arc<str>,
    journal: Arc<FencedTransitionV2RecoveryJournal>,
    scope: FencedTransitionV2JournalScope,
    legacy_journal: Option<Arc<PreparedFencedTransitionJournal>>,
}

impl<S> PreparedFencedTransitionV2WrapperFactory for RemoteSealPreparedFencedTransitionV2Wrapper<S>
where
    S: RemoteSealProvider + Send + Sync + 'static + ?Sized,
{
    fn journal(&self) -> Arc<FencedTransitionV2RecoveryJournal> {
        Arc::clone(&self.journal)
    }

    fn wrap(
        &self,
        physical: Arc<dyn SessionBackend>,
        class: ScopeWorkClass,
    ) -> Arc<dyn ProtectedFencedTransitionV2Backend> {
        let wrapper = RemoteSealingSessionBackend::new(
            physical,
            Arc::clone(&self.provider),
            self.backend_namespace.to_string(),
        )
        .with_fenced_transition_v2_recovery_journal(Arc::new(
            self.journal.with_operation_class(class),
        ))
        .with_fenced_transition_v2_journal_scope(self.scope);
        Arc::new(match &self.legacy_journal {
            Some(legacy) => wrapper.with_fenced_transition_journal(Arc::clone(legacy)),
            None => wrapper,
        })
    }

    fn with_legacy_journal(
        &self,
        journal: Arc<PreparedFencedTransitionJournal>,
    ) -> Arc<dyn PreparedFencedTransitionV2WrapperFactory> {
        Arc::new(Self {
            provider: Arc::clone(&self.provider),
            backend_namespace: Arc::clone(&self.backend_namespace),
            journal: Arc::clone(&self.journal),
            scope: self.scope,
            legacy_journal: Some(journal),
        })
    }
}

/// Stable recovery-journal authority for one consumer: its local
/// authenticated identity commitment and the stable cluster ID.
///
/// Endpoint, leader, configuration epoch, and credential material are
/// deliberately excluded so authorized rotation keeps the same journal.
fn prepared_fenced_v2_recovery_scope(
    router: &PreparedConsumerRouter,
) -> Result<FencedTransitionV2JournalScope, SessionConsumerPreparedFencedTransitionV2BackendError> {
    let client = router
        .clients
        .first()
        .ok_or(SessionConsumerPreparedFencedTransitionV2BackendError)?;
    let local_identity_commitment = client
        .pool
        .client
        .tls_config
        .local_spiffe_identity_commitment()
        .ok_or(SessionConsumerPreparedFencedTransitionV2BackendError)?;
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/prepared-fenced-v2-recovery-scope/v1\0");
    digest.update(local_identity_commitment);
    digest.update(router.scope.consensus_identity().cluster_id().as_bytes());
    Ok(FencedTransitionV2JournalScope::from_bytes(
        digest.finalize().into(),
    ))
}

fn prepared_fenced_v2_origin(
    router: &PreparedConsumerRouter,
    request_id: FencedTransitionRequestId,
) -> usize {
    let identity = router.scope.consensus_identity();
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/prepared-fenced-transition-v2-origin/v1\0");
    digest.update(identity.cluster_id().as_bytes());
    digest.update(identity.configuration_id().as_bytes());
    digest.update(identity.configuration_epoch().get().to_be_bytes());
    digest.update(router.clients[0].pool.client.voter.roster_commitment());
    for client in router.clients.iter() {
        digest.update(client.pool.client.voter.node_id().get().to_be_bytes());
    }
    digest.update(request_id.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    (u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]) as usize)
        % router.clients.len()
}

/// Per-handle routing state for one protected V2 transition.
///
/// The public handle and the net-private physical adapter share only this
/// allocation. It is not keyed in any facade-wide map, so one handle can
/// never inherit another's cursor or dispatch state.
struct PreparedFencedTransitionV2Route {
    mutation_cursor: AtomicUsize,
    status_cursor: AtomicUsize,
    attempt_deadline: StdMutex<Option<tokio::time::Instant>>,
    // Set immediately before the adapter enters a physical V2 mutation call
    // and cleared only by that call's authoritative no-dispatch classification,
    // including a complete, correlated pre-dispatch refusal. A handle cancelled
    // while this is set may have sent.
    dispatch_admitted: AtomicBool,
    // Value-free stage of the most recent failed execution observation. Per
    // handle: the public handle's `&mut` execution/status methods serialize
    // access, and the net-private adapter shares only this allocation.
    failure_stage: StdMutex<Option<SessionConsumerPreparedFencedTransitionV2FailureStage>>,
}

impl PreparedFencedTransitionV2Route {
    fn new(origin: usize) -> Self {
        Self {
            mutation_cursor: AtomicUsize::new(origin),
            status_cursor: AtomicUsize::new(origin.wrapping_add(1)),
            attempt_deadline: StdMutex::new(None),
            dispatch_admitted: AtomicBool::new(false),
            failure_stage: StdMutex::new(None),
        }
    }

    fn clear_failure_stage(&self) {
        *self
            .failure_stage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    fn record_failure_stage(&self, stage: SessionConsumerPreparedFencedTransitionV2FailureStage) {
        *self
            .failure_stage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stage);
    }

    fn failure_stage(&self) -> Option<SessionConsumerPreparedFencedTransitionV2FailureStage> {
        *self
            .failure_stage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn mutation_voter(&self, voter_count: usize) -> usize {
        prepared_voter_index(self.mutation_cursor.load(Ordering::Acquire), voter_count)
    }

    fn rotate_after_not_transmitted(&self) {
        self.mutation_cursor.fetch_add(1, Ordering::AcqRel);
    }

    /// A receipt traversal begins after the voter that may have received the
    /// mutation, as for the V1 facade.
    fn begin_receipt_after_current_mutation_voter(&self, voter_count: usize) {
        let voter = self.mutation_voter(voter_count);
        self.status_cursor
            .store(voter.wrapping_add(1), Ordering::Release);
    }

    fn next_status_voter(&self, voter_count: usize) -> usize {
        prepared_voter_index(
            self.status_cursor.fetch_add(1, Ordering::AcqRel),
            voter_count,
        )
    }

    fn install_attempt_deadline(&self, deadline: tokio::time::Instant) {
        *self
            .attempt_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(deadline);
    }

    fn attempt_deadline(&self) -> Option<tokio::time::Instant> {
        *self
            .attempt_deadline
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn admit_dispatch(&self) {
        self.dispatch_admitted.store(true, Ordering::Release);
    }

    fn prove_not_transmitted(&self) {
        self.dispatch_admitted.store(false, Ordering::Release);
    }

    fn may_have_dispatched(&self) -> bool {
        self.dispatch_admitted.load(Ordering::Acquire)
    }
}

/// Classify one physical-attempt failure into the closed diagnostic stage.
///
/// Diagnostic-only: the effect classification is derived from the same
/// response by the caller and is never changed here. `deadline_reached`
/// records whether the installed physical-attempt budget had expired when the
/// failure was observed; a request whose reply was still outstanding then is
/// `AwaitingReply`, while a reply path that ended earlier is `ReplyLost`.
/// Revoked authority is a resolved classification and returns no stage.
fn prepared_fenced_v2_effect_failure_stage(
    deadline_reached: bool,
    response: &Result<SessionConsumerV2Response, PersistentSessionConsumerV2ExecuteError>,
) -> Option<SessionConsumerPreparedFencedTransitionV2FailureStage> {
    use SessionConsumerPreparedFencedTransitionV2FailureStage as Stage;
    match response {
        Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Scope | SessionConsumerClientError::AuthorityRevoked,
        }) => None,
        Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted { .. }) => Some(Stage::Send),
        Err(_) if deadline_reached => Some(Stage::AwaitingReply),
        Err(_) => Some(Stage::ReplyLost),
        Ok(_) => Some(Stage::ReplyLost),
    }
}

/// Best-effort stage for an ambiguous effect result when the physical boundary
/// did not record a more precise observation (for example an in-process
/// scripted backend). The attempt deadline is the only fixed fact available.
fn prepared_fenced_v2_ambiguous_failure_stage(
    attempt_deadline: Option<tokio::time::Instant>,
) -> SessionConsumerPreparedFencedTransitionV2FailureStage {
    use SessionConsumerPreparedFencedTransitionV2FailureStage as Stage;
    if attempt_deadline.is_none_or(|deadline| tokio::time::Instant::now() >= deadline) {
        Stage::AwaitingReply
    } else {
        Stage::ReplyLost
    }
}

/// Most recent linearized V2 history state observed by one facade.
///
/// Every V2 history-state read is a consensus-backed linearized read, so the
/// facade keeps it off the per-transition path. Any previously linearized
/// active epoch is safe for a new preparation: epochs only advance, and a
/// request that names an epoch that has since closed is rejected at execution
/// without binding a receipt. The handle then invalidates this cache so the
/// next preparation reads the successor epoch. Maintenance opens a successor
/// only after the active epoch is full, so a request that names the cached
/// epoch after it filled would have been rejected as `HistoryFull` by a fresh
/// read as well. A state that names no active epoch, or a full one, is never
/// served from the cache: preparation reads again instead of rejecting on
/// stale capacity.
#[derive(Default)]
struct PreparedFencedV2HistoryCache {
    state: StdMutex<Option<FencedTransitionV2HistoryState>>,
}

impl PreparedFencedV2HistoryCache {
    fn primed(state: Option<FencedTransitionV2HistoryState>) -> Self {
        Self {
            state: StdMutex::new(state),
        }
    }

    /// The cached state, only while it names an active epoch with remaining
    /// capacity.
    fn bindable(&self) -> Option<FencedTransitionV2HistoryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .filter(|state| {
                state.active_epoch().is_some()
                    && state.bound_entries() < FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            })
    }

    /// Retain the newest lifecycle state; an older concurrent read never
    /// replaces a newer one. Epochs, maintenance generations, and bound
    /// counts within one generation only advance.
    fn observe(&self, observed: FencedTransitionV2HistoryState) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.is_none_or(|cached| {
            (
                observed.active_epoch(),
                observed.generation(),
                observed.bound_entries(),
            ) >= (
                cached.active_epoch(),
                cached.generation(),
                cached.bound_entries(),
            )
        }) {
            *state = Some(observed);
        }
    }

    /// Forget a cached state whose active epoch is at or below `epoch`, after
    /// an execution proved that epoch can no longer bind new requests.
    fn invalidate_through(&self, epoch: FencedTransitionV2HistoryEpoch) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.is_some_and(|cached| cached.active_epoch().is_none_or(|active| active <= epoch)) {
            *state = None;
        }
    }
}

/// Whether a physical adapter may answer a history-state read from the
/// facade cache, must use a caller's original deadline, or may use bounded
/// per-voter attempts during background reclamation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum V2HistoryRead {
    Cached,
    Fresh,
    Maintenance,
}

/// Net-private physical V2 adapter for one affine handle or one bounded
/// facade operation. It owns the activated roster but no global cursor map,
/// serves only the V2 subset, and fails every other operation locally.
struct ActivatedFencedTransitionV2Backend {
    capability: FencedTransitionV2Capability,
    router: Arc<PreparedConsumerRouter>,
    route: Arc<PreparedFencedTransitionV2Route>,
    history: Arc<PreparedFencedV2HistoryCache>,
    history_read: V2HistoryRead,
    deadline: tokio::time::Instant,
    attempt_timeout: Duration,
}

impl ActivatedFencedTransitionV2Backend {
    fn voter_count(&self) -> usize {
        self.router.clients.len()
    }

    /// The mutation deadline installed by the handle, or a fresh mutation
    /// attempt cap bounded by this adapter's immutable deadline.
    fn attempt_deadline(&self) -> Option<tokio::time::Instant> {
        let deadline = self.route.attempt_deadline().unwrap_or_else(|| {
            tokio::time::Instant::now()
                .checked_add(self.attempt_timeout)
                .map_or(self.deadline, |capped| capped.min(self.deadline))
        });
        let deadline = deadline.min(self.deadline);
        (deadline > tokio::time::Instant::now()).then_some(deadline)
    }

    fn read_budget(&self) -> Option<PreparedCheckpointBudget> {
        (self.deadline > tokio::time::Instant::now())
            .then(|| PreparedCheckpointBudget::new(self.deadline, self.attempt_timeout).ok())
            .flatten()
    }

    fn status_read_budget(&self) -> Option<PreparedCheckpointBudget> {
        // The status caller installs its chosen read deadline, which may be
        // earlier than the immutable original deadline. Mutation attempts
        // still install their own physical cap through the same affine route.
        let deadline = self
            .route
            .attempt_deadline()
            .unwrap_or(self.deadline)
            .min(self.deadline);
        (deadline > tokio::time::Instant::now())
            .then(|| PreparedCheckpointBudget::new(deadline, self.attempt_timeout).ok())
            .flatten()
    }
}

/// Read linearized V2 history state, traversing the canonical roster from
/// `origin`. Advance after a reply or a pre-write failure. A transmitted read
/// without a reply spends the remaining caller deadline without hedging.
/// Background maintenance instead retains its bounded per-voter attempts.
async fn linearized_v2_history_state(
    router: &PreparedConsumerRouter,
    origin: usize,
    budget: PreparedCheckpointBudget,
    mode: V2HistoryRead,
) -> Result<FencedTransitionV2HistoryState, StoreError> {
    let voter_count = router.clients.len();
    for offset in 0..voter_count {
        if tokio::time::Instant::now() >= budget.original_deadline() {
            break;
        }
        let client =
            &router.clients[prepared_voter_index(origin.wrapping_add(offset), voter_count)];
        let read_budget = if mode == V2HistoryRead::Maintenance {
            let deadline = reclaim_attempt_deadline(&budget, budget.original_deadline())
                .ok_or_else(prepared_fenced_v2_deadline)?;
            PreparedCheckpointBudget::new(deadline, budget.physical_attempt_timeout())
                .map_err(|_| prepared_fenced_v2_deadline())?
        } else {
            budget
        };
        let response = client
            .execute_v2_read_with_budget(DeadlineV2Read::HistoryState, read_budget)
            .await;
        if v2_authority_revoked(&response) {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        if let Ok(SessionConsumerV2Response::FencedTransitionV2HistoryState(Ok(state))) = response {
            return Ok(state);
        }
    }
    Err(StoreError::BackendUnavailable(
        PREPARED_FENCED_V2_HISTORY_UNAVAILABLE.into(),
    ))
}

pub(super) fn v2_authority_revoked(
    response: &Result<SessionConsumerV2Response, PersistentSessionConsumerV2ExecuteError>,
) -> bool {
    matches!(
        response,
        Ok(SessionConsumerV2Response::Rejected(
            SessionConsumerRejection::ScopeMismatch
                | SessionConsumerRejection::TopologyMismatch
                | SessionConsumerRejection::Unauthorized,
        )) | Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Scope | SessionConsumerClientError::AuthorityRevoked,
        }) | Err(PersistentSessionConsumerV2ExecuteError::ReadUnavailable {
            cause: SessionConsumerClientError::Scope | SessionConsumerClientError::AuthorityRevoked,
        })
    )
}

fn consumer_v2_status_into_store(
    status: SessionConsumerV2FencedTransitionStatus,
) -> Result<FencedTransitionV2Status, StoreError> {
    Ok(match status {
        SessionConsumerV2FencedTransitionStatus::Recorded(result) => {
            FencedTransitionV2Status::Recorded(Box::new(
                (*result).map_err(|error| error.into_store_error()),
            ))
        }
        SessionConsumerV2FencedTransitionStatus::RequestConflict => {
            FencedTransitionV2Status::RequestConflict
        }
        SessionConsumerV2FencedTransitionStatus::Expired => FencedTransitionV2Status::Expired,
        SessionConsumerV2FencedTransitionStatus::Retired => FencedTransitionV2Status::Retired,
        SessionConsumerV2FencedTransitionStatus::HistoryFull => {
            FencedTransitionV2Status::HistoryFull
        }
        SessionConsumerV2FencedTransitionStatus::NotFound => FencedTransitionV2Status::NotFound,
        SessionConsumerV2FencedTransitionStatus::EpochNotActive => {
            FencedTransitionV2Status::EpochNotActive
        }
        SessionConsumerV2FencedTransitionStatus::RetentionExhausted => {
            FencedTransitionV2Status::RetentionExhausted
        }
        SessionConsumerV2FencedTransitionStatus::LeaseDeferred { request_id } => {
            FencedTransitionV2Status::LeaseDeferred { request_id }
        }
        _ => {
            return Err(StoreError::BackendUnavailable(
                PREPARED_FENCED_V2_RECEIPT_UNAVAILABLE.into(),
            ))
        }
    })
}

#[async_trait::async_trait]
impl SessionBackend for ActivatedFencedTransitionV2Backend {
    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::minimal()
    }

    async fn preflight_record_expiry(
        &self,
        preflights: &[RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        // A nonfinite descriptor carries only the fixed profile shape and no
        // remote clock can make an absent expiry stale; validate it locally
        // exactly as the V1 facade does.
        validate_record_expiry_preflights_profile(preflights)?;
        if preflights.iter().all(|preflight| !preflight.is_finite()) {
            return Ok(());
        }
        // Expiry authority is a read-only general-lane RPC. Traverse the same
        // deterministic order from this handle's origin under one immutable
        // deadline. No response wait overlaps another physical read.
        let voter_count = self.voter_count();
        let mut last_unavailable = None;
        for offset in 0..voter_count {
            let Some(budget) = self.read_budget() else {
                break;
            };
            let client = &self.router.clients[prepared_voter_index(
                self.route.mutation_voter(voter_count).wrapping_add(offset),
                voter_count,
            )];
            let response = journal_before_deadline(
                budget.original_deadline(),
                client.execute_v1_read_with_budget(
                    DeadlineV1Read::PreflightRecordExpiry(preflights.to_vec()),
                    budget,
                ),
            )
            .await;
            match response {
                Ok(Ok(SessionConsumerResponse::PreflightRecordExpiry(Ok(())))) => return Ok(()),
                Ok(Ok(SessionConsumerResponse::PreflightRecordExpiry(Err(error)))) => {
                    if matches!(error, SessionConsumerStoreError::Unavailable) {
                        last_unavailable = Some(StoreError::BackendUnavailable(
                            "prepared fenced V2 expiry authority unavailable".into(),
                        ));
                    } else {
                        return Err(error.into_store_error());
                    }
                }
                Ok(Ok(SessionConsumerResponse::Rejected(
                    SessionConsumerRejection::ScopeMismatch
                    | SessionConsumerRejection::TopologyMismatch
                    | SessionConsumerRejection::Unauthorized,
                )))
                | Ok(Err(
                    SessionConsumerCallError::BeforeCallWrite(
                        SessionConsumerClientError::Scope
                        | SessionConsumerClientError::AuthorityRevoked,
                    )
                    | SessionConsumerCallError::MayHaveSent(
                        SessionConsumerClientError::Scope
                        | SessionConsumerClientError::AuthorityRevoked,
                    ),
                )) => return Err(StoreError::TopologyAuthorityRevoked),
                Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
                    last_unavailable = Some(StoreError::BackendUnavailable(
                        "prepared fenced V2 expiry authority unavailable".into(),
                    ));
                }
            }
        }
        Err(last_unavailable.unwrap_or_else(prepared_fenced_v2_deadline))
    }

    async fn get(
        &self,
        _key: &opc_session_store::SessionKey,
    ) -> Result<Option<opc_session_store::StoredSessionRecord>, StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn observe_fenced_transition(
        &self,
        key: &opc_session_store::SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        // The activated roster is canonicalized by node ordinal, so its first
        // client is a stable authenticated coordinator for this authority.
        self.router.clients[0]
            .observe_fenced_transition(key.clone())
            .await
    }

    fn fenced_transition_preserves_protected_payloads(&self) -> bool {
        true
    }

    async fn fenced_transition_v2_capability(
        &self,
    ) -> Result<Option<FencedTransitionV2Capability>, StoreError> {
        // Activation proved the exact V2 profile on every voter before this
        // adapter could exist; each physical call is still authorized anew.
        Ok(Some(self.capability))
    }

    async fn fenced_transition_v2_history_state(
        &self,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        if self.history_read == V2HistoryRead::Cached {
            if let Some(state) = self.history.bindable() {
                return Ok(state);
            }
        }
        let state = linearized_v2_history_state(
            &self.router,
            self.route.mutation_voter(self.voter_count()),
            self.read_budget().ok_or_else(prepared_fenced_v2_deadline)?,
            self.history_read,
        )
        .await?;
        self.history.observe(state);
        Ok(state)
    }

    async fn fenced_transition_v2(
        &self,
        request: FencedTransitionV2Request,
    ) -> Result<FencedTransitionOutcome, StoreError> {
        match self.fenced_transition_v2_effect(request).await {
            FencedTransitionV2Effect::Resolved(result) => result,
            FencedTransitionV2Effect::NotTransmitted(error) => Err(error),
            _ => Err(StoreError::FencedTransitionOutcomeUnknown),
        }
    }

    async fn fenced_transition_v2_effect(
        &self,
        request: FencedTransitionV2Request,
    ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>> {
        let Some(deadline) = self.attempt_deadline() else {
            // No physical attempt could be admitted within the immutable
            // caller budget: this is the diagnostic-only `setup` stage.
            self.route
                .record_failure_stage(SessionConsumerPreparedFencedTransitionV2FailureStage::Setup);
            return FencedTransitionV2Effect::NotTransmitted(prepared_fenced_v2_deadline());
        };
        // The decisive observation is the attempt that resolves the call, so
        // discard any stage recorded for an earlier rotated attempt.
        self.route.clear_failure_stage();
        let voter = self.route.mutation_voter(self.voter_count());
        let client = &self.router.clients[voter];
        let wire = SessionConsumerV2Request::new(
            self.router.scope,
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(request.clone()),
            },
        );
        // From here on a cancellation may leave the lane actor writing, so
        // the owning handle must treat it as a possible send.
        self.route.admit_dispatch();
        let response = client.execute_v2_before(&wire, deadline).await;
        match response {
            Ok(SessionConsumerV2Response::FencedTransitionV2Deferred { request_id })
                if request_id == request.request_id() =>
            {
                FencedTransitionV2Effect::Resolved(Err(StoreError::FencedTransitionLeaseDeferred))
            }
            Ok(SessionConsumerV2Response::FencedTransitionV2(Ok(outcome)))
                if outcome.matches_v2_request(&request) =>
            {
                FencedTransitionV2Effect::Resolved(Ok(outcome))
            }
            // The `/2` client admits a singleton error only when it is a V2
            // pre-dispatch deterministic result; every such result is a
            // definitive no-effect rejection for this exact request.
            Ok(SessionConsumerV2Response::FencedTransitionV2(Err(error)))
                if error.is_pre_dispatch_deterministic() =>
            {
                FencedTransitionV2Effect::Resolved(Err(error.into_store_error()))
            }
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
                cause:
                    SessionConsumerClientError::Scope | SessionConsumerClientError::AuthorityRevoked,
            }) => {
                self.route.prove_not_transmitted();
                FencedTransitionV2Effect::Resolved(Err(StoreError::TopologyAuthorityRevoked))
            }
            Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted { .. }) => {
                self.route.prove_not_transmitted();
                // The attempt was admitted but proved that no request byte
                // crossed the boundary.
                self.route.record_failure_stage(
                    SessionConsumerPreparedFencedTransitionV2FailureStage::Send,
                );
                FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(
                    "prepared fenced transition V2 was not transmitted".into(),
                ))
            }
            // Every other response, including an uncorrelated success, a
            // recorded deterministic error that the client does not accept
            // as an exact completion, and any post-write loss, may have
            // crossed the effect boundary.
            response => {
                let deadline_reached = tokio::time::Instant::now() >= deadline;
                if let Some(stage) =
                    prepared_fenced_v2_effect_failure_stage(deadline_reached, &response)
                {
                    self.route.record_failure_stage(stage);
                }
                FencedTransitionV2Effect::OutcomeUnknown {
                    request_ids: vec![request.request_id()],
                }
            }
        }
    }

    async fn fenced_transition_v2_void(
        &self,
        request: &FencedTransitionV2Request,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        let deadline = self
            .attempt_deadline()
            .ok_or_else(prepared_fenced_v2_deadline)?;
        // The store proves the exact immutable voter profile at activation.
        // Any reachable voter can expose that proof; an unavailable lane does
        // not veto an already certified quorum.
        use futures_util::StreamExt as _;
        let mut probes = self
            .router
            .clients
            .iter()
            .enumerate()
            .map(|(index, client)| async move {
                let probe = SessionConsumerV2Request::new(
                    self.router.scope,
                    SessionConsumerV2Operation::FencedTransitionV2VoidCapability,
                );
                (index, client.execute_v2_before(&probe, deadline).await)
            })
            .collect::<futures_util::stream::FuturesUnordered<_>>();
        let mut voter = None;
        let mut unsupported = 0;
        while let Some((index, response)) = probes.next().await {
            if v2_authority_revoked(&response) {
                return Err(StoreError::TopologyAuthorityRevoked);
            }
            match response {
                Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(Ok(()))) => {
                    voter = Some(index);
                    break;
                }
                Ok(SessionConsumerV2Response::FencedTransitionV2VoidCapability(Err(
                    SessionConsumerStoreError::CapabilityNotSupported,
                )))
                | Ok(SessionConsumerV2Response::Rejected(
                    SessionConsumerRejection::MalformedRequest,
                )) => unsupported += 1,
                _ => {}
            }
        }
        drop(probes);
        let Some(voter) = voter else {
            return Err(if unsupported == self.voter_count() {
                StoreError::CapabilityNotSupported("fenced_transition_v2_void".into())
            } else {
                StoreError::BackendUnavailable(
                    "fenced transition V2 void capability unavailable".into(),
                )
            });
        };
        let wire = SessionConsumerV2Request::new(
            self.router.scope,
            SessionConsumerV2Operation::FencedTransitionV2Void {
                request: Box::new(request.clone()),
            },
        );
        let response = self.router.clients[voter]
            .execute_v2_before(&wire, deadline)
            .await;
        if v2_authority_revoked(&response) {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        match response {
            Ok(SessionConsumerV2Response::FencedTransitionV2Void { request_id, result })
                if request_id == request.request_id() =>
            {
                result
                    .map_err(SessionConsumerStoreError::into_store_error)
                    .and_then(consumer_v2_status_into_store)
            }
            _ => Err(StoreError::FencedTransitionOutcomeUnknown),
        }
    }

    async fn fenced_transition_v2_status(
        &self,
        request: &FencedTransitionV2Request,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        let budget = self
            .status_read_budget()
            .ok_or_else(prepared_fenced_v2_deadline)?;
        let voter = self.route.next_status_voter(self.voter_count());
        let response = self.router.clients[voter]
            .execute_v2_read_with_budget(DeadlineV2Read::Status(Box::new(request.clone())), budget)
            .await;
        if v2_authority_revoked(&response) {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        match response {
            Ok(SessionConsumerV2Response::FencedTransitionV2Status(Ok(status))) => {
                consumer_v2_status_into_store(status)
            }
            _ => Err(StoreError::BackendUnavailable(
                PREPARED_FENCED_V2_RECEIPT_UNAVAILABLE.into(),
            )),
        }
    }

    async fn compare_and_set(
        &self,
        _operation: CompareAndSet,
    ) -> Result<CompareAndSetResult, StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }

    async fn batch(&self, _operations: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        Err(authenticated_consumer_fenced_transition_only())
    }
}

/// Net-owned affine facade for protected V2 fenced transitions (#982).
///
/// It accepts only an opaque, completely V2-prewarmed exact roster, retains
/// the SDK sealing wrapper behind a private erased port, and exposes neither
/// a backend, the wrapper, a physical request, nor a sealed body. The caller
/// supplies the same [`FencedTransitionRequest`] as for the V1 facade; its
/// 16-byte ID is the caller-stable recovery identity, while the V2 epoch and
/// nonce are chosen internally.
///
/// ```compile_fail
/// use opc_session_net::SessionConsumerPreparedFencedTransitionV2Backend;
/// use opc_session_store::SessionBackend;
///
/// fn needs_raw_mutation_authority(_: &dyn SessionBackend) {}
///
/// fn cannot_lower(facade: &SessionConsumerPreparedFencedTransitionV2Backend) {
///     needs_raw_mutation_authority(facade);
/// }
/// ```
pub struct SessionConsumerPreparedFencedTransitionV2Backend {
    capability: FencedTransitionV2Capability,
    router: Arc<PreparedConsumerRouter>,
    wrapper_factory: Arc<dyn PreparedFencedTransitionV2WrapperFactory>,
    legacy_v1: Option<SessionConsumerPreparedFencedTransitionBackend>,
    history: Arc<PreparedFencedV2HistoryCache>,
    reclaim_cursor: StdMutex<Option<FencedTransitionRequestId>>,
}

impl fmt::Debug for SessionConsumerPreparedFencedTransitionV2Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerPreparedFencedTransitionV2Backend(<redacted>)")
    }
}

impl SessionConsumerPreparedFencedTransitionV2Backend {
    /// Activate and prewarm the complete exact V2 voter roster.
    ///
    /// This requires one persistent client for every voter of one scope, the
    /// same local authenticated identity, one roster commitment, and distinct
    /// node IDs and voter TLS identities. Every voter's `/2` lane is
    /// prewarmed and must return `FencedTransitionV2Capability::V2`; any
    /// other result refuses construction. Void is negotiated separately. The
    /// returned roster is opaque and canonicalized by node ordinal.
    ///
    /// Activation also reads the linearized V2 history state once to seed
    /// the facade's active-epoch cache. A revoked topology authority refuses
    /// activation; any other failed read only defers that read to the first
    /// preparation.
    pub async fn persistent_exact_voter_prewarm_roster(
        voters: impl IntoIterator<Item = PersistentSessionConsumerClient>,
    ) -> Result<ActivatedSessionConsumerFencedTransitionV2Voters, StoreError> {
        let voters: Vec<_> = voters.into_iter().collect();
        if voters.is_empty() || voters.len() > QUORUM_TOPOLOGY_MAX_MEMBERS {
            return Err(prepared_fenced_v2_readiness_unavailable());
        }
        let readiness: Vec<_> = voters
            .iter()
            .map(persistent_fenced_transition_voter_readiness)
            .collect::<Option<_>>()
            .ok_or_else(prepared_fenced_v2_readiness_unavailable)?;
        let primary = readiness
            .first()
            .ok_or_else(prepared_fenced_v2_readiness_unavailable)?;
        if readiness.len() != primary.voter_count
            || primary.voter_count > QUORUM_TOPOLOGY_MAX_MEMBERS
            || readiness.iter().any(|voter| {
                voter.scope != primary.scope
                    || voter.voter_count != primary.voter_count
                    || voter.roster_commitment != primary.roster_commitment
                    || voter.local_spiffe_identity_commitment
                        != primary.local_spiffe_identity_commitment
            })
            || !consumer_fenced_transition_readiness_roster_is_exact(&readiness)
        {
            return Err(prepared_fenced_v2_readiness_unavailable());
        }

        // Activation is deliberately off the request hot path. Establish the
        // complete configured `/2` width before the capability proof so the
        // first protected dispatch does not spend its physical attempt cap
        // opening lanes.
        let capabilities = futures_util::future::join_all(voters.iter().map(|client| async {
            client.prewarm_v2().await.map_err(|error| match error {
                SessionConsumerClientError::Scope
                | SessionConsumerClientError::AuthorityRevoked => {
                    StoreError::TopologyAuthorityRevoked
                }
                _ => prepared_fenced_v2_readiness_unavailable(),
            })?;
            let readiness = client.v2_readiness().await;
            if !readiness.ready
                || readiness.ready_request_connections != readiness.configured_request_connections
            {
                return Err(prepared_fenced_v2_readiness_unavailable());
            }
            let response = client
                .execute_v2(&SessionConsumerV2Request::new(
                    client.scope(),
                    SessionConsumerV2Operation::FencedTransitionV2Capability,
                ))
                .await;
            if v2_authority_revoked(&response) {
                return Err(StoreError::TopologyAuthorityRevoked);
            }
            match response {
                Ok(SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
                    capability @ FencedTransitionV2Capability::V2,
                ))) => Ok(capability),
                Ok(SessionConsumerV2Response::FencedTransitionV2Capability(_)) => {
                    Err(StoreError::CapabilityNotSupported(
                        "atomic_fenced_transition_epoch_history_v2".into(),
                    ))
                }
                _ => Err(prepared_fenced_v2_readiness_unavailable()),
            }
        }))
        .await;
        for proof in capabilities {
            proof?;
        }
        let capability = FencedTransitionV2Capability::V2;

        // The client configuration is immutable, but read it again after the
        // fan-out so a semantic authority change cannot race activation.
        if voters
            .iter()
            .map(persistent_fenced_transition_voter_readiness)
            .collect::<Option<Vec<_>>>()
            .as_deref()
            != Some(readiness.as_slice())
        {
            return Err(prepared_fenced_v2_readiness_unavailable());
        }
        let mut clients = voters;
        clients.sort_unstable_by_key(|client| client.pool.client.voter.node_id());
        let router = PreparedConsumerRouter::persistent(clients)
            .map_err(|_| prepared_fenced_v2_readiness_unavailable())?;
        // Prime the facade's active-epoch cache off the request hot path. A
        // revoked authority refuses activation like the capability proof; any
        // other failed read only defers the read to the first preparation.
        let priming_timeout = router
            .clients
            .iter()
            .map(|client| {
                effective_consumer_operation_timeout(client.pool.client.operation_timeout)
            })
            .min()
            .ok_or_else(prepared_fenced_v2_readiness_unavailable)?;
        let read_deadline = tokio::time::Instant::now()
            .checked_add(priming_timeout)
            .unwrap_or_else(tokio::time::Instant::now);
        let read_budget = PreparedCheckpointBudget::new(
            read_deadline,
            opc_session_store::PREPARED_CHECKPOINT_MAX_PHYSICAL_ATTEMPT,
        )
        .map_err(|_| prepared_fenced_v2_readiness_unavailable())?;
        let history = match linearized_v2_history_state(
            &router,
            0,
            read_budget,
            V2HistoryRead::Fresh,
        )
        .await
        {
            Ok(state) => Some(state),
            Err(StoreError::TopologyAuthorityRevoked) => {
                return Err(StoreError::TopologyAuthorityRevoked);
            }
            Err(_) => None,
        };
        Ok(ActivatedSessionConsumerFencedTransitionV2Voters {
            capability,
            router: Arc::new(router),
            history,
        })
    }

    /// Construct the local-AEAD protected V2 facade from one opaque activated
    /// roster and the consumer's provisioned recovery journal.
    pub fn persistent_encrypting<P>(
        voters: ActivatedSessionConsumerFencedTransitionV2Voters,
        provider: Arc<P>,
        backend_namespace: impl Into<String>,
        journal: Arc<FencedTransitionV2RecoveryJournal>,
    ) -> Result<Self, SessionConsumerPreparedFencedTransitionV2BackendError>
    where
        P: KeyProvider + Send + Sync + 'static + ?Sized,
    {
        let scope = prepared_fenced_v2_recovery_scope(&voters.router)?;
        Ok(Self {
            capability: voters.capability,
            router: voters.router,
            wrapper_factory: Arc::new(LocalAeadPreparedFencedTransitionV2Wrapper {
                provider,
                backend_namespace: Arc::from(backend_namespace.into()),
                journal,
                scope,
                legacy_journal: None,
            }),
            legacy_v1: None,
            history: Arc::new(PreparedFencedV2HistoryCache::primed(voters.history)),
            reclaim_cursor: StdMutex::new(None),
        })
    }

    /// Construct the remote-seal protected V2 facade from one opaque
    /// activated roster and the consumer's provisioned recovery journal.
    pub fn persistent_remote_sealing<S>(
        voters: ActivatedSessionConsumerFencedTransitionV2Voters,
        provider: Arc<S>,
        backend_namespace: impl Into<String>,
        journal: Arc<FencedTransitionV2RecoveryJournal>,
    ) -> Result<Self, SessionConsumerPreparedFencedTransitionV2BackendError>
    where
        S: RemoteSealProvider + Send + Sync + 'static + ?Sized,
    {
        let scope = prepared_fenced_v2_recovery_scope(&voters.router)?;
        Ok(Self {
            capability: voters.capability,
            router: voters.router,
            wrapper_factory: Arc::new(RemoteSealPreparedFencedTransitionV2Wrapper {
                provider,
                backend_namespace: Arc::from(backend_namespace.into()),
                journal,
                scope,
                legacy_journal: None,
            }),
            legacy_v1: None,
            history: Arc::new(PreparedFencedV2HistoryCache::primed(voters.history)),
            reclaim_cursor: StdMutex::new(None),
        })
    }

    /// Compose an existing V1 facade for the same scope so its retained
    /// transitions stay status-recoverable after the upgrade.
    ///
    /// The V1 facade is consumed, so this process can no longer prepare V1
    /// transitions through it. V2 preparation then rejects every ID its
    /// journal retains, and [`Self::recover_fenced_transition_status`]
    /// returns [`SessionConsumerRecoveredFencedTransition::LegacyV1`] for it.
    pub fn with_legacy_v1_recovery(
        mut self,
        legacy: SessionConsumerPreparedFencedTransitionBackend,
    ) -> Result<Self, SessionConsumerPreparedFencedTransitionV2BackendError> {
        if self.legacy_v1.is_some() || legacy.router.scope != self.router.scope {
            return Err(SessionConsumerPreparedFencedTransitionV2BackendError);
        }
        self.wrapper_factory = self
            .wrapper_factory
            .with_legacy_journal(legacy.wrapper_factory.journal());
        self.legacy_v1 = Some(legacy);
        Ok(self)
    }

    fn handle_routing(
        &self,
        route: Arc<PreparedFencedTransitionV2Route>,
    ) -> PreparedFencedV2HandleRouting {
        PreparedFencedV2HandleRouting {
            voter_count: self.router.clients.len(),
            route,
            history: Arc::clone(&self.history),
        }
    }

    fn backend_for_route_with_journal_class(
        &self,
        route: Arc<PreparedFencedTransitionV2Route>,
        budget: PreparedCheckpointBudget,
        history_read: V2HistoryRead,
        class: ScopeWorkClass,
    ) -> Arc<dyn ProtectedFencedTransitionV2Backend> {
        self.wrapper_factory.wrap(
            Arc::new(ActivatedFencedTransitionV2Backend {
                capability: self.capability,
                router: Arc::clone(&self.router),
                route,
                history: Arc::clone(&self.history),
                history_read,
                deadline: budget.original_deadline(),
                attempt_timeout: budget.physical_attempt_timeout(),
            }),
            class,
        )
    }

    fn local_backend_with_journal_class(
        &self,
        deadline: tokio::time::Instant,
        class: ScopeWorkClass,
    ) -> Arc<dyn ProtectedFencedTransitionV2Backend> {
        // Journal-only and observation work never reaches a V2 mutation, so
        // one bounded default operation window is sufficient here.
        self.wrapper_factory.wrap(
            Arc::new(ActivatedFencedTransitionV2Backend {
                capability: self.capability,
                router: Arc::clone(&self.router),
                route: Arc::new(PreparedFencedTransitionV2Route::new(0)),
                history: Arc::clone(&self.history),
                history_read: V2HistoryRead::Cached,
                deadline,
                attempt_timeout: DEFAULT_CONSUMER_OPERATION_TIMEOUT,
            }),
            class,
        )
    }

    /// Read the current record head and durable fence floor for one exact key
    /// and return a present record in caller-visible unprotected form.
    ///
    /// This uses the existing exact-key observation operation and adds no
    /// raw backend, prepared request, or dispatch authority. The full call,
    /// including its local journal waits, uses the existing ten-second default
    /// consumer operation window.
    pub async fn observe_fenced_transition(
        &self,
        key: &opc_session_store::SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        self.observe_fenced_transition_with_journal_class(
            key,
            self.wrapper_factory.journal().operation_class(),
        )
        .await
    }

    /// Observe with the current operation's authenticated local journal class.
    /// The class applies to local scope authentication only; remote reads and
    /// unprotection hold no journal priority. The default window is unchanged.
    pub async fn observe_fenced_transition_with_journal_class(
        &self,
        key: &opc_session_store::SessionKey,
        class: ScopeWorkClass,
    ) -> Result<FencedTransitionObservation, StoreError> {
        let deadline = default_fenced_v2_operation_deadline();
        journal_before_deadline(
            deadline,
            self.local_backend_with_journal_class(deadline, class)
                .observe_protected_fenced_transition_v2(key),
        )
        .await
        .map_err(|_| prepared_fenced_v2_deadline())?
    }

    /// Prepare one protected V2 transition and retain it in a move-only,
    /// affine dispatch handle.
    ///
    /// The wrapper selects the linearized active epoch, seals a create or
    /// update record once, and durably binds `request.request_id()` to the
    /// complete sealed request before this returns. A retained caller ID,
    /// including one retained by a composed legacy V1 journal, is a conflict;
    /// a full recovery journal or full active epoch is
    /// `FencedTransitionHistoryFull`. The configured journal view supplies
    /// the default work class; newly opened journals use `Normal`.
    pub async fn prepare_fenced_transition(
        &self,
        request: FencedTransitionRequest,
        budget: PreparedCheckpointBudget,
    ) -> Result<SessionConsumerPreparedFencedTransitionV2, StoreError> {
        self.prepare_fenced_transition_with_journal_class(
            request,
            budget,
            self.wrapper_factory.journal().operation_class(),
        )
        .await
    }

    /// Prepare with an explicit local recovery-journal scheduling class.
    ///
    /// The caller chooses [`ScopeWorkClass`] from authenticated operation and
    /// session state. Its existing rank orders the local journal's FIFO class
    /// heads. Each consecutive local journal sequence retains registration,
    /// preventing lower-class operations from interleaving within it. Remote
    /// I/O, sealing and backoff hold no journal priority. Higher classes may
    /// still precede local work; already admitted blocking work finishes.
    /// The returned handle retains the class for later active calls, without
    /// holding priority while idle. Class selection changes no authority,
    /// remote-voter scheduling or class budget; a composed legacy V1 journal
    /// keeps its existing scheduling.
    /// Cancelling a call removes its registration. Already admitted blocking
    /// work finishes under the existing journal progress budget.
    pub async fn prepare_fenced_transition_with_journal_class(
        &self,
        request: FencedTransitionRequest,
        budget: PreparedCheckpointBudget,
        class: ScopeWorkClass,
    ) -> Result<SessionConsumerPreparedFencedTransitionV2, StoreError> {
        let deadline = budget.original_deadline();
        if tokio::time::Instant::now() >= deadline {
            return Err(prepared_fenced_v2_deadline());
        }
        let route = Arc::new(PreparedFencedTransitionV2Route::new(
            prepared_fenced_v2_origin(&self.router, request.request_id()),
        ));
        let backend = self.backend_for_route_with_journal_class(
            Arc::clone(&route),
            budget,
            V2HistoryRead::Cached,
            class,
        );
        let (prepared, call) = journal_before_deadline(
            deadline,
            backend.prepare_protected_fenced_transition_v2_with_call(request, deadline),
        )
        .await
        .map_err(|_| prepared_fenced_v2_deadline())??;
        Ok(SessionConsumerPreparedFencedTransitionV2 {
            inner: PersistentPreparedFencedTransitionV2Token::new(
                backend,
                prepared,
                budget,
                self.handle_routing(route),
                PreparedRequestState::new(0),
                true,
            )
            .with_call(call),
        })
    }

    /// Reopen a retained transition by its caller-stable ID as a
    /// receipt-only handle.
    ///
    /// This is a local journal lookup: it needs neither the plaintext body
    /// nor a key provider, and it never restores dispatch authority. `None`
    /// means neither this facade's recovery journal nor a composed legacy V1
    /// journal retains the ID: it was never prepared through them, or its row
    /// was released or reclaimed after resolution. This uses the configured
    /// journal view's work class, `Normal` for a newly opened journal.
    pub async fn recover_fenced_transition_status(
        &self,
        request_id: FencedTransitionRequestId,
        budget: PreparedCheckpointBudget,
    ) -> Result<Option<SessionConsumerRecoveredFencedTransition>, StoreError> {
        self.recover_fenced_transition_status_with_journal_class(
            request_id,
            budget,
            self.wrapper_factory.journal().operation_class(),
        )
        .await
    }

    /// Recover receipt authority with an explicit V2 recovery-journal class.
    ///
    /// This has the same scheduling and cancellation contract as
    /// [`Self::prepare_fenced_transition_with_journal_class`]. The recovered
    /// V2 handle retains the class, without acquiring dispatch authority.
    /// A composed legacy V1 journal keeps its existing scheduling behavior.
    pub async fn recover_fenced_transition_status_with_journal_class(
        &self,
        request_id: FencedTransitionRequestId,
        budget: PreparedCheckpointBudget,
        class: ScopeWorkClass,
    ) -> Result<Option<SessionConsumerRecoveredFencedTransition>, StoreError> {
        let journal = self.wrapper_factory.journal().with_operation_class(class);
        let deadline = budget.original_deadline();
        if tokio::time::Instant::now() >= deadline {
            return Err(prepared_fenced_v2_deadline());
        }
        let route = Arc::new(PreparedFencedTransitionV2Route::new(
            prepared_fenced_v2_origin(&self.router, request_id),
        ));
        let backend = self.backend_for_route_with_journal_class(
            Arc::clone(&route),
            budget,
            V2HistoryRead::Cached,
            class,
        );
        journal_before_deadline(deadline, async {
            let _priority = journal.retain_call_priority();
            let (retained, notice) = backend
                .recover_protected_fenced_transition_v2_with_notice(request_id)
                .await?;
            let legacy = match &self.legacy_v1 {
                Some(legacy) => {
                    legacy
                        .recover_fenced_transition_status(request_id, budget)
                        .await?
                }
                None => None,
            };
            match (retained, legacy) {
                (PreparedFencedTransitionV2Lookup::Found(prepared), None) => {
                    let state = PreparedRequestState::new(0);
                    state.receipt_only();
                    Ok(Some(SessionConsumerRecoveredFencedTransition::V2(
                        SessionConsumerRecoveredFencedTransitionV2Status {
                            inner: PersistentPreparedFencedTransitionV2Token::new(
                                Arc::clone(&backend),
                                prepared,
                                budget,
                                self.handle_routing(Arc::clone(&route)),
                                state,
                                false,
                            )
                            .with_recovery_notice(notice),
                        },
                    )))
                }
                // One caller-stable ID names one logical operation. A binding
                // in both journals is corrupt state and fails closed.
                (PreparedFencedTransitionV2Lookup::Found(_), Some(_)) => {
                    Err(StoreError::FencedTransitionRequestConflict)
                }
                (PreparedFencedTransitionV2Lookup::Absent, Some(legacy)) => Ok(Some(
                    SessionConsumerRecoveredFencedTransition::LegacyV1(legacy),
                )),
                (PreparedFencedTransitionV2Lookup::Absent, None) => Ok(None),
                _ => Err(invalid_authenticated_consumer_fenced_transition()),
            }
        })
        .await
        .map_err(|_| prepared_fenced_v2_deadline())?
    }

    /// Resume the original sealed request only after a fresh authoritative
    /// `LeaseDeferred` status for its complete identity.
    ///
    /// This reads and authenticates the retained row; it never prepares a new
    /// request, calls a key provider, changes epoch, or inserts a journal row.
    /// `None` grants no dispatch authority: the row was absent or the observed
    /// status was not a deferral. In particular, `NotFound`, an unavailable
    /// read, and an unknown outcome cannot authorize a retry. Keep using status
    /// recovery for those outcomes. Every resumed attempt has a new caller
    /// budget and must pass the current consumer admission before dispatch.
    /// The returned handle cannot abandon the already-bound request.
    /// An owned journal also requires the previous call to have returned a
    /// known deferral, ended, or reached its deadline; drop an unknown handle
    /// before resuming after a later authoritative deferral observation.
    /// This uses the configured journal view's work class. Use the explicit
    /// class variant when resuming work classified per call.
    pub async fn resume_deferred_fenced_transition(
        &self,
        request_id: FencedTransitionRequestId,
        budget: PreparedCheckpointBudget,
    ) -> Result<Option<SessionConsumerPreparedFencedTransitionV2>, StoreError> {
        self.resume_deferred_fenced_transition_with_journal_class(
            request_id,
            budget,
            self.wrapper_factory.journal().operation_class(),
        )
        .await
    }

    /// Resume a deferred transition with an explicit recovery-journal class.
    ///
    /// The caller supplies its current authenticated work class. Every local
    /// journal step and the resumed handle retain it, including deferred-call
    /// registration. The class does not change receipt or dispatch authority.
    pub async fn resume_deferred_fenced_transition_with_journal_class(
        &self,
        request_id: FencedTransitionRequestId,
        budget: PreparedCheckpointBudget,
        class: ScopeWorkClass,
    ) -> Result<Option<SessionConsumerPreparedFencedTransitionV2>, StoreError> {
        let journal = self.wrapper_factory.journal().with_operation_class(class);
        let deadline = budget.original_deadline();
        if tokio::time::Instant::now() >= deadline {
            return Err(prepared_fenced_v2_deadline());
        }
        let route = Arc::new(PreparedFencedTransitionV2Route::new(
            prepared_fenced_v2_origin(&self.router, request_id),
        ));
        let backend = self.backend_for_route_with_journal_class(
            Arc::clone(&route),
            budget,
            V2HistoryRead::Fresh,
            class,
        );
        journal_before_deadline(deadline, async {
            let priority = journal.retain_call_priority();
            let prepared = match backend
                .recover_protected_fenced_transition_v2(request_id)
                .await?
            {
                PreparedFencedTransitionV2Lookup::Found(prepared) => prepared,
                PreparedFencedTransitionV2Lookup::Absent => return Ok(None),
                _ => return Err(invalid_authenticated_consumer_fenced_transition()),
            };
            if let Some(legacy) = &self.legacy_v1 {
                if legacy
                    .recover_fenced_transition_status(request_id, budget)
                    .await?
                    .is_some()
                {
                    return Err(StoreError::FencedTransitionRequestConflict);
                }
            }
            drop(priority);
            for _ in 0..self.router.clients.len() {
                if tokio::time::Instant::now() >= deadline {
                    return Err(prepared_fenced_v2_deadline());
                }
                route.install_attempt_deadline(deadline);
                match journal_before_deadline(
                    deadline,
                    backend.protected_fenced_transition_v2_status(&prepared),
                )
                .await
                {
                    Ok(Ok(FencedTransitionV2Status::LeaseDeferred { .. })) => {
                        // The protected wrapper and wire client both compare
                        // the complete ID with the authenticated sealed body.
                        let call = journal.begin_deferred_call(&prepared, deadline).await?;
                        return Ok(Some(SessionConsumerPreparedFencedTransitionV2 {
                            inner: PersistentPreparedFencedTransitionV2Token::new(
                                Arc::clone(&backend),
                                prepared,
                                budget,
                                self.handle_routing(Arc::clone(&route)),
                                PreparedRequestState::new(0),
                                false,
                            )
                            .with_call(call),
                        }));
                    }
                    Ok(Ok(_)) => return Ok(None),
                    Ok(Err(StoreError::TopologyAuthorityRevoked)) => {
                        return Err(StoreError::TopologyAuthorityRevoked);
                    }
                    Ok(Err(_)) | Err(_) => {}
                }
            }
            Err(StoreError::BackendUnavailable(
                PREPARED_FENCED_V2_RECEIPT_UNAVAILABLE.into(),
            ))
        })
        .await
        .map_err(|_| prepared_fenced_v2_deadline())?
    }

    /// Run one bounded reclamation sweep over retained rows.
    ///
    /// It first reads the linearized history state once and removes rows at
    /// or below its retired floor without further I/O. It then reads the
    /// exact status of at most `limit` rows in caller-ID order from a
    /// process-local cursor and removes those whose status is `Expired`,
    /// `Retired`, `HistoryFull`, `RetentionExhausted`, or `EpochNotActive`
    /// for an epoch below the active epoch. A row's read-only status moves
    /// to the next canonical voter after the bounded physical-attempt wait,
    /// including when a voter accepts the read and never replies. These
    /// background attempts share the sweep's original absolute deadline.
    /// The sweep stops
    /// as interrupted when every voter failed for one row, when a local
    /// journal read or removal fails, or at the budget's deadline. `limit`
    /// must be in
    /// `1..=FENCED_TRANSITION_V2_RECOVERY_RECLAIM_BATCH_MAX`.
    ///
    /// For an exclusively owned journal, exact `NotFound` or `LeaseDeferred`
    /// permits one void attempt after a known return, cancellation, drop, or
    /// the original in-memory deadline. An unknown attempt return continues to wait for
    /// that deadline. Inherited and unregistered rows are immediately eligible,
    /// including inherited deferrals. To continue an inherited deferral, call
    /// `resume_deferred_fenced_transition` before running this sweep; the sweep
    /// can otherwise void it. Store-side pending expiry also makes abandoned
    /// deferrals reclaimable when no caller journal survives.
    /// A reachable voter proves the separately admitted immutable void profile.
    /// Waiting callers and unsupported peers retain the row and are counted
    /// in the report. An unavailable or unknown void advances past the retained
    /// row and suppresses further void attempts for this pass; status work
    /// continues and a later pass retries after the cursor wraps.
    /// An exact terminal void receipt removes the row and remains observable
    /// by live or recovered handles. An original success remains retained
    /// for its caller to observe and release. `RequestConflict` stays retained.
    /// No deadline is persisted, and ordinary journals retain `NotFound` rows.
    ///
    /// The caller owns scheduling. Epoch rotation and retired-floor
    /// advancement remain the state process's replicated maintenance.
    pub async fn reclaim_resolved_fenced_transitions(
        &self,
        limit: usize,
        budget: PreparedCheckpointBudget,
    ) -> Result<SessionConsumerFencedTransitionV2ReclaimReport, StoreError> {
        self.reclaim_resolved_fenced_transitions_with_journal_class(
            limit,
            budget,
            self.wrapper_factory.journal().operation_class(),
        )
        .await
    }

    /// Reclaim with an explicit local journal class, typically `Maintenance`.
    /// Each consecutive local sequence retains this class; remote history,
    /// receipt and void requests hold no journal priority. The original sweep
    /// and physical-attempt budgets remain unchanged.
    pub async fn reclaim_resolved_fenced_transitions_with_journal_class(
        &self,
        limit: usize,
        budget: PreparedCheckpointBudget,
        class: ScopeWorkClass,
    ) -> Result<SessionConsumerFencedTransitionV2ReclaimReport, StoreError> {
        if limit == 0 || limit > FENCED_TRANSITION_V2_RECOVERY_RECLAIM_BATCH_MAX {
            return Err(StoreError::InvalidKey(
                PREPARED_FENCED_V2_RECLAIM_LIMIT_INVALID.into(),
            ));
        }
        let deadline = budget.original_deadline();
        if tokio::time::Instant::now() >= deadline {
            return Err(prepared_fenced_v2_deadline());
        }
        let route = Arc::new(PreparedFencedTransitionV2Route::new(0));
        let backend = self.backend_for_route_with_journal_class(
            Arc::clone(&route),
            budget,
            V2HistoryRead::Maintenance,
            class,
        );
        // One linearized history read supplies both the retired floor, which
        // the wrapper applies itself, and the active epoch used below.
        let (history, retired) = journal_before_deadline(
            deadline,
            backend.reclaim_retired_protected_fenced_transitions_v2(limit),
        )
        .await
        .map_err(|_| prepared_fenced_v2_deadline())??;
        let mut report = SessionConsumerFencedTransitionV2ReclaimReport {
            reclaimed: retired,
            ..SessionConsumerFencedTransitionV2ReclaimReport::default()
        };
        let remaining = limit.saturating_sub(report.reclaimed);
        if remaining == 0 {
            return Ok(report);
        }
        let cursor = *self
            .reclaim_cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let page = journal_before_deadline(
            deadline,
            backend.protected_fenced_transition_v2_page(cursor, remaining),
        )
        .await
        .map_err(|_| prepared_fenced_v2_deadline())??;
        let mut next_cursor = cursor;
        let wrapped = page.len() < remaining;
        let voter_count = self.router.clients.len();
        let mut attempt_void = true;
        let mut void_unsupported = false;
        for (request_id, history_epoch) in page {
            let Some(attempt_deadline) = reclaim_attempt_deadline(&budget, deadline) else {
                report.interrupted = true;
                break;
            };
            let prepared = match journal_before_deadline(
                attempt_deadline,
                backend.recover_protected_fenced_transition_v2(request_id),
            )
            .await
            {
                Ok(Ok(PreparedFencedTransitionV2Lookup::Found(prepared))) => prepared,
                // A row removed concurrently (for example by a release) is
                // already reclaimed; move past it.
                Ok(Ok(_)) => {
                    next_cursor = Some(request_id);
                    continue;
                }
                Ok(Err(_)) | Err(_) => {
                    report.interrupted = true;
                    break;
                }
            };
            // Background maintenance retains a bounded wait for each voter,
            // including one that accepts a read and never replies. All
            // attempts remain within the original sweep deadline.
            let mut status = None;
            for _ in 0..voter_count {
                let Some(attempt_deadline) = reclaim_attempt_deadline(&budget, deadline) else {
                    break;
                };
                route.install_attempt_deadline(attempt_deadline);
                match journal_before_deadline(
                    attempt_deadline,
                    backend.protected_fenced_transition_v2_status(&prepared),
                )
                .await
                {
                    Ok(Ok(observed)) => {
                        status = Some(observed);
                        break;
                    }
                    Ok(Err(StoreError::TopologyAuthorityRevoked)) => {
                        return Err(StoreError::TopologyAuthorityRevoked);
                    }
                    Ok(Err(_)) | Err(_) => {}
                }
            }
            let mut observed = match status {
                Some(status) => status,
                _ => {
                    report.interrupted = true;
                    break;
                }
            };
            let mut void_result = false;
            if matches!(
                observed,
                FencedTransitionV2Status::NotFound | FencedTransitionV2Status::LeaseDeferred { .. }
            ) {
                match backend.protected_fenced_transition_v2_void_eligibility(&prepared) {
                    opc_session_store::FencedTransitionV2VoidEligibility::Ready if attempt_void => {
                        let Some(attempt_deadline) = reclaim_attempt_deadline(&budget, deadline)
                        else {
                            report.interrupted = true;
                            break;
                        };
                        route.install_attempt_deadline(attempt_deadline);
                        match journal_before_deadline(
                            attempt_deadline,
                            backend.protected_fenced_transition_v2_void(&prepared),
                        )
                        .await
                        {
                            Ok(Ok(status)) => {
                                observed = status;
                                void_result = true;
                            }
                            Ok(Err(StoreError::CapabilityNotSupported(_))) => {
                                report.unsupported += 1;
                                attempt_void = false;
                                void_unsupported = true;
                            }
                            Ok(Err(StoreError::TopologyAuthorityRevoked)) => {
                                return Err(StoreError::TopologyAuthorityRevoked)
                            }
                            _ => {
                                // Neither an unavailable probe nor an unknown
                                // void is a receipt. Keep this row, but continue
                                // status work and advance past it for this pass.
                                attempt_void = false;
                            }
                        }
                    }
                    opc_session_store::FencedTransitionV2VoidEligibility::Ready => {
                        if void_unsupported {
                            report.unsupported += 1;
                        }
                    }
                    opc_session_store::FencedTransitionV2VoidEligibility::WaitingCaller => {
                        report.waiting_callers += 1
                    }
                    _ => report.unsupported += 1,
                }
            }
            let reclaimable = match &observed {
                FencedTransitionV2Status::Recorded(result)
                    if matches!(result.as_ref(), Err(StoreError::FencedTransitionVoided)) =>
                {
                    report.voided += 1;
                    true
                }
                // A void can also replay a prior deterministic rejection or
                // bind its own original authority/fence rejection. Either is
                // an exact no-effect receipt; successful originals stay retained.
                FencedTransitionV2Status::Recorded(result) if void_result && result.is_err() => {
                    true
                }
                FencedTransitionV2Status::Expired
                | FencedTransitionV2Status::Retired
                | FencedTransitionV2Status::HistoryFull
                | FencedTransitionV2Status::RetentionExhausted => true,
                FencedTransitionV2Status::EpochNotActive => history
                    .active_epoch()
                    .is_some_and(|active| history_epoch < active),
                _ => false,
            };
            report.examined += 1;
            if reclaimable {
                if tokio::time::Instant::now() >= deadline {
                    report.interrupted = true;
                    break;
                }
                match journal_before_deadline(
                    deadline,
                    backend.discard_protected_fenced_transition_v2(&prepared),
                )
                .await
                {
                    Ok(Ok(_)) => report.reclaimed += 1,
                    Ok(Err(_)) | Err(_) => {
                        report.interrupted = true;
                        break;
                    }
                }
            } else {
                report.retained += 1;
            }
            next_cursor = Some(request_id);
        }
        *self
            .reclaim_cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = if wrapped && !report.interrupted
        {
            None
        } else {
            next_cursor
        };
        Ok(report)
    }

    /// Return the authenticated number of retained recovery-journal rows.
    ///
    /// The value is a fixed count only; it never exceeds
    /// `FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES`. Journal waits use
    /// the existing ten-second default consumer operation window. This uses
    /// the configured journal view's class, `Normal` for a newly opened journal.
    pub async fn retained_fenced_transitions(&self) -> Result<usize, StoreError> {
        self.retained_fenced_transitions_with_journal_class(
            self.wrapper_factory.journal().operation_class(),
        )
        .await
    }

    /// Return the authenticated retained-row count for a selected journal class.
    ///
    /// An inventory read made while preparing or retrying work can use that
    /// work's authenticated class, so it does not queue behind lower-ranked
    /// operations. The local scope-binding and count sequence retains its
    /// registration. Cancelling a queued call releases its place; already
    /// admitted blocking work retains its progress budget and permit lifetime.
    /// The read keeps the existing ten-second default operation window and
    /// grants no mutation, dispatch or recovery authority.
    pub async fn retained_fenced_transitions_with_journal_class(
        &self,
        class: ScopeWorkClass,
    ) -> Result<usize, StoreError> {
        let deadline = default_fenced_v2_operation_deadline();
        journal_before_deadline(
            deadline,
            self.local_backend_with_journal_class(deadline, class)
                .retained_protected_fenced_transitions_v2(),
        )
        .await
        .map_err(|_| prepared_fenced_v2_deadline())?
    }
}

/// One reclamation attempt's deadline: the budget's physical-attempt cap,
/// bounded by the sweep's absolute deadline. `None` once that has elapsed.
fn reclaim_attempt_deadline(
    budget: &PreparedCheckpointBudget,
    deadline: tokio::time::Instant,
) -> Option<tokio::time::Instant> {
    let now = tokio::time::Instant::now();
    let attempt_deadline = now
        .checked_add(budget.physical_attempt_timeout())
        .map_or(deadline, |capped| capped.min(deadline));
    (attempt_deadline > now).then_some(attempt_deadline)
}

/// Resolution the handle observed through this facade.
#[derive(Clone, Copy, PartialEq, Eq)]
enum V2Resolution {
    Unresolved,
    Resolved,
    Released,
}

/// Affine dispatch authority for one exact protected V2 transition.
///
/// It is intentionally not cloneable and does not expose its retained
/// request.
///
/// ```compile_fail
/// use opc_session_net::SessionConsumerPreparedFencedTransitionV2;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<SessionConsumerPreparedFencedTransitionV2>();
/// ```
pub struct SessionConsumerPreparedFencedTransitionV2 {
    inner: PersistentPreparedFencedTransitionV2Token,
}

impl fmt::Debug for SessionConsumerPreparedFencedTransitionV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerPreparedFencedTransitionV2(<redacted>)")
    }
}

impl SessionConsumerPreparedFencedTransitionV2 {
    /// Caller-stable identity that recovers this transition after restart.
    pub fn request_id(&self) -> FencedTransitionRequestId {
        self.inner.prepared.request_id()
    }

    /// Abandon a request before `execute_once` has ever been polled.
    ///
    /// This permanently consumes dispatch authority before awaiting local
    /// compare-and-delete of the exact retained row. It performs no network
    /// I/O. Cancellation or a journal failure leaves dispatch disabled; retry
    /// this method on the same handle to finish deletion. Successful retries
    /// are no-ops. Once execution has started, even if cancelled before a
    /// physical call, abandonment is refused and the existing execution and
    /// receipt rules apply. Recovered status-only handles have no such method.
    pub async fn abandon_unexecuted(
        &mut self,
    ) -> Result<(), SessionConsumerFencedTransitionV2AbandonError> {
        self.inner.abandon_unexecuted().await
    }

    /// Dispatch the retained mutation once.
    ///
    /// A possible send permanently removes dispatch authority and returns
    /// `OutcomeUnknown` with the caller-stable ID; use receipt status only
    /// afterwards. When an original handle fails preflight, every candidate
    /// voter proves a pre-dispatch failure, topology authority is revoked
    /// before any Call byte, or the V2 history definitively rejects the
    /// request without binding it, this handle removes its own retained row
    /// within the original caller deadline. If expiry prevents cleanup, the
    /// handle remains resolved and cannot dispatch again; the existing
    /// scheduled reclamation completes cleanup under its maintenance budget.
    /// A resumed deferred request retains its earlier binding and status
    /// recovery when the current attempt fails preflight.
    ///
    /// If local removal fails or is cancelled, the original handle stays
    /// resolved and `release_resolved` retries it. This no-effect decision is
    /// not persisted separately: a crash before deletion commits leaves an
    /// ordinary unresolved row, recovered through status only. An owned
    /// journal with the void profile can settle that row through a terminal
    /// void receipt; otherwise the existing epoch lifecycle applies. The
    /// missing in-memory decision never authorizes deletion after restart.
    pub async fn execute_once(
        &mut self,
    ) -> Result<FencedTransitionOutcome, FencedTransitionExecuteError> {
        self.inner.execute_once().await
    }

    /// Dispatch the retained mutation once and report a value-free failure
    /// diagnostic for an ambiguous transport result.
    ///
    /// This performs exactly the same operation as [`Self::execute_once`]:
    /// effect classification, dispatch authority and ownership are unchanged,
    /// and [`SessionConsumerPreparedFencedTransitionV2Failure::into_error`]
    /// yields precisely the error `execute_once` would have returned. The
    /// attached diagnostic explains the failure stage that the effect
    /// classification cannot distinguish: a cold setup that never dispatched,
    /// an admitted attempt that wrote nothing, a request whose reply was still
    /// outstanding when the physical attempt budget expired, or a reply path
    /// that ended without an exact completion. It contains only those closed
    /// labels and the remaining original budget in milliseconds; it never
    /// carries a value, request ID, identity, scope, endpoint, owner, fence,
    /// credential, key or payload byte. A resolved rejection or lease deferral
    /// carries no diagnostic.
    pub async fn execute_once_with_failure_diagnostic(
        &mut self,
    ) -> Result<FencedTransitionOutcome, SessionConsumerPreparedFencedTransitionV2Failure> {
        match self.inner.execute_once().await {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                let ambiguous = matches!(
                    &error,
                    FencedTransitionExecuteError::NotTransmitted
                        | FencedTransitionExecuteError::OutcomeUnknown { .. }
                );
                let diagnostic = if ambiguous {
                    self.inner.failure_diagnostic()
                } else {
                    None
                };
                Err(SessionConsumerPreparedFencedTransitionV2Failure { error, diagnostic })
            }
        }
    }

    /// Try one read-only receipt lookup on the next deterministic voter.
    pub async fn status_once(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError> {
        self.inner.status_once(deadline).await
    }

    /// Rotate read-only receipt lookups over the roster until a terminal
    /// status is found or the caller's absolute deadline is reached. It never
    /// re-enters mutation dispatch.
    /// A correlated `LeaseDeferred` also returns immediately, remains
    /// nonterminal, and keeps the row for explicit deferral resumption.
    ///
    /// A retained row that is missing or fails authentication is a local
    /// fail-closed condition: `Unavailable` is then returned at once and is
    /// final for this handle. `recover_fenced_transition_status` reports
    /// whether the caller ID is still retained.
    pub async fn status_until_terminal(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError> {
        self.inner.status_until_terminal(deadline).await
    }

    /// Remove the retained row after this handle observed a resolution.
    ///
    /// A matching outcome, any execution result that proved the request was
    /// never sent or never bound (see `execute_once`), any other definitive
    /// rejection except `RequestConflict`, or a terminal status other than
    /// `RequestConflict` permits release. Afterwards the caller-stable ID is
    /// no longer retained: recovery returns `None`, and the ID may name a new
    /// transition. An `abandon_unexecuted` call that failed or was cancelled
    /// also permits release. Callers must derive later work from authoritative
    /// observation. Releasing twice is a no-op. Each cleanup call has the
    /// existing ten-second default operation window, so it can be retried
    /// after the execution budget expires. Timeout leaves the row releasable.
    pub async fn release_resolved(
        &mut self,
    ) -> Result<(), SessionConsumerFencedTransitionV2ReleaseError> {
        self.inner.release_resolved().await
    }
}

/// A reopened protected V2 transition with receipt authority only.
///
/// It deliberately has no `execute_once` method, so a restarted caller can
/// never replay a mutation that may already have been sent.
///
/// ```compile_fail
/// use opc_session_net::SessionConsumerRecoveredFencedTransitionV2Status;
///
/// async fn cannot_replay(recovered: &mut SessionConsumerRecoveredFencedTransitionV2Status) {
///     let _ = recovered.execute_once().await;
/// }
/// ```
///
/// ```compile_fail
/// use opc_session_net::SessionConsumerRecoveredFencedTransitionV2Status;
///
/// async fn cannot_abandon(recovered: &mut SessionConsumerRecoveredFencedTransitionV2Status) {
///     let _ = recovered.abandon_unexecuted().await;
/// }
/// ```
pub struct SessionConsumerRecoveredFencedTransitionV2Status {
    inner: PersistentPreparedFencedTransitionV2Token,
}

impl fmt::Debug for SessionConsumerRecoveredFencedTransitionV2Status {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRecoveredFencedTransitionV2Status(<redacted>)")
    }
}

impl SessionConsumerRecoveredFencedTransitionV2Status {
    /// Caller-stable identity of the recovered transition.
    pub fn request_id(&self) -> FencedTransitionRequestId {
        self.inner.prepared.request_id()
    }

    /// Try one read-only receipt lookup on the next deterministic voter.
    pub async fn status_once(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError> {
        self.inner.status_once(deadline).await
    }

    /// Rotate read-only receipt lookups until a terminal status is found or
    /// the caller's absolute deadline is reached. As for a live handle, a
    /// local row failure returns `Unavailable` at once and is final for this
    /// handle.
    /// `LeaseDeferred` returns immediately without making the row releasable;
    /// only the facade's explicit deferral resume method can restore dispatch.
    pub async fn status_until_terminal(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError> {
        self.inner.status_until_terminal(deadline).await
    }

    /// Remove the retained row after a terminal status other than
    /// `RequestConflict`; see
    /// [`SessionConsumerPreparedFencedTransitionV2::release_resolved`].
    pub async fn release_resolved(
        &mut self,
    ) -> Result<(), SessionConsumerFencedTransitionV2ReleaseError> {
        self.inner.release_resolved().await
    }
}

const V2_DISPATCH_UNUSED: u8 = 0;
const V2_EXECUTION_STARTED: u8 = 1;
const V2_DISPATCH_ABANDONED: u8 = 2;

struct PersistentPreparedFencedTransitionV2Token {
    recovery_call: Option<opc_session_store::FencedTransitionV2RecoveryCall>,
    recovery_notice: Option<opc_session_store::FencedTransitionV2RecoveryNotice>,
    backend: Arc<dyn ProtectedFencedTransitionV2Backend>,
    prepared: PreparedFencedTransitionV2,
    budget: PreparedCheckpointBudget,
    voter_count: usize,
    route: Arc<PreparedFencedTransitionV2Route>,
    history: Arc<PreparedFencedV2HistoryCache>,
    state: PreparedRequestState,
    // Only the handle that prepared the row holds dispatch authority, so only
    // it may conclude that no copy of the request was ever sent.
    original: bool,
    // Unlike the retryable preparation phase, execution having started is
    // permanent: cancellation before admission must not re-arm abandonment.
    dispatch_authority: AtomicU8,
    terminal_receipt: StdMutex<
        Option<
            Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError>,
        >,
    >,
    resolution: StdMutex<V2Resolution>,
}

/// Owns the pre-dispatch phase of `execute_once`. Dropping it before a
/// terminal classification returns the handle to `READY` only while no
/// physical V2 mutation call was admitted; otherwise the handle becomes
/// receipt-only.
struct PreparedFencedV2PreparationGuard<'a> {
    state: &'a PreparedRequestState,
    route: &'a PreparedFencedTransitionV2Route,
    voter_count: usize,
    completed: bool,
}

impl<'a> PreparedFencedV2PreparationGuard<'a> {
    fn begin(
        state: &'a PreparedRequestState,
        route: &'a PreparedFencedTransitionV2Route,
        voter_count: usize,
    ) -> Option<Self> {
        state
            .phase
            .compare_exchange(
                PREPARED_READY,
                PREPARED_PREPARING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()
            .map(|_| Self {
                state,
                route,
                voter_count,
                completed: false,
            })
    }

    fn terminal(&mut self) {
        self.state.terminal();
        self.completed = true;
    }

    fn receipt_only(&mut self) {
        self.route
            .begin_receipt_after_current_mutation_voter(self.voter_count);
        self.state
            .phase
            .store(PREPARED_RECEIPT_ONLY, Ordering::Release);
        self.completed = true;
    }
}

impl Drop for PreparedFencedV2PreparationGuard<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.route.may_have_dispatched() {
            self.receipt_only();
            return;
        }
        let _ = self.state.phase.compare_exchange(
            PREPARED_PREPARING,
            PREPARED_READY,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

/// Definitive V2 rejections of the original handle's single possible
/// dispatch that prove the exact request has not bound a receipt and never
/// will. As a later status, `Retired` does not prove that: V2 classifies the
/// retired floor before any receipt lookup.
fn v2_rejection_never_binds(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::FencedTransitionHistoryEpochNotActive
            | StoreError::FencedTransitionHistoryEpochRetired
            | StoreError::FencedTransitionHistoryFull
            | StoreError::FencedTransitionRetentionExhausted
    )
}

/// Routing context one handle shares with its physical adapter: the
/// canonical roster size, the handle's own cursors and dispatch latch, and
/// the facade-wide active-epoch cache.
struct PreparedFencedV2HandleRouting {
    voter_count: usize,
    route: Arc<PreparedFencedTransitionV2Route>,
    history: Arc<PreparedFencedV2HistoryCache>,
}

impl PersistentPreparedFencedTransitionV2Token {
    fn new(
        backend: Arc<dyn ProtectedFencedTransitionV2Backend>,
        prepared: PreparedFencedTransitionV2,
        budget: PreparedCheckpointBudget,
        routing: PreparedFencedV2HandleRouting,
        state: PreparedRequestState,
        original: bool,
    ) -> Self {
        let PreparedFencedV2HandleRouting {
            voter_count,
            route,
            history,
        } = routing;
        Self {
            recovery_call: None,
            recovery_notice: None,
            backend,
            prepared,
            budget,
            voter_count,
            route,
            history,
            state,
            original,
            dispatch_authority: AtomicU8::new(if original {
                V2_DISPATCH_UNUSED
            } else {
                V2_EXECUTION_STARTED
            }),
            terminal_receipt: StdMutex::new(None),
            resolution: StdMutex::new(V2Resolution::Unresolved),
        }
    }

    fn with_call(mut self, call: opc_session_store::FencedTransitionV2RecoveryCall) -> Self {
        self.recovery_notice = Some(call.notice());
        self.recovery_call = Some(call);
        self
    }

    fn with_recovery_notice(
        mut self,
        notice: Option<opc_session_store::FencedTransitionV2RecoveryNotice>,
    ) -> Self {
        self.recovery_notice = notice;
        self
    }

    fn reclaimed_receipt(&self) -> Option<FencedTransitionV2Status> {
        self.recovery_notice
            .as_ref()
            .and_then(|notice| notice.terminal_status())
    }

    fn set_resolution(&self, resolution: V2Resolution) {
        let mut current = self
            .resolution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current != V2Resolution::Released {
            *current = resolution;
        }
    }

    fn resolution(&self) -> V2Resolution {
        *self
            .resolution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Remove this handle's own row after it proved the request never bound
    /// a receipt. Failure leaves the row for status recovery and the sweep;
    /// it never changes the caller-visible execution result.
    async fn discard_own_unbound_row(&self) {
        if !self.original {
            return;
        }
        #[cfg(test)]
        tests::pause_execution_journal(tests::ExecutionJournalCut::BeforeDiscard).await;
        let deadline = self.budget.original_deadline();
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        if matches!(
            journal_before_deadline(
                deadline,
                self.backend
                    .discard_protected_fenced_transition_v2(&self.prepared),
            )
            .await,
            Ok(Ok(_))
        ) {
            self.set_resolution(V2Resolution::Released);
        }
    }

    async fn abandon_unexecuted(
        &self,
    ) -> Result<(), SessionConsumerFencedTransitionV2AbandonError> {
        if !self.original {
            return Err(SessionConsumerFencedTransitionV2AbandonError::NotAllowed);
        }
        match self.dispatch_authority.compare_exchange(
            V2_DISPATCH_UNUSED,
            V2_DISPATCH_ABANDONED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(V2_DISPATCH_ABANDONED) => {}
            Err(_) => return Err(SessionConsumerFencedTransitionV2AbandonError::NotAllowed),
        }
        self.state.terminal();
        self.set_resolution(V2Resolution::Resolved);
        self.release_resolved()
            .await
            .map_err(|_| SessionConsumerFencedTransitionV2AbandonError::Unavailable)
    }

    async fn execute_once(&self) -> Result<FencedTransitionOutcome, FencedTransitionExecuteError> {
        self.route.clear_failure_stage();
        match self.dispatch_authority.compare_exchange(
            V2_DISPATCH_UNUSED,
            V2_EXECUTION_STARTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(V2_EXECUTION_STARTED) => {}
            Err(_) => {
                self.route.record_failure_stage(
                    SessionConsumerPreparedFencedTransitionV2FailureStage::Setup,
                );
                return Err(FencedTransitionExecuteError::NotTransmitted);
            }
        }
        if let Some(FencedTransitionV2Status::Recorded(result)) = self.reclaimed_receipt() {
            self.terminal_receipt(Ok(FencedTransitionV2Status::Recorded(result.clone())))
                .ok();
            return (*result).map_err(FencedTransitionExecuteError::Rejected);
        }

        let Some(mut preparation) =
            PreparedFencedV2PreparationGuard::begin(&self.state, &self.route, self.voter_count)
        else {
            self.route
                .record_failure_stage(SessionConsumerPreparedFencedTransitionV2FailureStage::Setup);
            return Err(FencedTransitionExecuteError::NotTransmitted);
        };
        if self
            .recovery_call
            .as_ref()
            .is_some_and(|call| !call.dispatch_started())
        {
            preparation.receipt_only();
            self.route
                .record_failure_stage(SessionConsumerPreparedFencedTransitionV2FailureStage::Setup);
            return Err(FencedTransitionExecuteError::OutcomeUnknown {
                request_id: self.prepared.request_id(),
            });
        }
        struct Returned<'a>(Option<&'a opc_session_store::FencedTransitionV2RecoveryCall>);
        impl Drop for Returned<'_> {
            fn drop(&mut self) {
                if let Some(call) = self.0 {
                    call.returned();
                }
            }
        }
        let mut returned = Returned(self.recovery_call.as_ref());
        // Authenticate the exact retained row before any lane work. The
        // wrapper repeats this immediately before each physical dispatch.
        if !matches!(
            journal_before_deadline(
                self.budget.original_deadline(),
                self.backend
                    .preflight_protected_fenced_transition_v2(&self.prepared),
            )
            .await,
            Ok(Ok(()))
        ) {
            // Only an original handle proves that no earlier execution
            // could bind this row. A resumed deferral still needs its receipt.
            if self.original {
                preparation.terminal();
                self.set_resolution(V2Resolution::Resolved);
                self.discard_own_unbound_row().await;
            } else {
                preparation.receipt_only();
            }
            self.route
                .record_failure_stage(SessionConsumerPreparedFencedTransitionV2FailureStage::Setup);
            return Err(FencedTransitionExecuteError::NotTransmitted);
        }
        #[cfg(test)]
        tests::pause_execution_journal(tests::ExecutionJournalCut::AfterPreflight).await;
        for _ in 0..self.voter_count {
            let now = tokio::time::Instant::now();
            let Some(attempt_deadline) = now
                .checked_add(self.budget.physical_attempt_timeout())
                .map(|capped| capped.min(self.budget.original_deadline()))
            else {
                if self.route.failure_stage().is_none() {
                    self.route.record_failure_stage(
                        SessionConsumerPreparedFencedTransitionV2FailureStage::Setup,
                    );
                }
                break;
            };
            if attempt_deadline <= now {
                if self.route.failure_stage().is_none() {
                    self.route.record_failure_stage(
                        SessionConsumerPreparedFencedTransitionV2FailureStage::Setup,
                    );
                }
                break;
            }
            self.route.install_attempt_deadline(attempt_deadline);
            // Bound the wrapper's repeated journal authentication before
            // physical dispatch. The lane actor owns the later deadline and
            // transmission classification; never time out the whole mutation.
            match self
                .backend
                .protected_fenced_transition_v2_effect_with_journal_deadline(
                    &self.prepared,
                    attempt_deadline,
                )
                .await
            {
                FencedTransitionV2Effect::Resolved(Ok(outcome)) => {
                    preparation.terminal();
                    self.set_resolution(V2Resolution::Resolved);
                    return Ok(outcome);
                }
                FencedTransitionV2Effect::Resolved(Err(
                    StoreError::FencedTransitionLeaseDeferred,
                )) => {
                    preparation.receipt_only();
                    if let Some(call) = &self.recovery_call {
                        call.lease_deferred();
                    }
                    returned.0 = None;
                    return Err(FencedTransitionExecuteError::LeaseDeferred);
                }
                FencedTransitionV2Effect::Resolved(Err(StoreError::TopologyAuthorityRevoked)) => {
                    if !self.original {
                        preparation.receipt_only();
                        return Err(FencedTransitionExecuteError::Rejected(
                            StoreError::TopologyAuthorityRevoked,
                        ));
                    }
                    // Revocation is classified before any Call byte, and every
                    // earlier attempt proved the same. Nothing was sent, so a
                    // failed discard stays releasable.
                    preparation.terminal();
                    self.set_resolution(V2Resolution::Resolved);
                    self.discard_own_unbound_row().await;
                    return Err(FencedTransitionExecuteError::Rejected(
                        StoreError::TopologyAuthorityRevoked,
                    ));
                }
                FencedTransitionV2Effect::Resolved(Err(error)) => {
                    if !self.original && v2_rejection_never_binds(&error) {
                        preparation.receipt_only();
                        return Err(FencedTransitionExecuteError::Rejected(error));
                    }
                    preparation.terminal();
                    if matches!(
                        error,
                        StoreError::FencedTransitionHistoryEpochNotActive
                            | StoreError::FencedTransitionHistoryEpochRetired
                            | StoreError::FencedTransitionHistoryFull
                    ) {
                        // The cached active epoch can no longer bind new
                        // requests; the next preparation reads its successor.
                        self.history
                            .invalidate_through(self.prepared.history_epoch());
                    }
                    if v2_rejection_never_binds(&error) {
                        self.set_resolution(V2Resolution::Resolved);
                        self.discard_own_unbound_row().await;
                    } else if !matches!(error, StoreError::FencedTransitionRequestConflict) {
                        self.set_resolution(V2Resolution::Resolved);
                    }
                    return Err(FencedTransitionExecuteError::Rejected(error));
                }
                FencedTransitionV2Effect::NotTransmitted(_)
                    if !self.route.may_have_dispatched() =>
                {
                    self.route.rotate_after_not_transmitted();
                }
                FencedTransitionV2Effect::NotTransmitted(_) => {
                    preparation.receipt_only();
                    if self.route.failure_stage().is_none() {
                        self.route.record_failure_stage(
                            SessionConsumerPreparedFencedTransitionV2FailureStage::Send,
                        );
                    }
                    returned.0 = None;
                    return Err(FencedTransitionExecuteError::OutcomeUnknown {
                        request_id: self.prepared.request_id(),
                    });
                }
                _ => {
                    preparation.receipt_only();
                    // An attempt timeout does not end the original caller's
                    // deadline. Cancellation still drops the guard normally.
                    if self.route.failure_stage().is_none() {
                        self.route.record_failure_stage(
                            prepared_fenced_v2_ambiguous_failure_stage(
                                self.route.attempt_deadline(),
                            ),
                        );
                    }
                    returned.0 = None;
                    return Err(FencedTransitionExecuteError::OutcomeUnknown {
                        request_id: self.prepared.request_id(),
                    });
                }
            }
        }
        // Every candidate proved a pre-dispatch failure, and only this
        // original handle can dispatch the row, so no copy can take effect.
        // A failed or cancelled discard therefore stays releasable.
        if self.original {
            preparation.terminal();
            self.set_resolution(V2Resolution::Resolved);
            self.discard_own_unbound_row().await;
        } else {
            preparation.receipt_only();
        }
        if self.route.failure_stage().is_none() {
            self.route
                .record_failure_stage(SessionConsumerPreparedFencedTransitionV2FailureStage::Setup);
        }
        Err(FencedTransitionExecuteError::NotTransmitted)
    }

    /// Value-free diagnostic for the most recent failed execution, if the
    /// physical boundary or the facade recorded a stage.
    fn failure_diagnostic(
        &self,
    ) -> Option<SessionConsumerPreparedFencedTransitionV2FailureDiagnostic> {
        let stage = self.route.failure_stage()?;
        let remaining = self
            .budget
            .original_deadline()
            .saturating_duration_since(tokio::time::Instant::now());
        let remaining_budget_millis = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        Some(
            SessionConsumerPreparedFencedTransitionV2FailureDiagnostic::new(
                stage,
                remaining_budget_millis,
            ),
        )
    }

    fn cached_terminal_receipt(
        &self,
    ) -> Option<Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError>>
    {
        if let Some(status) = self.reclaimed_receipt() {
            return Some(self.terminal_receipt(Ok(status)));
        }
        self.terminal_receipt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn terminal_receipt(
        &self,
        result: Result<
            FencedTransitionV2Status,
            SessionConsumerPreparedFencedTransitionStatusError,
        >,
    ) -> Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError> {
        let mut receipt = self
            .terminal_receipt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cached) = receipt.clone() {
            return cached;
        }
        *receipt = Some(result.clone());
        drop(receipt);
        if matches!(&result, Ok(status) if !matches!(status, FencedTransitionV2Status::RequestConflict))
        {
            self.set_resolution(V2Resolution::Resolved);
        }
        self.state.terminal();
        result
    }

    async fn status_once(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError> {
        if let Some(result) = self.cached_terminal_receipt() {
            return result;
        }
        if !self.state.status_allowed() {
            return Err(SessionConsumerPreparedFencedTransitionStatusError::NotExecuted);
        }
        let now = tokio::time::Instant::now();
        if deadline <= now || deadline > self.budget.original_deadline() {
            return Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline);
        }
        // A missing, corrupt, or substituted row is a local fail-closed
        // condition, checked before any receipt lane is used.
        match journal_before_deadline(
            deadline,
            self.backend
                .preflight_protected_fenced_transition_v2(&self.prepared),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                if let Some(result) = self.cached_terminal_receipt() {
                    return result;
                }
                return self.terminal_receipt(Err(
                    SessionConsumerPreparedFencedTransitionStatusError::Unavailable,
                ));
            }
            Err(_) => return Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline),
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline);
        }
        let _attempt = self
            .state
            .begin_status()
            .map_err(|_| SessionConsumerPreparedFencedTransitionStatusError::Unavailable)?;
        if let Some(result) = self.cached_terminal_receipt() {
            return result;
        }
        self.route.install_attempt_deadline(deadline);
        let result = match journal_before_deadline(
            deadline,
            self.backend
                .protected_fenced_transition_v2_status(&self.prepared),
        )
        .await
        {
            Ok(Ok(_)) if tokio::time::Instant::now() >= deadline => {
                Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline)
            }
            Ok(Ok(status)) => Ok(status),
            Ok(Err(StoreError::TopologyAuthorityRevoked)) => {
                Err(SessionConsumerPreparedFencedTransitionStatusError::TopologyAuthorityRevoked)
            }
            Ok(Err(_)) => Err(SessionConsumerPreparedFencedTransitionStatusError::Unavailable),
            Err(_) => Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline),
        };
        match result {
            // NotFound is non-exclusionary while the request's epoch is
            // active; unavailable and per-attempt deadlines stay retryable.
            Ok(FencedTransitionV2Status::NotFound)
            | Ok(FencedTransitionV2Status::LeaseDeferred { .. })
            | Err(SessionConsumerPreparedFencedTransitionStatusError::Unavailable) => result,
            Ok(_)
            | Err(SessionConsumerPreparedFencedTransitionStatusError::TopologyAuthorityRevoked) => {
                self.terminal_receipt(result)
            }
            Err(_) => result,
        }
    }

    async fn status_until_terminal(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError> {
        if let Some(result) = self.cached_terminal_receipt() {
            return result;
        }
        let now = tokio::time::Instant::now();
        if deadline <= now || deadline > self.budget.original_deadline() {
            return Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline);
        }
        loop {
            for _ in 0..self.voter_count {
                let result = self.status_once(deadline).await;
                // A cached terminal receipt, including a local fail-closed
                // row failure, never changes; retrying it only spends the
                // caller's deadline. A concurrent call may have cached it.
                if let Some(cached) = self.cached_terminal_receipt() {
                    return cached;
                }
                if !prepared_fenced_v2_status_retryable_before(&result, deadline)? {
                    return result;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline);
                }
            }
            let now = tokio::time::Instant::now();
            let Some(next_round) = now.checked_add(PREPARED_FENCED_STATUS_ROUND_BACKOFF) else {
                return Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline);
            };
            tokio::time::sleep_until(next_round.min(deadline)).await;
            if tokio::time::Instant::now() >= deadline {
                return Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline);
            }
        }
    }

    async fn release_resolved(&self) -> Result<(), SessionConsumerFencedTransitionV2ReleaseError> {
        let _ = self.cached_terminal_receipt();
        match self.resolution() {
            V2Resolution::Released => Ok(()),
            V2Resolution::Unresolved => {
                Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved)
            }
            V2Resolution::Resolved => {
                // The row may already have been reclaimed by a sweep; the
                // compare-and-delete then removes nothing and release still
                // completes.
                // Cleanup has its own existing default operation window.
                // A later retry remains possible after execution's original
                // deadline, without restoring any dispatch authority.
                journal_before_deadline(
                    default_fenced_v2_operation_deadline(),
                    self.backend
                        .discard_protected_fenced_transition_v2(&self.prepared),
                )
                .await
                .map_err(|_| SessionConsumerFencedTransitionV2ReleaseError::Unavailable)?
                .map_err(|_| SessionConsumerFencedTransitionV2ReleaseError::Unavailable)?;
                self.set_resolution(V2Resolution::Released);
                Ok(())
            }
        }
    }
}

fn prepared_fenced_v2_status_retryable_before(
    result: &Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError>,
    deadline: tokio::time::Instant,
) -> Result<bool, SessionConsumerPreparedFencedTransitionStatusError> {
    match result {
        Ok(FencedTransitionV2Status::NotFound)
        | Err(SessionConsumerPreparedFencedTransitionStatusError::Unavailable)
        | Err(SessionConsumerPreparedFencedTransitionStatusError::AttemptDeadline) => {
            if tokio::time::Instant::now() >= deadline {
                Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline)
            } else {
                Ok(true)
            }
        }
        Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline) => {
            Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    #[cfg(unix)]
    mod settlement_crash;

    use bytes::Bytes;
    use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
    use opc_session_store::{
        FenceToken, FencedTransitionLease, FencedTransitionMutation,
        FencedTransitionMutationResult, FencedTransitionV2RecoveryJournalKey, Generation,
        SessionKeyType,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    use super::*;

    const VOTERS: usize = 3;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum ExecutionJournalCut {
        AfterPreflight,
        BeforeDiscard,
    }

    #[derive(Default)]
    struct ExecutionJournalPause {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    tokio::task_local! {
        static EXECUTION_JOURNAL_PAUSE: (ExecutionJournalCut, Arc<ExecutionJournalPause>);
    }

    pub(super) async fn pause_execution_journal(cut: ExecutionJournalCut) {
        if let Some(pause) = EXECUTION_JOURNAL_PAUSE
            .try_with(|(selected, pause)| (*selected == cut).then(|| Arc::clone(pause)))
            .ok()
            .flatten()
        {
            pause.entered.notify_one();
            pause.release.notified().await;
        }
    }

    #[derive(Clone)]
    enum Step {
        NotTransmitted,
        Commit,
        Unknown,
        Reject(StoreError),
        HangBeforeAdmission,
        HangAfterAdmission,
        /// Holds the physical attempt past its installed deadline and then
        /// reports an ambiguous outcome, like a voter that accepts the request
        /// and withholds its reply past the physical cap.
        HoldPastAttemptDeadline,
        /// A proven pre-write failure that first runs a local fault action.
        NotTransmittedAfter(Arc<dyn Fn() + Send + Sync>),
    }

    /// Scripted V2 physical boundary that mimics the private adapter's
    /// dispatch-admission latch on the handle's own route.
    struct ScriptedV2Physical {
        route: Arc<PreparedFencedTransitionV2Route>,
        steps: StdMutex<VecDeque<Step>>,
        voters: StdMutex<Vec<usize>>,
        status: StdMutex<FencedTransitionV2Status>,
        committed: StdMutex<Option<FencedTransitionOutcome>>,
        status_pause: ExecutionJournalPause,
        hang_status: std::sync::atomic::AtomicBool,
        status_reads: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedV2Physical {
        fn new(route: Arc<PreparedFencedTransitionV2Route>, steps: Vec<Step>) -> Arc<Self> {
            Arc::new(Self {
                route,
                steps: StdMutex::new(steps.into()),
                voters: StdMutex::new(Vec::new()),
                status: StdMutex::new(FencedTransitionV2Status::NotFound),
                committed: StdMutex::new(None),
                status_pause: ExecutionJournalPause::default(),
                hang_status: std::sync::atomic::AtomicBool::new(false),
                status_reads: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn push(&self, step: Step) {
            self.steps.lock().expect("steps").push_back(step);
        }

        fn voters(&self) -> Vec<usize> {
            self.voters.lock().expect("voters").clone()
        }

        fn set_status(&self, status: FencedTransitionV2Status) {
            *self.status.lock().expect("status") = status;
        }
    }

    /// Public DTO construction: the guard and outcome constructors are
    /// store-private, so tests build them through their frozen serde shapes.
    fn lease_guard(
        key: opc_session_store::SessionKey,
        acquired_at: Timestamp,
        expires_at: Timestamp,
    ) -> LeaseGuard {
        serde_json::from_value(serde_json::json!({
            "key": key,
            "owner": OwnerId::new("prepared-fenced-v2-unit-owner").expect("owner"),
            "fence": FenceToken::new(1),
            "acquired_at": acquired_at,
            "expires_at": expires_at,
            "credential_id": 1,
        }))
        .expect("public lease wire shape")
    }

    fn outcome_for(request: &FencedTransitionV2Request) -> FencedTransitionOutcome {
        let recorded_at = Timestamp::now_utc();
        let FencedTransitionLease::Renew { lease, ttl } = request.lease() else {
            panic!("scripted tests use renewals");
        };
        let renewed = lease_guard(
            lease.key().clone(),
            lease.acquired_at(),
            checked_session_deadline(recorded_at, *ttl).expect("lease expiry"),
        );
        let outcome: FencedTransitionOutcome = serde_json::from_value(serde_json::json!({
            "lease": renewed,
            "committed_generation": Generation::new(1),
            "mutation": FencedTransitionMutationResult::Deleted,
            "recorded_at": recorded_at,
            "retained_until": checked_session_deadline(
                recorded_at,
                opc_session_store::FENCED_TRANSITION_OUTCOME_RETENTION,
            )
            .expect("retention deadline"),
        }))
        .expect("public outcome wire shape");
        assert!(outcome.matches_v2_request(request));
        outcome
    }

    #[async_trait::async_trait]
    impl SessionBackend for ScriptedV2Physical {
        fn fenced_transition_preserves_protected_payloads(&self) -> bool {
            true
        }

        async fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities::minimal()
        }

        async fn get(
            &self,
            _key: &opc_session_store::SessionKey,
        ) -> Result<Option<opc_session_store::StoredSessionRecord>, StoreError> {
            Err(authenticated_consumer_fenced_transition_only())
        }

        async fn fenced_transition_v2_capability(
            &self,
        ) -> Result<Option<FencedTransitionV2Capability>, StoreError> {
            Ok(Some(FencedTransitionV2Capability::V2))
        }

        async fn fenced_transition_v2_history_state(
            &self,
        ) -> Result<FencedTransitionV2HistoryState, StoreError> {
            Ok(history_state(1, 1, 0))
        }

        async fn fenced_transition_v2_effect(
            &self,
            request: FencedTransitionV2Request,
        ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>> {
            self.voters
                .lock()
                .expect("voters")
                .push(self.route.mutation_voter(VOTERS));
            let step = self
                .steps
                .lock()
                .expect("steps")
                .pop_front()
                .expect("scripted step");
            match step {
                Step::NotTransmitted => {
                    // Mirrors the private adapter: an admitted attempt that
                    // proves no request byte crossed the boundary.
                    self.route.record_failure_stage(
                        SessionConsumerPreparedFencedTransitionV2FailureStage::Send,
                    );
                    FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(
                        "scripted pre-write failure".into(),
                    ))
                }
                Step::NotTransmittedAfter(fault) => {
                    fault();
                    FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(
                        "scripted pre-write failure".into(),
                    ))
                }
                Step::Commit => {
                    self.route.admit_dispatch();
                    let outcome = outcome_for(&request);
                    *self.committed.lock().expect("committed") = Some(outcome.clone());
                    FencedTransitionV2Effect::Resolved(Ok(outcome))
                }
                Step::Unknown => {
                    self.route.admit_dispatch();
                    // Mirrors a reply path that ends before the attempt cap.
                    self.route.record_failure_stage(
                        SessionConsumerPreparedFencedTransitionV2FailureStage::ReplyLost,
                    );
                    FencedTransitionV2Effect::OutcomeUnknown {
                        request_ids: vec![request.request_id()],
                    }
                }
                Step::Reject(error) => {
                    self.route.admit_dispatch();
                    FencedTransitionV2Effect::Resolved(Err(error))
                }
                Step::HangBeforeAdmission => std::future::pending().await,
                Step::HangAfterAdmission => {
                    self.route.admit_dispatch();
                    std::future::pending().await
                }
                Step::HoldPastAttemptDeadline => {
                    self.route.admit_dispatch();
                    let deadline = self
                        .route
                        .attempt_deadline()
                        .expect("handle installs the physical attempt deadline");
                    tokio::time::sleep_until(deadline).await;
                    // Mirrors a refused reply held past the physical cap.
                    self.route.record_failure_stage(
                        SessionConsumerPreparedFencedTransitionV2FailureStage::AwaitingReply,
                    );
                    FencedTransitionV2Effect::OutcomeUnknown {
                        request_ids: vec![request.request_id()],
                    }
                }
            }
        }

        async fn fenced_transition_v2_status(
            &self,
            _request: &FencedTransitionV2Request,
        ) -> Result<FencedTransitionV2Status, StoreError> {
            self.status_reads.fetch_add(1, Ordering::SeqCst);
            self.status_pause.entered.notify_one();
            if self.hang_status.load(Ordering::SeqCst) {
                self.status_pause.release.notified().await;
            }
            Ok(self.status.lock().expect("status").clone())
        }

        async fn compare_and_set(
            &self,
            _operation: CompareAndSet,
        ) -> Result<CompareAndSetResult, StoreError> {
            Err(authenticated_consumer_fenced_transition_only())
        }

        async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
            Err(authenticated_consumer_fenced_transition_only())
        }

        async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
            Err(authenticated_consumer_fenced_transition_only())
        }

        async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
            Err(authenticated_consumer_fenced_transition_only())
        }
    }

    struct Harness {
        _directory: tempfile::TempDir,
        journal: Arc<FencedTransitionV2RecoveryJournal>,
        physical: Arc<ScriptedV2Physical>,
        backend: Arc<dyn ProtectedFencedTransitionV2Backend>,
        route: Arc<PreparedFencedTransitionV2Route>,
        history: Arc<PreparedFencedV2HistoryCache>,
        request_id: FencedTransitionRequestId,
    }

    fn history_state(
        epoch: u64,
        generation: u64,
        bound_entries: usize,
    ) -> FencedTransitionV2HistoryState {
        FencedTransitionV2HistoryState::new(
            Some(FencedTransitionV2HistoryEpoch::new(epoch).expect("epoch")),
            None,
            None,
            0,
            generation,
            bound_entries,
            0,
        )
        .expect("history state")
    }

    const ORIGIN: usize = 1;

    fn tenant() -> TenantId {
        TenantId::from_static("prepared-fenced-v2-unit")
    }

    fn delete_request(request_id: FencedTransitionRequestId) -> FencedTransitionRequest {
        let key = opc_session_store::SessionKey {
            tenant: tenant(),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"prepared-fenced-v2-unit")
                .try_into()
                .expect("stable ID"),
        };
        let acquired_at = Timestamp::now_utc();
        let guard = lease_guard(
            key,
            acquired_at,
            checked_session_deadline(acquired_at, Duration::from_secs(60)).expect("expiry"),
        );
        FencedTransitionRequest::new(
            request_id,
            FencedTransitionLease::renew(guard, Duration::from_secs(60)).expect("renewal"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("delete request")
    }

    async fn harness(steps: Vec<Step>) -> Harness {
        harness_with_class(steps, ScopeWorkClass::Normal).await
    }

    async fn harness_with_class(steps: Vec<Step>, class: ScopeWorkClass) -> Harness {
        let directory = tempfile::tempdir().expect("journal directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private journal directory");
        }
        let journal = Arc::new(
            FencedTransitionV2RecoveryJournal::create_new(
                directory.path().join("recovery.sqlite3"),
                FencedTransitionV2RecoveryJournalKey::from_bytes([0x71; 32]),
            )
            .expect("recovery journal"),
        );
        let provider = Arc::new(MemoryKeyProvider::new());
        provider
            .insert_active_key(
                KeyId::new("prepared-fenced-v2-unit").expect("key ID"),
                KeyPurpose::Session,
                tenant(),
                Zeroizing::new([0x72; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("active key");
        let route = Arc::new(PreparedFencedTransitionV2Route::new(ORIGIN));
        let physical = ScriptedV2Physical::new(Arc::clone(&route), steps);
        let erased: Arc<dyn SessionBackend> = physical.clone();
        let backend: Arc<dyn ProtectedFencedTransitionV2Backend> = Arc::new(
            EncryptingSessionBackend::new(erased, provider, "prepared-fenced-v2-unit")
                .with_fenced_transition_v2_recovery_journal(Arc::new(
                    journal.with_operation_class(class),
                ))
                .with_fenced_transition_v2_journal_scope(
                    FencedTransitionV2JournalScope::from_bytes([0x73; 32]),
                ),
        );
        Harness {
            _directory: directory,
            journal,
            physical,
            backend,
            route,
            // The scripted boundary's active epoch, as activation would seed it.
            history: Arc::new(PreparedFencedV2HistoryCache::primed(Some(history_state(
                1, 1, 0,
            )))),
            request_id: FencedTransitionRequestId::from_bytes([0x74; 16]),
        }
    }

    fn budget() -> PreparedCheckpointBudget {
        PreparedCheckpointBudget::new(
            tokio::time::Instant::now() + Duration::from_secs(5),
            Duration::from_millis(100),
        )
        .expect("budget")
    }

    impl Harness {
        async fn prepare(&self) -> PersistentPreparedFencedTransitionV2Token {
            let prepared = self
                .backend
                .prepare_protected_fenced_transition_v2(delete_request(self.request_id))
                .await
                .expect("prepare");
            PersistentPreparedFencedTransitionV2Token::new(
                Arc::clone(&self.backend),
                prepared,
                budget(),
                PreparedFencedV2HandleRouting {
                    voter_count: VOTERS,
                    route: Arc::clone(&self.route),
                    history: Arc::clone(&self.history),
                },
                PreparedRequestState::new(0),
                true,
            )
        }

        async fn retained(&self) -> usize {
            self.backend
                .retained_protected_fenced_transitions_v2()
                .await
                .expect("retained count")
        }
    }

    struct PreDispatchRefusalConsumer {
        refuse: bool,
        calls: AtomicUsize,
        dispatched: Notify,
    }

    #[async_trait::async_trait]
    impl SessionQuorumConsumer for PreDispatchRefusalConsumer {
        async fn execute(
            &self,
            _authorization: &SessionConsumerAuthorization,
            _request: SessionConsumerRequest,
        ) -> SessionConsumerResponse {
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable)
        }

        async fn execute_v2(
            &self,
            _authorization: &SessionConsumerAuthorization,
            request: SessionConsumerV2Request,
        ) -> SessionConsumerV2Response {
            match request.operation() {
                SessionConsumerV2Operation::FencedTransitionV2Capability => {
                    SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
                        FencedTransitionV2Capability::V2,
                    ))
                }
                SessionConsumerV2Operation::FencedTransitionV2HistoryState => {
                    SessionConsumerV2Response::FencedTransitionV2HistoryState(Ok(history_state(
                        1, 1, 0,
                    )))
                }
                SessionConsumerV2Operation::FencedTransitionV2 { .. } => {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    if self.refuse {
                        SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
                    } else {
                        self.dispatched.notify_one();
                        std::future::pending().await
                    }
                }
                _ => SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable),
            }
        }

        async fn watch(
            &self,
            _authorization: &SessionConsumerAuthorization,
            _scope: SessionConsumerScope,
            _start_sequence: u64,
        ) -> Result<
            BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
            SessionConsumerRejection,
        > {
            Err(SessionConsumerRejection::Unavailable)
        }
    }

    async fn assert_v2_network_refusal_settlement(refuse: bool) {
        let _metrics_guard = crate::test_support::SESSION_CONNECTION_METRICS_TEST_LOCK
            .lock()
            .await;
        let client_identity = opc_types::SpiffeId::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/consumer/instance/v2-refusal",
        )
        .expect("client identity");
        let server_identity = opc_types::SpiffeId::new(
            "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/consumer/instance/v2-voter",
        )
        .expect("server identity");
        let material = crate::test_support::RotatableClientMaterial::new(client_identity.as_str());
        let scope = test_consumer_voter_authority().scope();
        let service = Arc::new(PreDispatchRefusalConsumer {
            refuse,
            calls: AtomicUsize::new(0),
            dispatched: Notify::new(),
        });
        let grant = opc_session_store::SessionConsumerAuthorizationGrant::try_new(
            client_identity,
            [opc_session_store::SessionConsumerTenantNfScope::new(
                tenant(),
                NetworkFunctionKind::smf(),
            )],
        )
        .expect("tenant/NF grant");
        let manifest = test_consumer_roster()
            .authorization_manifest(test_consumer_voter_authority().node_id(), [grant])
            .expect("consumer manifest");
        let (server, address) = SessionQuorumConsumerServer::new(
            service.clone(),
            material.trusted_server_config(server_identity.as_str()),
            SessionConsumerAuthorizer::try_new(manifest).expect("authorizer"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("listen");
        let client = PersistentSessionConsumerClient::from_stateless(
            StatelessSessionConsumerClient::new_unattested_for_test(
                address,
                rustls_pki_types::ServerName::IpAddress(address.ip().into()),
                server_identity,
                scope,
                material.config(),
            ),
        )
        .expect("persistent client");
        let voters =
            SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
                [client.clone()],
            )
            .await
            .expect("activate exact voter roster");
        let directory = tempfile::tempdir().expect("private journal directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private journal directory");
        }
        let journal = Arc::new(
            FencedTransitionV2RecoveryJournal::create_new(
                directory.path().join("recovery.sqlite3"),
                FencedTransitionV2RecoveryJournalKey::from_bytes([0x71; 32]),
            )
            .expect("recovery journal"),
        );
        let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_encrypting(
            voters,
            Arc::new(MemoryKeyProvider::new()),
            "prepared-fenced-v2-unit",
            journal,
        )
        .expect("protected facade");
        let request_id = FencedTransitionRequestId::from_bytes([0x74; 16]);
        let mut handle = facade
            .prepare_fenced_transition(delete_request(request_id), budget())
            .await
            .expect("prepare");
        assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 1);
        let result = if refuse {
            let result = handle.execute_once().await;
            server.abort_and_wait().await;
            result
        } else {
            let execute = handle.execute_once();
            tokio::pin!(execute);
            tokio::select! {
                result = &mut execute => panic!("the transport fixture returned before dispatch: {result:?}"),
                _ = service.dispatched.notified() => {}
            }
            server.abort_and_wait().await;
            execute.await
        };
        assert_eq!(service.calls.load(Ordering::SeqCst), 1);
        if refuse {
            assert_eq!(result, Err(FencedTransitionExecuteError::NotTransmitted));
            assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 0);
            assert_eq!(handle.release_resolved().await, Ok(()));
        } else {
            assert_eq!(
                result,
                Err(FencedTransitionExecuteError::OutcomeUnknown { request_id })
            );
            assert_eq!(facade.retained_fenced_transitions().await.unwrap(), 1);
            assert_eq!(
                handle.release_resolved().await,
                Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved)
            );
        }
        assert_eq!(
            handle.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted),
            "neither a settled nor an ambiguous handle may dispatch again"
        );
        assert_eq!(service.calls.load(Ordering::SeqCst), 1);
        let _ = client.shutdown().await;
    }

    #[tokio::test]
    async fn v2_handle_pre_dispatch_refusal_discards_its_unsent_row() {
        assert_v2_network_refusal_settlement(true).await;
    }

    #[tokio::test]
    async fn v2_handle_transport_failure_retains_its_recovery_row() {
        assert_v2_network_refusal_settlement(false).await;
    }

    fn journal_admissions(journal: &FencedTransitionV2RecoveryJournal) -> [usize; 5] {
        [
            ScopeWorkClass::SafetyControl,
            ScopeWorkClass::Emergency,
            ScopeWorkClass::EmergencyClassification,
            ScopeWorkClass::Normal,
            ScopeWorkClass::Maintenance,
        ]
        .map(|class| journal.operation_admissions_for_test(class))
    }

    async fn assert_execution_journal_wait_ends_by_original_deadline(cut: ExecutionJournalCut) {
        let before_dispatch = cut == ExecutionJournalCut::AfterPreflight;
        let harness = harness(if before_dispatch {
            vec![]
        } else {
            vec![
                Step::NotTransmitted,
                Step::NotTransmitted,
                Step::NotTransmitted,
            ]
        })
        .await;
        let token = harness.prepare().await;
        let deadline = token.budget.original_deadline();
        let pause = Arc::new(ExecutionJournalPause::default());
        let mut execution = Box::pin(
            EXECUTION_JOURNAL_PAUSE.scope((cut, Arc::clone(&pause)), token.execute_once()),
        );
        tokio::select! {
            result = &mut execution => panic!("execution must reach the selected journal cut: {result:?}"),
            () = pause.entered.notified() => {},
        }
        // Contention starts only after the first timed authentication, or
        // after all physical attempts have definitively proved no effect.
        let urgent = harness
            .journal
            .with_operation_class(ScopeWorkClass::Emergency);
        let held = urgent
            .hold_operation_for_test()
            .await
            .expect("hold urgent operation");
        let mut next_urgent = Box::pin(urgent.hold_operation_for_test());
        assert!(futures_util::poll!(&mut next_urgent).is_pending());
        let admissions = journal_admissions(&harness.journal);
        pause.release.notify_one();
        assert!(futures_util::poll!(&mut execution).is_pending());
        tokio::time::pause();
        tokio::time::advance(deadline.saturating_duration_since(tokio::time::Instant::now())).await;
        let result = futures_util::poll!(&mut execution);
        assert_eq!(journal_admissions(&harness.journal), admissions);
        drop(execution);
        drop(next_urgent);
        drop(held);
        tokio::time::resume();
        assert_eq!(
            result,
            std::task::Poll::Ready(Err(FencedTransitionExecuteError::NotTransmitted)),
            "queued journal work must not withhold a no-effect result past the original deadline"
        );
        assert!(!harness.route.may_have_dispatched());
        assert_eq!(
            harness.physical.voters(),
            if before_dispatch {
                vec![]
            } else {
                vec![ORIGIN, (ORIGIN + 1) % VOTERS, (ORIGIN + 2) % VOTERS]
            }
        );
        assert_eq!(harness.retained().await, 1);
        token
            .release_resolved()
            .await
            .expect("a later cleanup attempt remains available");
        assert_eq!(harness.retained().await, 0);
    }

    #[tokio::test]
    async fn v2_execution_journal_wait_after_timed_preflight_ends_by_original_deadline() {
        assert_execution_journal_wait_ends_by_original_deadline(
            ExecutionJournalCut::AfterPreflight,
        )
        .await;
    }

    #[tokio::test]
    async fn v2_execution_journal_cleanup_after_no_effect_ends_by_original_deadline() {
        assert_execution_journal_wait_ends_by_original_deadline(ExecutionJournalCut::BeforeDiscard)
            .await;
    }

    #[tokio::test]
    async fn v2_standalone_journal_cleanup_is_bounded_and_can_retry_after_original_deadline() {
        for abandon in [false, true] {
            let harness = harness(if abandon { vec![] } else { vec![Step::Commit] }).await;
            let token = harness.prepare().await;
            if !abandon {
                token
                    .execute_once()
                    .await
                    .expect("resolved physical effect");
            }
            let urgent = harness
                .journal
                .with_operation_class(ScopeWorkClass::Emergency);
            let held = urgent
                .hold_operation_for_test()
                .await
                .expect("hold urgent operation");
            let cleanup = async {
                if abandon {
                    token.abandon_unexecuted().await.map_err(|_| ())
                } else {
                    token.release_resolved().await.map_err(|_| ())
                }
            };
            let mut cleanup = Box::pin(cleanup);
            assert!(futures_util::poll!(&mut cleanup).is_pending());
            tokio::time::pause();
            tokio::time::advance(DEFAULT_CONSUMER_OPERATION_TIMEOUT).await;
            let result = futures_util::poll!(&mut cleanup);
            drop(cleanup);
            drop(held);
            tokio::time::resume();
            assert_eq!(result, std::task::Poll::Ready(Err(())));
            assert_eq!(harness.retained().await, 1);
            if abandon {
                assert_eq!(
                    token.execute_once().await,
                    Err(FencedTransitionExecuteError::NotTransmitted)
                );
                token
                    .abandon_unexecuted()
                    .await
                    .expect("retry abandoned cleanup");
            } else {
                token
                    .release_resolved()
                    .await
                    .expect("retry resolved cleanup");
            }
            assert_eq!(harness.retained().await, 0);
            assert_eq!(harness.physical.voters().len(), usize::from(!abandon));
        }
    }

    #[tokio::test]
    async fn v2_handle_abandons_a_never_executed_row_without_dispatch() {
        let harness = harness(vec![]).await;
        let mut handle = SessionConsumerPreparedFencedTransitionV2 {
            inner: harness.prepare().await,
        };
        assert_eq!(harness.retained().await, 1);
        assert_eq!(
            handle
                .status_once(tokio::time::Instant::now() + Duration::from_secs(1))
                .await,
            Err(SessionConsumerPreparedFencedTransitionStatusError::NotExecuted)
        );
        handle.abandon_unexecuted().await.unwrap();
        assert_eq!(
            harness.retained().await,
            0,
            "the original handle needs a way to release a never-executed row"
        );
        assert!(harness.physical.voters().is_empty());
        assert_eq!(
            handle.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        let _replacement = harness.prepare().await;
        handle.abandon_unexecuted().await.unwrap();
        assert_eq!(
            harness.retained().await,
            1,
            "an old handle cannot delete a replacement row"
        );
    }

    #[tokio::test]
    async fn v2_recovered_handle_has_no_abandon_authority() {
        let harness = harness(vec![]).await;
        let mut original = SessionConsumerPreparedFencedTransitionV2 {
            inner: harness.prepare().await,
        };
        let PreparedFencedTransitionV2Lookup::Found(prepared) = harness
            .backend
            .recover_protected_fenced_transition_v2(harness.request_id)
            .await
            .unwrap()
        else {
            panic!("prepared row is retained");
        };
        let state = PreparedRequestState::new(0);
        state.receipt_only();
        let recovered = SessionConsumerRecoveredFencedTransitionV2Status {
            inner: PersistentPreparedFencedTransitionV2Token::new(
                Arc::clone(&harness.backend),
                prepared,
                budget(),
                PreparedFencedV2HandleRouting {
                    voter_count: VOTERS,
                    route: Arc::clone(&harness.route),
                    history: Arc::clone(&harness.history),
                },
                state,
                false,
            ),
        };
        assert_eq!(
            recovered.inner.abandon_unexecuted().await,
            Err(SessionConsumerFencedTransitionV2AbandonError::NotAllowed)
        );
        assert_eq!(harness.retained().await, 1);
        original.abandon_unexecuted().await.unwrap();
        assert_eq!(harness.retained().await, 0);
        assert!(harness.physical.voters().is_empty());
    }

    #[tokio::test]
    async fn v2_handle_abandon_is_refused_after_execution_started_even_without_dispatch() {
        for admitted in [false, true] {
            let harness = harness(vec![if admitted {
                Step::HangAfterAdmission
            } else {
                Step::HangBeforeAdmission
            }])
            .await;
            let mut handle = SessionConsumerPreparedFencedTransitionV2 {
                inner: harness.prepare().await,
            };
            assert!(
                tokio::time::timeout(Duration::from_millis(50), handle.execute_once())
                    .await
                    .is_err()
            );
            assert_eq!(harness.route.may_have_dispatched(), admitted);
            assert_eq!(
                handle.abandon_unexecuted().await,
                Err(SessionConsumerFencedTransitionV2AbandonError::NotAllowed)
            );
            assert_eq!(harness.retained().await, 1);
            if admitted {
                assert_eq!(
                    handle.execute_once().await,
                    Err(FencedTransitionExecuteError::NotTransmitted)
                );
                assert_eq!(
                    handle.release_resolved().await,
                    Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved)
                );
            } else {
                harness.physical.push(Step::Commit);
                handle
                    .execute_once()
                    .await
                    .expect("existing pre-admission retry remains usable");
                handle.release_resolved().await.unwrap();
                assert_eq!(harness.retained().await, 0);
            }
        }
    }

    #[tokio::test]
    async fn v2_handle_abandon_retries_failed_local_deletion_without_restoring_dispatch() {
        let harness = harness(vec![]).await;
        let mut handle = SessionConsumerPreparedFencedTransitionV2 {
            inner: harness.prepare().await,
        };
        let journal = harness._directory.path().join("recovery.sqlite3");
        std::fs::rename(&journal, journal.with_extension("moved")).unwrap();
        assert_eq!(
            handle.abandon_unexecuted().await,
            Err(SessionConsumerFencedTransitionV2AbandonError::Unavailable)
        );
        assert_eq!(
            handle.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        std::fs::rename(journal.with_extension("moved"), &journal).unwrap();
        assert_eq!(harness.retained().await, 1);
        handle.abandon_unexecuted().await.unwrap();
        assert_eq!(harness.retained().await, 0);
        assert!(harness.physical.voters().is_empty());
    }

    #[test]
    fn v2_handle_abandon_retries_after_cancellation_with_dispatch_consumed() {
        // The journal uses spawn_blocking. Occupy the sole blocking worker
        // after preparation so the first poll consumes authority and suspends
        // before any local deletion can complete, without timing a disk write.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let harness = harness(vec![]).await;
            let mut handle = SessionConsumerPreparedFencedTransitionV2 {
                inner: harness.prepare().await,
            };
            let (entered, blocked) = tokio::sync::oneshot::channel();
            let (release, released) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            blocked.await.unwrap();
            {
                let mut abandon = Box::pin(handle.abandon_unexecuted());
                assert!(futures_util::poll!(abandon.as_mut()).is_pending());
            }
            assert_eq!(
                tokio::time::timeout(Duration::from_millis(100), handle.execute_once())
                    .await
                    .unwrap(),
                Err(FencedTransitionExecuteError::NotTransmitted)
            );
            assert!(harness.physical.voters().is_empty());
            release.send(()).unwrap();
            blocker.await.unwrap();
            handle.abandon_unexecuted().await.unwrap();
            assert_eq!(harness.retained().await, 0);
            handle.abandon_unexecuted().await.unwrap();
            assert_eq!(
                handle.execute_once().await,
                Err(FencedTransitionExecuteError::NotTransmitted)
            );
            assert!(harness.physical.voters().is_empty());
        });
    }

    #[tokio::test]
    async fn v2_handle_rotates_only_after_proven_pre_write_failure_and_discards_an_unsent_row() {
        let harness = harness(vec![
            Step::NotTransmitted,
            Step::NotTransmitted,
            Step::NotTransmitted,
        ])
        .await;
        let token = harness.prepare().await;
        assert_eq!(harness.retained().await, 1);
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert_eq!(
            harness.physical.voters(),
            vec![ORIGIN, (ORIGIN + 1) % VOTERS, (ORIGIN + 2) % VOTERS],
            "one attempt per canonical voter, starting at the origin"
        );
        assert_eq!(
            harness.retained().await,
            0,
            "no copy was sent, so the handle removes its own row"
        );
        assert_eq!(
            token
                .status_once(tokio::time::Instant::now() + Duration::from_secs(1))
                .await,
            Err(SessionConsumerPreparedFencedTransitionStatusError::NotExecuted)
        );
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted),
            "a terminal handle never dispatches again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn v2_handle_failed_preflight_discards_its_unsent_row() {
        let harness = harness(vec![Step::Commit]).await;
        let token = harness.prepare().await;
        assert_eq!(harness.retained().await, 1);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert!(harness.physical.voters().is_empty());
        assert_eq!(
            harness.retained().await,
            1,
            "expiry prevents deletion but leaves the never-dispatched row releasable"
        );
        assert!(token.resolution() == V2Resolution::Resolved);
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted),
            "retaining the expired row cannot restore dispatch authority"
        );
        assert!(harness.physical.voters().is_empty());
        assert_eq!(token.release_resolved().await, Ok(()));
        assert_eq!(harness.retained().await, 0);
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted),
            "settlement cannot restore dispatch authority"
        );
        assert!(harness.physical.voters().is_empty());
        assert!(matches!(
            harness
                .backend
                .recover_protected_fenced_transition_v2(harness.request_id)
                .await,
            Ok(PreparedFencedTransitionV2Lookup::Absent)
        ));
    }

    #[tokio::test]
    async fn v2_handle_failed_preflight_keeps_failed_deletion_releasable() {
        let harness = harness(vec![Step::Commit]).await;
        let token = harness.prepare().await;
        let journal = harness._directory.path().join("recovery.sqlite3");
        std::fs::rename(&journal, journal.with_extension("moved")).unwrap();
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert!(harness.physical.voters().is_empty());
        assert_eq!(
            token.release_resolved().await,
            Err(SessionConsumerFencedTransitionV2ReleaseError::Unavailable),
            "a failed deletion stays releasable"
        );
        std::fs::rename(journal.with_extension("moved"), &journal).unwrap();
        assert_eq!(harness.retained().await, 1);
        assert_eq!(token.release_resolved().await, Ok(()));
        assert_eq!(harness.retained().await, 0);
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert!(harness.physical.voters().is_empty());
    }

    #[tokio::test]
    async fn v2_resumed_handle_failed_preflight_retains_its_bound_row() {
        let harness = harness(vec![Step::Commit]).await;
        let original = harness.prepare().await;
        let token = PersistentPreparedFencedTransitionV2Token::new(
            Arc::clone(&harness.backend),
            original.prepared.clone(),
            budget(),
            PreparedFencedV2HandleRouting {
                voter_count: VOTERS,
                route: Arc::clone(&harness.route),
                history: Arc::clone(&harness.history),
            },
            PreparedRequestState::new(0),
            false,
        );
        let journal = harness._directory.path().join("recovery.sqlite3");
        std::fs::rename(&journal, journal.with_extension("moved")).unwrap();
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert!(harness.physical.voters().is_empty());
        std::fs::rename(journal.with_extension("moved"), &journal).unwrap();
        assert_eq!(harness.retained().await, 1);
        assert_eq!(
            token.release_resolved().await,
            Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved),
            "the current attempt's preflight cannot exclude an earlier bound request"
        );
        assert_eq!(
            token
                .status_once(tokio::time::Instant::now() + Duration::from_secs(1))
                .await,
            Ok(FencedTransitionV2Status::NotFound),
            "the resumed handle must retain status recovery"
        );
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert!(harness.physical.voters().is_empty());
        assert_eq!(harness.retained().await, 1);
    }

    #[tokio::test]
    async fn v2_handle_commit_after_rotation_is_resolved_and_releasable() {
        let harness = harness(vec![Step::NotTransmitted, Step::Commit]).await;
        let token = harness.prepare().await;
        token
            .execute_once()
            .await
            .expect("the second canonical voter commits");
        assert_eq!(
            harness.physical.voters(),
            vec![ORIGIN, (ORIGIN + 1) % VOTERS]
        );
        assert_eq!(
            harness.retained().await,
            1,
            "a committed row stays until release"
        );
        token.release_resolved().await.expect("release");
        assert_eq!(harness.retained().await, 0);
    }

    #[tokio::test]
    async fn v2_handle_possible_send_is_receipt_only_until_a_terminal_status() {
        let harness = harness(vec![Step::Unknown]).await;
        let token = harness.prepare().await;
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::OutcomeUnknown {
                request_id: harness.request_id
            }),
            "ambiguity names the caller-stable ID"
        );
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted),
            "a possible send permanently removes dispatch authority"
        );
        assert_eq!(harness.physical.voters().len(), 1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            token.status_once(deadline).await,
            Ok(FencedTransitionV2Status::NotFound),
            "status is read-only and NotFound stays nonterminal"
        );
        assert_eq!(
            token.release_resolved().await,
            Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved)
        );
        assert_eq!(harness.retained().await, 1);
        harness
            .physical
            .set_status(FencedTransitionV2Status::EpochNotActive);
        assert_eq!(
            token.status_until_terminal(deadline).await,
            Ok(FencedTransitionV2Status::EpochNotActive),
            "a closed epoch proves the request can never bind"
        );
        token
            .release_resolved()
            .await
            .expect("a terminal exclusion permits release");
        assert_eq!(harness.retained().await, 0);
        assert_eq!(
            harness.physical.voters().len(),
            1,
            "status never dispatched"
        );
    }

    #[tokio::test]
    async fn v2_emergency_remote_status_wait_leaves_ordinary_journal_available() {
        let harness = harness_with_class(vec![Step::Unknown], ScopeWorkClass::Emergency).await;
        let token = harness.prepare().await;
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::OutcomeUnknown {
                request_id: harness.request_id,
            })
        );
        harness.physical.hang_status.store(true, Ordering::SeqCst);
        let mut status = Box::pin(token.status_until_terminal(token.budget.original_deadline()));
        tokio::select! {
            result = &mut status => panic!("the voter must remain pending: {result:?}"),
            () = harness.physical.status_pause.entered.notified() => {},
        }
        let mut ordinary = Box::pin(harness.journal.hold_operation_for_test());
        assert!(
            matches!(
                futures_util::poll!(&mut ordinary),
                std::task::Poll::Ready(Ok(_))
            ),
            "idle native journal admission must be immediately available during remote status I/O"
        );
        assert!(futures_util::poll!(&mut status).is_pending());
        drop(status);
        assert_eq!(
            harness.physical.voters().len(),
            1,
            "receipt polling cannot redispatch"
        );
        assert_eq!(harness.retained().await, 1, "unknown rows remain retained");
    }

    #[tokio::test]
    async fn v2_emergency_status_backoff_leaves_ordinary_journal_available() {
        let harness = harness_with_class(vec![Step::Unknown], ScopeWorkClass::Emergency).await;
        let token = harness.prepare().await;
        assert!(matches!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
        ));
        let mut status = Box::pin(token.status_until_terminal(token.budget.original_deadline()));
        tokio::select! {
            result = &mut status => panic!("NotFound must stay retryable: {result:?}"),
            () = async {
                while harness.physical.status_reads.load(Ordering::SeqCst) < VOTERS {
                    harness.physical.status_pause.entered.notified().await;
                }
            } => {},
        }
        // The final synchronous NotFound return reaches the backoff sleep in
        // the same poll. Freeze that sleep while testing real native admission.
        tokio::time::pause();
        let mut ordinary = Box::pin(harness.journal.hold_operation_for_test());
        assert!(matches!(
            futures_util::poll!(&mut ordinary),
            std::task::Poll::Ready(Ok(_))
        ));
        assert!(futures_util::poll!(&mut status).is_pending());
        drop(status);
        tokio::time::resume();
        assert_eq!(harness.physical.voters().len(), 1);
        assert_eq!(harness.retained().await, 1);
    }

    #[tokio::test]
    async fn v2_emergency_physical_execution_leaves_ordinary_journal_available() {
        let harness =
            harness_with_class(vec![Step::HangAfterAdmission], ScopeWorkClass::Emergency).await;
        let token = harness.prepare().await;
        let mut execution = Box::pin(token.execute_once());
        tokio::select! {
            result = &mut execution => panic!("the admitted physical operation must remain pending: {result:?}"),
            () = async {
                while !harness.route.may_have_dispatched() {
                    tokio::task::yield_now().await;
                }
            } => {},
        }
        let mut ordinary = Box::pin(harness.journal.hold_operation_for_test());
        assert!(matches!(
            futures_util::poll!(&mut ordinary),
            std::task::Poll::Ready(Ok(_))
        ));
        assert!(futures_util::poll!(&mut execution).is_pending());
        drop(execution);
        assert_eq!(harness.physical.voters().len(), 1);
        assert_eq!(harness.retained().await, 1);
    }

    #[tokio::test]
    async fn v2_handle_definitive_unbound_rejection_discards_its_row() {
        let harness = harness(vec![Step::Reject(
            StoreError::FencedTransitionHistoryEpochNotActive,
        )])
        .await;
        let token = harness.prepare().await;
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::Rejected(
                StoreError::FencedTransitionHistoryEpochNotActive
            ))
        );
        assert_eq!(harness.retained().await, 0);
        token
            .release_resolved()
            .await
            .expect("an already removed row releases idempotently");
    }

    #[tokio::test]
    async fn v2_handle_cancellation_before_dispatch_admission_returns_to_ready() {
        let harness = harness(vec![Step::HangBeforeAdmission]).await;
        let token = harness.prepare().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), token.execute_once())
                .await
                .is_err(),
            "the scripted boundary never completes"
        );
        assert!(!harness.route.may_have_dispatched());
        harness.physical.push(Step::Commit);
        token
            .execute_once()
            .await
            .expect("a proven pre-dispatch cancellation keeps dispatch authority");
    }

    #[tokio::test]
    async fn v2_journal_deadline_never_cancels_an_admitted_physical_mutation() {
        let harness = harness(vec![Step::HangAfterAdmission]).await;
        let token = harness.prepare().await;
        let mut execution = Box::pin(token.execute_once());
        tokio::select! {
            result = &mut execution => panic!("the admitted physical operation must remain pending: {result:?}"),
            () = async {
                while !harness.route.may_have_dispatched() {
                    tokio::task::yield_now().await;
                }
            } => {},
        }
        tokio::time::pause();
        tokio::time::advance(
            token
                .budget
                .original_deadline()
                .saturating_duration_since(tokio::time::Instant::now()),
        )
        .await;
        assert!(futures_util::poll!(&mut execution).is_pending());
        drop(execution);
        tokio::time::resume();
        assert!(harness.route.may_have_dispatched());
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert_eq!(
            token.release_resolved().await,
            Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved)
        );
        assert_eq!(harness.physical.voters().len(), 1);
        assert_eq!(harness.retained().await, 1);
    }

    #[tokio::test]
    async fn v2_handle_cancellation_after_dispatch_admission_is_receipt_only() {
        let harness = harness(vec![Step::HangAfterAdmission]).await;
        let token = harness.prepare().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), token.execute_once())
                .await
                .is_err()
        );
        assert!(harness.route.may_have_dispatched());
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted),
            "a cancelled possible send never regains mutation authority"
        );
        assert_eq!(harness.physical.voters().len(), 1);
        assert_eq!(
            token
                .status_once(tokio::time::Instant::now() + Duration::from_secs(1))
                .await,
            Ok(FencedTransitionV2Status::NotFound),
            "the handle keeps receipt authority"
        );
        assert_eq!(harness.retained().await, 1);
    }

    #[tokio::test]
    async fn v2_handle_rejects_a_missing_row_before_any_dispatch() {
        let harness = harness(vec![]).await;
        let token = harness.prepare().await;
        assert!(harness
            .backend
            .discard_protected_fenced_transition_v2(&token.prepared)
            .await
            .expect("remove the row out from under the handle"));
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert!(harness.physical.voters().is_empty());
    }

    #[test]
    fn v2_history_cache_serves_only_a_bindable_newest_state() {
        let cache = PreparedFencedV2HistoryCache::default();
        assert_eq!(cache.bindable(), None, "an empty cache forces a read");
        cache.observe(history_state(1, 1, 5));
        assert_eq!(cache.bindable(), Some(history_state(1, 1, 5)));
        cache.observe(history_state(1, 1, 3));
        assert_eq!(
            cache.bindable(),
            Some(history_state(1, 1, 5)),
            "an older concurrent read never replaces a newer one"
        );
        cache.observe(history_state(2, 2, 0));
        assert_eq!(cache.bindable(), Some(history_state(2, 2, 0)));
        cache.observe(history_state(1, 3, 0));
        assert_eq!(
            cache.bindable(),
            Some(history_state(2, 2, 0)),
            "an older active epoch never replaces a newer one"
        );
        cache.observe(history_state(
            2,
            2,
            FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
        ));
        assert_eq!(
            cache.bindable(),
            None,
            "a full active epoch is never served, so preparation reads again"
        );
        cache.observe(history_state(3, 3, 0));
        cache.invalidate_through(FencedTransitionV2HistoryEpoch::new(2).expect("epoch"));
        assert_eq!(
            cache.bindable(),
            Some(history_state(3, 3, 0)),
            "a rejection for an older epoch keeps a newer cached epoch"
        );
        cache.invalidate_through(FencedTransitionV2HistoryEpoch::new(3).expect("epoch"));
        assert_eq!(cache.bindable(), None);
    }

    #[tokio::test]
    async fn v2_handle_closed_or_full_epoch_rejection_invalidates_the_cached_epoch() {
        for error in [
            StoreError::FencedTransitionHistoryEpochNotActive,
            StoreError::FencedTransitionHistoryEpochRetired,
            StoreError::FencedTransitionHistoryFull,
        ] {
            let harness = harness(vec![Step::Reject(error.clone())]).await;
            let token = harness.prepare().await;
            assert!(harness.history.bindable().is_some());
            assert_eq!(
                token.execute_once().await,
                Err(FencedTransitionExecuteError::Rejected(error))
            );
            assert_eq!(
                harness.history.bindable(),
                None,
                "the next preparation reads the successor epoch"
            );
            assert_eq!(harness.retained().await, 0);
        }
    }

    #[tokio::test]
    async fn v2_handle_other_rejections_keep_the_cached_epoch() {
        let harness = harness(vec![Step::Reject(
            StoreError::FencedTransitionRetentionExhausted,
        )])
        .await;
        let token = harness.prepare().await;
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::Rejected(
                StoreError::FencedTransitionRetentionExhausted
            ))
        );
        assert_eq!(
            harness.history.bindable(),
            Some(history_state(1, 1, 0)),
            "only an epoch or capacity rejection names a stale active epoch"
        );
    }

    #[tokio::test]
    async fn v2_handle_unsent_row_whose_discard_failed_stays_releasable() {
        let directory = std::sync::Arc::new(StdMutex::new(None::<std::path::PathBuf>));
        let moved = Arc::clone(&directory);
        let harness = harness(vec![
            Step::NotTransmitted,
            Step::NotTransmitted,
            Step::NotTransmittedAfter(Arc::new(move || {
                // Move the journal away after the last authenticated reload,
                // so the handle's own discard fails closed.
                let path = moved.lock().expect("path").clone().expect("journal path");
                std::fs::rename(&path, path.with_extension("moved")).expect("move journal");
            })),
        ])
        .await;
        let journal = harness._directory.path().join("recovery.sqlite3");
        *directory.lock().expect("path") = Some(journal.clone());
        let token = harness.prepare().await;
        assert_eq!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
        assert_eq!(
            token.release_resolved().await,
            Err(SessionConsumerFencedTransitionV2ReleaseError::Unavailable),
            "the proven-unsent row is releasable, and the moved journal fails closed"
        );
        std::fs::rename(journal.with_extension("moved"), &journal).expect("restore journal");
        assert_eq!(
            harness.retained().await,
            1,
            "the failed discard kept the row"
        );
        token
            .release_resolved()
            .await
            .expect("a proven-unsent row is released once the journal is back");
        assert_eq!(harness.retained().await, 0);
    }

    #[tokio::test]
    async fn v2_status_until_terminal_returns_a_cached_local_failure_without_spinning() {
        let harness = harness(vec![Step::Unknown]).await;
        let token = harness.prepare().await;
        assert!(matches!(
            token.execute_once().await,
            Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
        ));
        // Another handle or a sweep removed the row after this handle became
        // receipt-only.
        assert!(harness
            .backend
            .discard_protected_fenced_transition_v2(&token.prepared)
            .await
            .expect("remove the row out from under the handle"));
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(2);
        assert_eq!(
            token.status_until_terminal(deadline).await,
            Err(SessionConsumerPreparedFencedTransitionStatusError::Unavailable),
            "the cached local failure is returned, not the caller's deadline"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "a cached terminal receipt ends the loop at once"
        );
    }

    fn diagnosed_handle(
        token: PersistentPreparedFencedTransitionV2Token,
    ) -> SessionConsumerPreparedFencedTransitionV2 {
        SessionConsumerPreparedFencedTransitionV2 { inner: token }
    }

    /// The closed stage vocabulary is fixed-label and value-free.
    #[test]
    fn v2_failure_diagnostic_stages_are_fixed_labels() {
        use SessionConsumerPreparedFencedTransitionV2FailureStage as Stage;
        for (stage, label) in [
            (Stage::Setup, "setup"),
            (Stage::Send, "send"),
            (Stage::AwaitingReply, "awaiting_reply"),
            (Stage::ReplyLost, "reply_lost"),
        ] {
            assert_eq!(stage.as_str(), label);
            let diagnostic =
                SessionConsumerPreparedFencedTransitionV2FailureDiagnostic::new(stage, 4321);
            assert_eq!(diagnostic.stage(), stage);
            assert_eq!(diagnostic.as_str(), label);
            assert_eq!(diagnostic.remaining_budget_millis(), 4321);
        }
    }

    /// The pure classifier distinguishes a pre-write attempt failure from a
    /// held reply and a lost reply, and reports no stage for a resolved
    /// revocation classification.
    #[test]
    fn v2_effect_failure_stage_classification_is_fixed() {
        use SessionConsumerPreparedFencedTransitionV2FailureStage as Stage;
        let request_id = opc_session_store::FencedTransitionV2RequestId::from_parts(
            opc_session_store::FencedTransitionV2HistoryEpoch::new(1).expect("epoch"),
            opc_session_store::FencedTransitionV2CallerNonce::from_bytes([0x75; 16]),
            [0x76; 32],
        );
        let not_transmitted = Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable,
        });
        assert_eq!(
            prepared_fenced_v2_effect_failure_stage(false, &not_transmitted),
            Some(Stage::Send)
        );
        let revoked = Err(PersistentSessionConsumerV2ExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::AuthorityRevoked,
        });
        assert_eq!(
            prepared_fenced_v2_effect_failure_stage(false, &revoked),
            None
        );
        let unknown = Err(PersistentSessionConsumerV2ExecuteError::OutcomeUnknown { request_id });
        assert_eq!(
            prepared_fenced_v2_effect_failure_stage(false, &unknown),
            Some(Stage::ReplyLost)
        );
        assert_eq!(
            prepared_fenced_v2_effect_failure_stage(true, &unknown),
            Some(Stage::AwaitingReply)
        );
        let deadline = Err(PersistentSessionConsumerV2ExecuteError::ReadUnavailable {
            cause: SessionConsumerClientError::Deadline,
        });
        assert_eq!(
            prepared_fenced_v2_effect_failure_stage(true, &deadline),
            Some(Stage::AwaitingReply)
        );
        let inexact_reply = Ok(SessionConsumerV2Response::Rejected(
            SessionConsumerRejection::Unavailable,
        ));
        assert_eq!(
            prepared_fenced_v2_effect_failure_stage(false, &inexact_reply),
            Some(Stage::ReplyLost)
        );
    }

    /// The fallback used only when the physical boundary did not record a
    /// more precise observation uses the installed attempt deadline.
    #[test]
    fn v2_ambiguous_failure_stage_falls_back_to_the_attempt_deadline() {
        use SessionConsumerPreparedFencedTransitionV2FailureStage as Stage;
        let now = tokio::time::Instant::now();
        assert_eq!(
            prepared_fenced_v2_ambiguous_failure_stage(Some(now + Duration::from_secs(1))),
            Stage::ReplyLost
        );
        assert_eq!(
            prepared_fenced_v2_ambiguous_failure_stage(Some(now - Duration::from_secs(1))),
            Stage::AwaitingReply
        );
        assert_eq!(
            prepared_fenced_v2_ambiguous_failure_stage(None),
            Stage::AwaitingReply
        );
    }

    /// A cold setup that never admits a physical attempt reports `setup` and a
    /// zero remaining budget, and consumes no dispatch authority.
    #[tokio::test]
    async fn v2_failure_diagnostic_reports_setup_when_original_budget_expired() {
        use SessionConsumerPreparedFencedTransitionV2FailureStage as Stage;
        let harness = harness(vec![Step::Commit]).await;
        let mut token = harness.prepare().await;
        // The immutable caller budget is already exhausted before execution.
        token.budget = PreparedCheckpointBudget::new(
            tokio::time::Instant::now() - Duration::from_millis(1),
            Duration::from_millis(100),
        )
        .expect("past original budget");
        let mut handle = diagnosed_handle(token);
        let failure = handle
            .execute_once_with_failure_diagnostic()
            .await
            .expect_err("an expired original budget must not commit");
        assert_eq!(
            failure.error(),
            &FencedTransitionExecuteError::NotTransmitted
        );
        let diagnostic = failure
            .diagnostic()
            .copied()
            .expect("a transport failure carries a diagnostic");
        assert_eq!(diagnostic.stage(), Stage::Setup);
        assert_eq!(diagnostic.remaining_budget_millis(), 0);
        assert!(
            harness.physical.voters().is_empty(),
            "no physical attempt may start"
        );
        assert!(!harness.route.may_have_dispatched());
        assert_eq!(
            handle
                .execute_once_with_failure_diagnostic()
                .await
                .map_err(|failure| failure.into_error()),
            Err(FencedTransitionExecuteError::NotTransmitted),
            "dispatch authority stays consumed"
        );
    }

    /// A refusal held past the physical attempt cap reports `awaiting_reply`
    /// with the remaining original budget still visible.
    #[tokio::test]
    async fn v2_failure_diagnostic_reports_awaiting_reply_for_held_refusal() {
        use SessionConsumerPreparedFencedTransitionV2FailureStage as Stage;
        let harness = harness(vec![Step::HoldPastAttemptDeadline]).await;
        let mut handle = diagnosed_handle(harness.prepare().await);
        let failure = handle
            .execute_once_with_failure_diagnostic()
            .await
            .expect_err("a held refusal is an ambiguous outcome");
        assert!(matches!(
            failure.error(),
            FencedTransitionExecuteError::OutcomeUnknown { request_id }
                if *request_id == harness.request_id
        ));
        let diagnostic = failure
            .diagnostic()
            .copied()
            .expect("an ambiguous outcome carries a diagnostic");
        assert_eq!(diagnostic.stage(), Stage::AwaitingReply);
        assert!(
            (1..=5_000).contains(&diagnostic.remaining_budget_millis()),
            "remaining original budget is bounded and still positive"
        );
        assert_eq!(
            harness.retained().await,
            1,
            "ownership unchanged: a possible send keeps the recovery row"
        );
    }

    /// A reply path that ends without an exact completion reports `reply_lost`.
    #[tokio::test]
    async fn v2_failure_diagnostic_reports_reply_lost() {
        use SessionConsumerPreparedFencedTransitionV2FailureStage as Stage;
        let harness = harness(vec![Step::Unknown]).await;
        let mut handle = diagnosed_handle(harness.prepare().await);
        let failure = handle
            .execute_once_with_failure_diagnostic()
            .await
            .expect_err("a lost reply is an ambiguous outcome");
        assert!(matches!(
            failure.error(),
            FencedTransitionExecuteError::OutcomeUnknown { .. }
        ));
        let diagnostic = failure
            .diagnostic()
            .copied()
            .expect("an ambiguous outcome carries a diagnostic");
        assert_eq!(diagnostic.stage(), Stage::ReplyLost);
    }

    /// The diagnostic wrapper preserves the previous effect classification and
    /// ownership for both committed and ambiguous results.
    #[tokio::test]
    async fn v2_diagnosed_execution_preserves_effects_and_ownership() {
        let plain_harness = harness(vec![Step::Commit]).await;
        let plain = plain_harness
            .prepare()
            .await
            .execute_once()
            .await
            .expect("plain commit");
        let diagnosed_harness = harness(vec![Step::Commit]).await;
        let mut handle = diagnosed_handle(diagnosed_harness.prepare().await);
        // The recorded wall-clock outcome differs between two installations;
        // the effect shape, dispatch path and release ownership must not.
        let diagnosed = handle
            .execute_once_with_failure_diagnostic()
            .await
            .expect("diagnosed commit");
        assert_eq!(diagnosed.committed_generation(), Generation::new(1));
        assert_eq!(plain.committed_generation(), Generation::new(1));
        assert_eq!(
            diagnosed_harness.physical.voters(),
            plain_harness.physical.voters()
        );
        assert_eq!(diagnosed_harness.retained().await, 1);
        handle
            .release_resolved()
            .await
            .expect("release after commit");
        assert_eq!(diagnosed_harness.retained().await, 0);

        let plain_harness = harness(vec![Step::Unknown]).await;
        let plain_error = plain_harness
            .prepare()
            .await
            .execute_once()
            .await
            .expect_err("plain ambiguity");
        let diagnosed_harness = harness(vec![Step::Unknown]).await;
        let mut handle = diagnosed_handle(diagnosed_harness.prepare().await);
        let diagnosed = handle
            .execute_once_with_failure_diagnostic()
            .await
            .expect_err("diagnosed ambiguity")
            .into_error();
        assert_eq!(diagnosed, plain_error);
        assert_eq!(diagnosed_harness.retained().await, 1);
        assert_eq!(
            handle
                .execute_once_with_failure_diagnostic()
                .await
                .map_err(|failure| failure.into_error()),
            Err(FencedTransitionExecuteError::NotTransmitted)
        );
    }

    /// A resolved rejection carries no diagnostic because no transport stage
    /// exists for it.
    #[tokio::test]
    async fn v2_failure_diagnostic_absent_for_resolved_rejection() {
        let harness = harness(vec![Step::Reject(
            StoreError::FencedTransitionRequestConflict,
        )])
        .await;
        let mut handle = diagnosed_handle(harness.prepare().await);
        let failure = handle
            .execute_once_with_failure_diagnostic()
            .await
            .expect_err("a conflict is a rejection");
        assert!(matches!(
            failure.error(),
            FencedTransitionExecuteError::Rejected(StoreError::FencedTransitionRequestConflict)
        ));
        assert!(failure.diagnostic().is_none());
    }

    /// The wrapper debug/display surface never renders the exact request
    /// identity, a scope/identity/endpoint, or payload material.
    #[test]
    fn v2_failure_diagnostic_is_value_free() {
        use SessionConsumerPreparedFencedTransitionV2FailureStage as Stage;
        let request_id = FencedTransitionRequestId::from_bytes([0x74; 16]);
        let failure = SessionConsumerPreparedFencedTransitionV2Failure {
            error: FencedTransitionExecuteError::OutcomeUnknown { request_id },
            diagnostic: Some(
                SessionConsumerPreparedFencedTransitionV2FailureDiagnostic::new(
                    Stage::AwaitingReply,
                    987,
                ),
            ),
        };
        let debug = format!("{failure:?}");
        assert!(debug.contains("outcome_unknown"), "{debug}");
        assert!(debug.contains("awaiting_reply"), "{debug}");
        assert!(debug.contains("987"), "{debug}");
        let rendered_id = format!("{request_id:?}");
        for forbidden in [
            "prepared-fenced-v2-unit",
            "spiffe://",
            "tenant",
            "owner",
            "endpoint",
            "request_id",
            "credential",
            rendered_id.as_str(),
        ] {
            assert!(
                !debug.contains(forbidden),
                "debug surface leaked {forbidden:?}: {debug}"
            );
        }
        let display = format!("{failure}");
        for forbidden in [
            "prepared-fenced-v2-unit",
            "spiffe://",
            "0x74",
            rendered_id.as_str(),
        ] {
            assert!(!display.contains(forbidden), "display leaked {forbidden:?}");
        }
    }
}
