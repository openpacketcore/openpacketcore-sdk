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
/// `FencedTransitionV2Capability::V2` over a prewarmed `/2` lane.
pub struct ActivatedSessionConsumerFencedTransitionV2Voters {
    router: Arc<PreparedConsumerRouter>,
    history: Option<FencedTransitionV2HistoryState>,
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

/// Fixed numeric result of one bounded reclamation sweep.
///
/// It contains no identity, epoch, key, or payload value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionConsumerFencedTransitionV2ReclaimReport {
    examined: usize,
    reclaimed: usize,
    retained: usize,
    interrupted: bool,
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

    /// Examined rows retained because their status is `Recorded`,
    /// `NotFound`, `RequestConflict`, or otherwise not reclaimable.
    pub const fn retained(&self) -> usize {
        self.retained
    }

    /// Whether the sweep stopped early at an unavailable status or at the
    /// caller's deadline. A later sweep resumes from the same position.
    pub const fn interrupted(&self) -> bool {
        self.interrupted
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
    fn wrap(
        &self,
        physical: Arc<dyn SessionBackend>,
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
    fn wrap(
        &self,
        physical: Arc<dyn SessionBackend>,
    ) -> Arc<dyn ProtectedFencedTransitionV2Backend> {
        let wrapper = EncryptingSessionBackend::new(
            physical,
            Arc::clone(&self.provider),
            self.backend_namespace.to_string(),
        )
        .with_fenced_transition_v2_recovery_journal(Arc::clone(&self.journal))
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
    fn wrap(
        &self,
        physical: Arc<dyn SessionBackend>,
    ) -> Arc<dyn ProtectedFencedTransitionV2Backend> {
        let wrapper = RemoteSealingSessionBackend::new(
            physical,
            Arc::clone(&self.provider),
            self.backend_namespace.to_string(),
        )
        .with_fenced_transition_v2_recovery_journal(Arc::clone(&self.journal))
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
    // and cleared only by that call's authoritative pre-write
    // classification. A handle cancelled while this is set may have sent.
    dispatch_admitted: AtomicBool,
}

impl PreparedFencedTransitionV2Route {
    fn new(origin: usize) -> Self {
        Self {
            mutation_cursor: AtomicUsize::new(origin),
            status_cursor: AtomicUsize::new(origin.wrapping_add(1)),
            attempt_deadline: StdMutex::new(None),
            dispatch_admitted: AtomicBool::new(false),
        }
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
/// facade cache (preparation) or must read linearized state (reclamation).
#[derive(Clone, Copy, PartialEq, Eq)]
enum V2HistoryRead {
    Cached,
    Fresh,
}

/// Net-private physical V2 adapter for one affine handle or one bounded
/// facade operation. It owns the activated roster but no global cursor map,
/// serves only the V2 subset, and fails every other operation locally.
struct ActivatedFencedTransitionV2Backend {
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

    /// The per-attempt deadline installed by the handle, or a fresh
    /// read-attempt cap bounded by this adapter's immutable deadline.
    fn attempt_deadline(&self) -> Option<tokio::time::Instant> {
        let deadline = self.route.attempt_deadline().unwrap_or_else(|| {
            tokio::time::Instant::now()
                .checked_add(self.attempt_timeout)
                .map_or(self.deadline, |capped| capped.min(self.deadline))
        });
        let deadline = deadline.min(self.deadline);
        (deadline > tokio::time::Instant::now()).then_some(deadline)
    }

    fn read_attempt_deadline(&self) -> Option<tokio::time::Instant> {
        let now = tokio::time::Instant::now();
        let deadline = now
            .checked_add(self.attempt_timeout)
            .map_or(self.deadline, |capped| capped.min(self.deadline));
        (deadline > now).then_some(deadline)
    }
}

/// Read linearized V2 history state, traversing the canonical roster from
/// `origin`. Every attempt is read-only, so an interrupted read may move to
/// the next voter under the caller's deadline.
async fn linearized_v2_history_state(
    router: &PreparedConsumerRouter,
    origin: usize,
    attempt_deadline: impl Fn() -> Option<tokio::time::Instant>,
) -> Result<FencedTransitionV2HistoryState, StoreError> {
    let voter_count = router.clients.len();
    for offset in 0..voter_count {
        let Some(deadline) = attempt_deadline() else {
            break;
        };
        let client =
            &router.clients[prepared_voter_index(origin.wrapping_add(offset), voter_count)];
        let request = SessionConsumerV2Request::new(
            router.scope,
            SessionConsumerV2Operation::FencedTransitionV2HistoryState,
        );
        let response = client.execute_v2_before(&request, deadline).await;
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

fn v2_authority_revoked(
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
        // deadline; retrying an interrupted read spends no dispatch authority.
        let voter_count = self.voter_count();
        let mut last_unavailable = None;
        for offset in 0..voter_count {
            let Some(deadline) = self.read_attempt_deadline() else {
                break;
            };
            let client = &self.router.clients[prepared_voter_index(
                self.route.mutation_voter(voter_count).wrapping_add(offset),
                voter_count,
            )];
            let request = SessionConsumerRequest::new(
                self.router.scope,
                SessionConsumerRequestId::new(),
                SessionConsumerOperation::PreflightRecordExpiry {
                    preflights: preflights.to_vec(),
                },
            );
            let response = tokio::time::timeout_at(
                deadline,
                client.execute_classified_before(&request, deadline, 1),
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
        Ok(Some(FencedTransitionV2Capability::V2))
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
            || self.read_attempt_deadline(),
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
            return FencedTransitionV2Effect::NotTransmitted(prepared_fenced_v2_deadline());
        };
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
                FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(
                    "prepared fenced transition V2 was not transmitted".into(),
                ))
            }
            // Every other response, including an uncorrelated success, a
            // recorded deterministic error that the client does not accept
            // as an exact completion, and any post-write loss, may have
            // crossed the effect boundary.
            _ => FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: vec![request.request_id()],
            },
        }
    }

    async fn fenced_transition_v2_status(
        &self,
        request: &FencedTransitionV2Request,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        let Some(deadline) = self.attempt_deadline() else {
            return Err(prepared_fenced_v2_deadline());
        };
        let voter = self.route.next_status_voter(self.voter_count());
        let wire = SessionConsumerV2Request::new(
            self.router.scope,
            SessionConsumerV2Operation::FencedTransitionV2Status {
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
    /// other result refuses construction. The returned roster is opaque and
    /// canonicalized by node ordinal.
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
                    FencedTransitionV2Capability::V2,
                ))) => Ok(()),
                Ok(SessionConsumerV2Response::FencedTransitionV2Capability(_)) => {
                    Err(StoreError::CapabilityNotSupported(
                        "atomic_fenced_transition_epoch_history_v2".into(),
                    ))
                }
                _ => Err(prepared_fenced_v2_readiness_unavailable()),
            }
        }))
        .await;
        for capability in capabilities {
            capability?;
        }

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
        let read_deadline = tokio::time::Instant::now()
            .checked_add(DEFAULT_CONSUMER_OPERATION_TIMEOUT)
            .unwrap_or_else(tokio::time::Instant::now);
        let history = match linearized_v2_history_state(&router, 0, || {
            (tokio::time::Instant::now() < read_deadline).then_some(read_deadline)
        })
        .await
        {
            Ok(state) => Some(state),
            Err(StoreError::TopologyAuthorityRevoked) => {
                return Err(StoreError::TopologyAuthorityRevoked);
            }
            Err(_) => None,
        };
        Ok(ActivatedSessionConsumerFencedTransitionV2Voters {
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

    fn backend_for_route(
        &self,
        route: Arc<PreparedFencedTransitionV2Route>,
        budget: PreparedCheckpointBudget,
        history_read: V2HistoryRead,
    ) -> Arc<dyn ProtectedFencedTransitionV2Backend> {
        self.wrapper_factory
            .wrap(Arc::new(ActivatedFencedTransitionV2Backend {
                router: Arc::clone(&self.router),
                route,
                history: Arc::clone(&self.history),
                history_read,
                deadline: budget.original_deadline(),
                attempt_timeout: budget.physical_attempt_timeout(),
            }))
    }

    fn local_backend(&self) -> Arc<dyn ProtectedFencedTransitionV2Backend> {
        // Journal-only and observation work never reaches a V2 mutation, so
        // one bounded default operation window is sufficient here.
        let deadline = tokio::time::Instant::now()
            .checked_add(DEFAULT_CONSUMER_OPERATION_TIMEOUT)
            .unwrap_or_else(tokio::time::Instant::now);
        self.wrapper_factory
            .wrap(Arc::new(ActivatedFencedTransitionV2Backend {
                router: Arc::clone(&self.router),
                route: Arc::new(PreparedFencedTransitionV2Route::new(0)),
                history: Arc::clone(&self.history),
                history_read: V2HistoryRead::Cached,
                deadline,
                attempt_timeout: DEFAULT_CONSUMER_OPERATION_TIMEOUT,
            }))
    }

    /// Read the current record head and durable fence floor for one exact key
    /// and return a present record in caller-visible unprotected form.
    ///
    /// This uses the existing exact-key observation operation and adds no
    /// raw backend, prepared request, or dispatch authority.
    pub async fn observe_fenced_transition(
        &self,
        key: &opc_session_store::SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        self.local_backend()
            .observe_protected_fenced_transition_v2(key)
            .await
    }

    /// Prepare one protected V2 transition and retain it in a move-only,
    /// affine dispatch handle.
    ///
    /// The wrapper selects the linearized active epoch, seals a create or
    /// update record once, and durably binds `request.request_id()` to the
    /// complete sealed request before this returns. A retained caller ID,
    /// including one retained by a composed legacy V1 journal, is a conflict;
    /// a full recovery journal or full active epoch is
    /// `FencedTransitionHistoryFull`.
    pub async fn prepare_fenced_transition(
        &self,
        request: FencedTransitionRequest,
        budget: PreparedCheckpointBudget,
    ) -> Result<SessionConsumerPreparedFencedTransitionV2, StoreError> {
        let deadline = budget.original_deadline();
        if tokio::time::Instant::now() >= deadline {
            return Err(prepared_fenced_v2_deadline());
        }
        let route = Arc::new(PreparedFencedTransitionV2Route::new(
            prepared_fenced_v2_origin(&self.router, request.request_id()),
        ));
        let backend = self.backend_for_route(Arc::clone(&route), budget, V2HistoryRead::Cached);
        let prepared = tokio::time::timeout_at(
            deadline,
            backend.prepare_protected_fenced_transition_v2(request),
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
            ),
        })
    }

    /// Reopen a retained transition by its caller-stable ID as a
    /// receipt-only handle.
    ///
    /// This is a local journal lookup: it needs neither the plaintext body
    /// nor a key provider, and it never restores dispatch authority. `None`
    /// means neither this facade's recovery journal nor a composed legacy V1
    /// journal retains the ID: it was never prepared through them, or its row
    /// was released or reclaimed after resolution.
    pub async fn recover_fenced_transition_status(
        &self,
        request_id: FencedTransitionRequestId,
        budget: PreparedCheckpointBudget,
    ) -> Result<Option<SessionConsumerRecoveredFencedTransition>, StoreError> {
        let deadline = budget.original_deadline();
        if tokio::time::Instant::now() >= deadline {
            return Err(prepared_fenced_v2_deadline());
        }
        let route = Arc::new(PreparedFencedTransitionV2Route::new(
            prepared_fenced_v2_origin(&self.router, request_id),
        ));
        let backend = self.backend_for_route(Arc::clone(&route), budget, V2HistoryRead::Cached);
        tokio::time::timeout_at(deadline, async {
            let retained = backend
                .recover_protected_fenced_transition_v2(request_id)
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
                            ),
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

    /// Run one bounded reclamation sweep over retained rows.
    ///
    /// It first reads the linearized history state once and removes rows at
    /// or below its retired floor without further I/O. It then reads the exact status of at most `limit` rows in
    /// caller-ID order from a process-local cursor and removes those whose
    /// status is `Expired`, `Retired`, `HistoryFull`, `RetentionExhausted`,
    /// or `EpochNotActive` for an epoch below the active epoch. It retains
    /// `Recorded`, `NotFound`, and `RequestConflict` rows and stops at the
    /// first unavailable status or at the budget's deadline. `limit` must be
    /// in `1..=FENCED_TRANSITION_V2_RECOVERY_RECLAIM_BATCH_MAX`.
    ///
    /// The caller owns scheduling. Epoch rotation and retired-floor
    /// advancement remain the state process's replicated maintenance.
    pub async fn reclaim_resolved_fenced_transitions(
        &self,
        limit: usize,
        budget: PreparedCheckpointBudget,
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
        let backend = self.backend_for_route(Arc::clone(&route), budget, V2HistoryRead::Fresh);
        // One linearized history read supplies both the retired floor, which
        // the wrapper applies itself, and the active epoch used below.
        let (history, retired) = tokio::time::timeout_at(
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
        let page = tokio::time::timeout_at(
            deadline,
            backend.protected_fenced_transition_v2_page(cursor, remaining),
        )
        .await
        .map_err(|_| prepared_fenced_v2_deadline())??;
        let mut next_cursor = cursor;
        let wrapped = page.len() < remaining;
        for (request_id, history_epoch) in page {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                report.interrupted = true;
                break;
            }
            let Some(attempt_deadline) = now
                .checked_add(budget.physical_attempt_timeout())
                .map(|capped| capped.min(deadline))
            else {
                report.interrupted = true;
                break;
            };
            route.install_attempt_deadline(attempt_deadline);
            let prepared = match tokio::time::timeout_at(
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
            let status = tokio::time::timeout_at(
                attempt_deadline,
                backend.protected_fenced_transition_v2_status(&prepared),
            )
            .await;
            let reclaimable = match status {
                Ok(Ok(
                    FencedTransitionV2Status::Expired
                    | FencedTransitionV2Status::Retired
                    | FencedTransitionV2Status::HistoryFull
                    | FencedTransitionV2Status::RetentionExhausted,
                )) => true,
                // A request in an epoch below the active epoch can never bind.
                Ok(Ok(FencedTransitionV2Status::EpochNotActive)) => history
                    .active_epoch()
                    .is_some_and(|active| history_epoch < active),
                Ok(Ok(_)) => false,
                Ok(Err(StoreError::TopologyAuthorityRevoked)) => {
                    return Err(StoreError::TopologyAuthorityRevoked);
                }
                Ok(Err(_)) | Err(_) => {
                    report.interrupted = true;
                    break;
                }
            };
            report.examined += 1;
            if reclaimable {
                match backend
                    .discard_protected_fenced_transition_v2(&prepared)
                    .await
                {
                    Ok(_) => report.reclaimed += 1,
                    Err(_) => {
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
    /// `FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES`.
    pub async fn retained_fenced_transitions(&self) -> Result<usize, StoreError> {
        self.local_backend()
            .retained_protected_fenced_transitions_v2()
            .await
    }
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

    /// Dispatch the retained mutation once.
    ///
    /// A possible send permanently removes dispatch authority and returns
    /// `OutcomeUnknown` with the caller-stable ID; use receipt status only
    /// afterwards. When every candidate voter proved a pre-dispatch failure,
    /// or the V2 history definitively rejected the request without binding
    /// it, this handle removes its own retained row.
    pub async fn execute_once(
        &mut self,
    ) -> Result<FencedTransitionOutcome, FencedTransitionExecuteError> {
        self.inner.execute_once().await
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
    pub async fn status_until_terminal(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError> {
        self.inner.status_until_terminal(deadline).await
    }

    /// Remove the retained row after this handle observed a resolution.
    ///
    /// A matching outcome, a definitive rejection other than
    /// `TopologyAuthorityRevoked`, or a terminal status other than
    /// `RequestConflict` permits release. Afterwards the caller-stable ID is
    /// no longer retained: recovery returns `None`, and the ID may name a new
    /// transition. Callers must derive later work from authoritative
    /// observation. Releasing twice is a no-op.
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
    /// the caller's absolute deadline is reached.
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

struct PersistentPreparedFencedTransitionV2Token {
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

/// Definitive V2 rejections that prove the exact request has not bound a
/// receipt and never will.
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
            backend,
            prepared,
            budget,
            voter_count,
            route,
            history,
            state,
            original,
            terminal_receipt: StdMutex::new(None),
            resolution: StdMutex::new(V2Resolution::Unresolved),
        }
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
        if self
            .backend
            .discard_protected_fenced_transition_v2(&self.prepared)
            .await
            .is_ok()
        {
            self.set_resolution(V2Resolution::Released);
        }
    }

    async fn execute_once(&self) -> Result<FencedTransitionOutcome, FencedTransitionExecuteError> {
        let Some(mut preparation) =
            PreparedFencedV2PreparationGuard::begin(&self.state, &self.route, self.voter_count)
        else {
            return Err(FencedTransitionExecuteError::NotTransmitted);
        };
        // Authenticate the exact retained row before any lane work. The
        // wrapper repeats this immediately before each physical dispatch.
        if !matches!(
            tokio::time::timeout_at(
                self.budget.original_deadline(),
                self.backend
                    .preflight_protected_fenced_transition_v2(&self.prepared),
            )
            .await,
            Ok(Ok(()))
        ) {
            preparation.terminal();
            return Err(FencedTransitionExecuteError::NotTransmitted);
        }
        for _ in 0..self.voter_count {
            let now = tokio::time::Instant::now();
            let Some(attempt_deadline) = now
                .checked_add(self.budget.physical_attempt_timeout())
                .map(|capped| capped.min(self.budget.original_deadline()))
            else {
                break;
            };
            if attempt_deadline <= now {
                break;
            }
            self.route.install_attempt_deadline(attempt_deadline);
            // The lane actor honors the attempt deadline and classifies the
            // result itself; this future is never cancelled to bound it.
            match self
                .backend
                .protected_fenced_transition_v2_effect(&self.prepared)
                .await
            {
                FencedTransitionV2Effect::Resolved(Ok(outcome)) => {
                    preparation.terminal();
                    self.set_resolution(V2Resolution::Resolved);
                    return Ok(outcome);
                }
                FencedTransitionV2Effect::Resolved(Err(StoreError::TopologyAuthorityRevoked)) => {
                    // Revocation is classified before any Call byte, and every
                    // earlier attempt proved the same. Nothing was sent.
                    preparation.terminal();
                    self.discard_own_unbound_row().await;
                    return Err(FencedTransitionExecuteError::Rejected(
                        StoreError::TopologyAuthorityRevoked,
                    ));
                }
                FencedTransitionV2Effect::Resolved(Err(error)) => {
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
                _ => {
                    preparation.receipt_only();
                    return Err(FencedTransitionExecuteError::OutcomeUnknown {
                        request_id: self.prepared.request_id(),
                    });
                }
            }
        }
        // Every candidate proved that no Call byte was accepted, and only this
        // handle can dispatch the row, so no copy of the request was sent.
        preparation.terminal();
        self.discard_own_unbound_row().await;
        Err(FencedTransitionExecuteError::NotTransmitted)
    }

    fn cached_terminal_receipt(
        &self,
    ) -> Option<Result<FencedTransitionV2Status, SessionConsumerPreparedFencedTransitionStatusError>>
    {
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
        match tokio::time::timeout_at(
            deadline,
            self.backend
                .preflight_protected_fenced_transition_v2(&self.prepared),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
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
        let attempt_deadline = deadline.min(
            now.checked_add(self.budget.physical_attempt_timeout())
                .ok_or(SessionConsumerPreparedFencedTransitionStatusError::Deadline)?,
        );
        let physical_cap_active = attempt_deadline < deadline;
        let _attempt = self
            .state
            .begin_status()
            .map_err(|_| SessionConsumerPreparedFencedTransitionStatusError::Unavailable)?;
        if let Some(result) = self.cached_terminal_receipt() {
            return result;
        }
        self.route.install_attempt_deadline(attempt_deadline);
        let result = match tokio::time::timeout_at(
            attempt_deadline,
            self.backend
                .protected_fenced_transition_v2_status(&self.prepared),
        )
        .await
        {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(StoreError::TopologyAuthorityRevoked)) => {
                Err(SessionConsumerPreparedFencedTransitionStatusError::TopologyAuthorityRevoked)
            }
            Ok(Err(_)) => Err(SessionConsumerPreparedFencedTransitionStatusError::Unavailable),
            Err(_) if physical_cap_active => {
                Err(SessionConsumerPreparedFencedTransitionStatusError::AttemptDeadline)
            }
            Err(_) => Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline),
        };
        match result {
            // NotFound is non-exclusionary while the request's epoch is
            // active; unavailable and per-attempt deadlines stay retryable.
            Ok(FencedTransitionV2Status::NotFound)
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
        match self.resolution() {
            V2Resolution::Released => Ok(()),
            V2Resolution::Unresolved => {
                Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved)
            }
            V2Resolution::Resolved => {
                // The row may already have been reclaimed by a sweep; the
                // compare-and-delete then removes nothing and release still
                // completes.
                self.backend
                    .discard_protected_fenced_transition_v2(&self.prepared)
                    .await
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

    #[derive(Clone)]
    enum Step {
        NotTransmitted,
        Commit,
        Unknown,
        Reject(StoreError),
        HangBeforeAdmission,
        HangAfterAdmission,
    }

    /// Scripted V2 physical boundary that mimics the private adapter's
    /// dispatch-admission latch on the handle's own route.
    struct ScriptedV2Physical {
        route: Arc<PreparedFencedTransitionV2Route>,
        steps: StdMutex<VecDeque<Step>>,
        voters: StdMutex<Vec<usize>>,
        status: StdMutex<FencedTransitionV2Status>,
        committed: StdMutex<Option<FencedTransitionOutcome>>,
    }

    impl ScriptedV2Physical {
        fn new(route: Arc<PreparedFencedTransitionV2Route>, steps: Vec<Step>) -> Arc<Self> {
            Arc::new(Self {
                route,
                steps: StdMutex::new(steps.into()),
                voters: StdMutex::new(Vec::new()),
                status: StdMutex::new(FencedTransitionV2Status::NotFound),
                committed: StdMutex::new(None),
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
                Step::NotTransmitted => FencedTransitionV2Effect::NotTransmitted(
                    StoreError::BackendUnavailable("scripted pre-write failure".into()),
                ),
                Step::Commit => {
                    self.route.admit_dispatch();
                    let outcome = outcome_for(&request);
                    *self.committed.lock().expect("committed") = Some(outcome.clone());
                    FencedTransitionV2Effect::Resolved(Ok(outcome))
                }
                Step::Unknown => {
                    self.route.admit_dispatch();
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
            }
        }

        async fn fenced_transition_v2_status(
            &self,
            _request: &FencedTransitionV2Request,
        ) -> Result<FencedTransitionV2Status, StoreError> {
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
                .with_fenced_transition_v2_recovery_journal(journal)
                .with_fenced_transition_v2_journal_scope(
                    FencedTransitionV2JournalScope::from_bytes([0x73; 32]),
                ),
        );
        Harness {
            _directory: directory,
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
}
