//! Protected V2 prepared transitions recoverable by caller-stable identity.
//!
//! This is the store half of the #982 consumer facade. A protection wrapper
//! selects the linearized active V2 epoch internally, seals a create or update
//! record exactly once, and durably binds the caller's stable
//! [`FencedTransitionRequestId`] to the complete sealed V2 request before any
//! dispatch. Execution and status reload and compare that authenticated row
//! and dispatch only its exact bytes. The raw `fenced_transition_v2` wrapper
//! path and its body-keyed journal are unchanged.

use super::*;
use crate::{
    fenced_transition::{
        FencedTransitionV2CallerNonce, FencedTransitionV2HistoryEpoch, PreparedFencedTransitionV2,
        PreparedFencedTransitionV2Lookup, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
    },
    fenced_transition_journal::{
        canonical_recovery_request, FencedTransitionV2RecoveryJournal, RecoveryJournalAdmission,
    },
};

const PROTECTED_V2_RECOVERY_CAPABILITY: &str = "protected_fenced_transition_v2_recovery";
const PROTECTED_V2_RECOVERY_ROW_UNAVAILABLE: &str =
    "protected fenced-transition V2 recovery row unavailable";

/// Sealed SDK composition port for the protected V2 consumer facade.
///
/// Only [`EncryptingSessionBackend`] and [`RemoteSealingSessionBackend`]
/// implement this port, and only when configured with a
/// [`FencedTransitionV2RecoveryJournal`] and an explicit backend journal
/// scope. It is a composition boundary for the SDK consumer facade, not an
/// application API: the facade retains the wrapper privately and exposes
/// neither it nor a physical request.
///
/// Every method fails closed without provider or transport I/O when the
/// recovery journal, its scope binding, the payload namespace, or the inner
/// V2 physical boundary is missing or invalid.
///
/// ```compile_fail
/// use opc_session_store::ProtectedFencedTransitionV2Backend;
///
/// struct ProductBackend;
///
/// // Fails: the SDK-owned sealed supertrait is not externally nameable.
/// impl ProtectedFencedTransitionV2Backend for ProductBackend {}
/// ```
#[doc(hidden)]
#[async_trait]
pub trait ProtectedFencedTransitionV2Backend:
    protected_fenced_transition_backend_seal::Sealed + Send + Sync
{
    /// Observe one exact key's record head and durable fence floor through
    /// the V2 physical boundary, unprotecting only a present record.
    async fn observe_protected_fenced_transition_v2(
        &self,
        key: &SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError>;

    /// Select the active epoch, seal once, and durably bind the caller ID to
    /// the complete sealed V2 request before returning.
    async fn prepare_protected_fenced_transition_v2(
        &self,
        request: FencedTransitionRequest,
    ) -> Result<PreparedFencedTransitionV2, StoreError>;

    /// Reload the exact retained sealed request for one caller-stable ID.
    async fn recover_protected_fenced_transition_v2(
        &self,
        request_id: FencedTransitionRequestId,
    ) -> Result<PreparedFencedTransitionV2Lookup, StoreError>;

    /// Locally authenticate that `prepared` is still the exact retained row.
    async fn preflight_protected_fenced_transition_v2(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<(), StoreError>;

    /// Dispatch only the exact retained sealed request, preserving whether it
    /// may have crossed the physical effect boundary.
    async fn protected_fenced_transition_v2_effect(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>>;

    /// Read the exact receipt status of the retained sealed request.
    async fn protected_fenced_transition_v2_status(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<FencedTransitionV2Status, StoreError>;

    /// Remove the retained row only while it still holds `prepared` exactly.
    ///
    /// Callers must have proved that the transition is resolved or can never
    /// bind a receipt; this method performs no network I/O.
    async fn discard_protected_fenced_transition_v2(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<bool, StoreError>;

    /// Read the linearized V2 history state through the physical boundary.
    async fn protected_fenced_transition_v2_history_state(
        &self,
    ) -> Result<FencedTransitionV2HistoryState, StoreError>;

    /// Return at most `limit` retained caller IDs and their history epochs in
    /// ascending caller-ID order after `after`.
    async fn protected_fenced_transition_v2_page(
        &self,
        after: Option<FencedTransitionRequestId>,
        limit: usize,
    ) -> Result<Vec<(FencedTransitionRequestId, FencedTransitionV2HistoryEpoch)>, StoreError>;

    /// Read the linearized V2 history state through the physical boundary,
    /// then remove at most `limit` retained rows at or below its retired
    /// floor. Returns that state and the number of rows removed.
    ///
    /// The floor is never caller-supplied: a request at or below the floor
    /// observed here can never bind again.
    async fn reclaim_retired_protected_fenced_transitions_v2(
        &self,
        limit: usize,
    ) -> Result<(FencedTransitionV2HistoryState, usize), StoreError>;

    /// Return the authenticated number of retained rows.
    async fn retained_protected_fenced_transitions_v2(&self) -> Result<usize, StoreError>;
}

pub(super) fn unsupported_protected_fenced_transition_v2_recovery() -> StoreError {
    StoreError::CapabilityNotSupported(PROTECTED_V2_RECOVERY_CAPABILITY.into())
}

fn recovery_row_unavailable() -> StoreError {
    StoreError::BackendUnavailable(PROTECTED_V2_RECOVERY_ROW_UNAVAILABLE.into())
}

/// Bind one recovery journal to its exact wrapper authority.
///
/// The commitment covers the protection mode, the explicitly configured
/// stable backend scope, and the payload namespace. A journal bound to one of
/// these can never be read under another.
pub(crate) fn protected_fenced_transition_v2_recovery_scope(
    configured_scope: Option<FencedTransitionV2JournalScope>,
    backend_namespace: &str,
    mode: ProtectedFencedTransitionV2JournalMode,
) -> Result<[u8; 32], StoreError> {
    let payload_scope = protected_payload_scope_commitment(backend_namespace)
        .ok_or_else(unsupported_protected_fenced_transition_v2_recovery)?;
    let backend_scope =
        configured_scope.ok_or_else(unsupported_protected_fenced_transition_v2_recovery)?;
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-store/protected-v2-recovery-journal/wrapper-scope/v1\0");
    digest.update([mode.tag()]);
    digest.update(backend_scope.as_bytes());
    digest.update(payload_scope);
    Ok(digest.finalize().into())
}

/// Borrowed view of one protection wrapper's #982 configuration.
pub(super) struct ProtectedV2RecoveryParts<'a, B: ?Sized> {
    pub(super) inner: &'a B,
    pub(super) recovery_journal: Option<&'a Arc<FencedTransitionV2RecoveryJournal>>,
    pub(super) legacy_journal: Option<&'a Arc<PreparedFencedTransitionJournal>>,
    pub(super) configured_scope: Option<FencedTransitionV2JournalScope>,
    pub(super) backend_namespace: &'a str,
    pub(super) mode: ProtectedFencedTransitionV2JournalMode,
}

impl<'a, B> ProtectedV2RecoveryParts<'a, B>
where
    B: SessionBackend + ?Sized,
{
    /// Resolve the journal and bind it to this wrapper's scope. Binding is a
    /// write only for a never-used journal.
    async fn bound_journal(
        &self,
    ) -> Result<(&'a Arc<FencedTransitionV2RecoveryJournal>, [u8; 32]), StoreError> {
        let scope = protected_fenced_transition_v2_recovery_scope(
            self.configured_scope,
            self.backend_namespace,
            self.mode,
        )?;
        let journal = self
            .recovery_journal
            .ok_or_else(unsupported_protected_fenced_transition_v2_recovery)?;
        journal.ensure_scope(scope).await?;
        Ok((journal, scope))
    }

    async fn require_v2_boundary(&self) -> Result<(), StoreError> {
        require_fenced_transition_v2_capability(self.inner).await
    }

    pub(super) async fn observe<U, UnprotectFuture>(
        &self,
        key: &SessionKey,
        unprotect: U,
    ) -> Result<FencedTransitionObservation, StoreError>
    where
        U: FnOnce(Option<StoredSessionRecord>) -> UnprotectFuture,
        UnprotectFuture: Future<Output = Result<Option<StoredSessionRecord>, StoreError>>,
    {
        self.bound_journal().await?;
        self.require_v2_boundary().await?;
        let observation = self.inner.observe_fenced_transition(key).await?;
        if observation
            .record()
            .is_some_and(|record| record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1)
        {
            return Err(unsupported_protected_fenced_transition_v2_recovery());
        }
        let record = unprotect(observation.record().cloned()).await?;
        FencedTransitionObservation::new(record, observation.current_fence())
    }

    pub(super) async fn prepare<S, SealFuture>(
        &self,
        request: FencedTransitionRequest,
        seal: S,
    ) -> Result<PreparedFencedTransitionV2, StoreError>
    where
        S: Fn(StoredSessionRecord) -> SealFuture,
        SealFuture: Future<Output = Result<StoredSessionRecord, StoreError>>,
    {
        request.validate()?;
        if request
            .mutation()
            .record()
            .is_some_and(|record| record.payload.encoding() != SessionPayloadEncoding::Plaintext)
        {
            return Err(unsupported_protected_fenced_transition_v2_recovery());
        }
        let (journal, scope) = self.bound_journal().await?;
        self.require_v2_boundary().await?;
        let request_id = request.request_id();
        // Held from the cross-journal check through this journal's insert, so
        // a concurrent V1 or V2 preparation of the same ID cannot pass its
        // own check in between.
        let _admission = journal.admit(request_id)?;
        // A caller-stable ID names exactly one logical operation across both
        // protected compositions. A retained #701 row keeps its V1 recovery
        // authority; V2 preparation must not start a second lineage under it.
        if let Some(legacy) = self.legacy_journal {
            if matches!(
                legacy.lookup(request_id).await?,
                PreparedFencedTransitionLookup::Found(_)
            ) {
                return Err(StoreError::FencedTransitionRequestConflict);
            }
        }
        journal.ensure_absent(scope, request_id).await?;
        // The facade chooses the only epoch that may bind a new identity.
        // A full active epoch cannot bind before the operator's maintenance
        // opens its successor, so it is rejected without journal or provider
        // work.
        let history = self.inner.fenced_transition_v2_history_state().await?;
        let epoch = history
            .active_epoch()
            .ok_or_else(unsupported_protected_fenced_transition_v2_recovery)?;
        if history.bound_entries() >= FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
            return Err(StoreError::FencedTransitionHistoryFull);
        }
        if let Some(record) = request.mutation().record() {
            let preflight = RecordExpiryPreflight::from_record(record);
            self.inner
                .preflight_record_expiry(std::slice::from_ref(&preflight))
                .await?;
        }
        let (_, lease, mutation) = request.into_parts();
        let mutation = match mutation {
            FencedTransitionMutation::Create { record } => {
                FencedTransitionMutation::create(seal(*record).await?)
            }
            FencedTransitionMutation::Update {
                expected_generation,
                record,
            } => FencedTransitionMutation::update(expected_generation, seal(*record).await?),
            FencedTransitionMutation::Delete {
                expected_generation,
            } => FencedTransitionMutation::delete(expected_generation),
            FencedTransitionMutation::RefreshTtl {
                expected_generation,
                ttl,
            } => FencedTransitionMutation::refresh_ttl(expected_generation, ttl)?,
        };
        let sealed = FencedTransitionV2Request::new(
            epoch,
            FencedTransitionV2CallerNonce::new(),
            lease,
            mutation,
        )?;
        require_fenced_transition_v2_physical_envelope(&sealed)?;
        journal.insert(scope, request_id, &sealed).await?;
        Ok(PreparedFencedTransitionV2::new(request_id, sealed))
    }

    pub(super) async fn recover(
        &self,
        request_id: FencedTransitionRequestId,
    ) -> Result<PreparedFencedTransitionV2Lookup, StoreError> {
        require_fenced_transition_physical_boundary(self.inner)?;
        let (journal, scope) = self.bound_journal().await?;
        match journal.lookup(scope, request_id).await? {
            Some(request) => {
                require_fenced_transition_v2_physical_envelope(&request)?;
                Ok(PreparedFencedTransitionV2Lookup::Found(
                    PreparedFencedTransitionV2::new(request_id, request),
                ))
            }
            None => Ok(PreparedFencedTransitionV2Lookup::Absent),
        }
    }

    /// Reload the authenticated row and require the complete canonical bytes
    /// to equal the retained value. A missing row is unavailable, a different
    /// row is a conflict; neither permits dispatch.
    pub(super) async fn require_exact(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<(), StoreError> {
        require_fenced_transition_physical_boundary(self.inner)?;
        let (journal, scope) = self.bound_journal().await?;
        let Some(stored) = journal.lookup(scope, prepared.request_id()).await? else {
            return Err(recovery_row_unavailable());
        };
        if canonical_recovery_request(&stored)?.as_slice()
            != canonical_recovery_request(prepared.physical_request())?.as_slice()
        {
            return Err(StoreError::FencedTransitionRequestConflict);
        }
        require_fenced_transition_v2_physical_envelope(&stored)
    }

    pub(super) async fn effect(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>> {
        if let Err(error) = self.require_exact(prepared).await {
            return FencedTransitionV2Effect::NotTransmitted(error);
        }
        if let Err(error) = self.require_v2_boundary().await {
            return FencedTransitionV2Effect::NotTransmitted(error);
        }
        let physical = prepared.physical_request();
        let unknown = || FencedTransitionV2Effect::OutcomeUnknown {
            request_ids: vec![physical.request_id()],
        };
        match self
            .inner
            .fenced_transition_v2_effect(physical.clone())
            .await
        {
            FencedTransitionV2Effect::NotTransmitted(error) => {
                FencedTransitionV2Effect::NotTransmitted(error)
            }
            FencedTransitionV2Effect::Resolved(Ok(outcome))
                if outcome.matches_v2_request(physical) =>
            {
                FencedTransitionV2Effect::Resolved(Ok(outcome))
            }
            // A success that does not correlate with the exact request, or a
            // lower layer that still reports ambiguity inside a result, keeps
            // the conservative may-have-sent classification.
            FencedTransitionV2Effect::Resolved(Ok(_))
            | FencedTransitionV2Effect::Resolved(Err(StoreError::FencedTransitionOutcomeUnknown))
            | FencedTransitionV2Effect::OutcomeUnknown { .. } => unknown(),
            FencedTransitionV2Effect::Resolved(Err(error)) => {
                FencedTransitionV2Effect::Resolved(Err(error))
            }
        }
    }

    pub(super) async fn status(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        self.require_exact(prepared).await?;
        self.require_v2_boundary().await?;
        self.inner
            .fenced_transition_v2_status(prepared.physical_request())
            .await
    }

    pub(super) async fn discard(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<bool, StoreError> {
        let (journal, scope) = self.bound_journal().await?;
        journal
            .remove_if_exact(scope, prepared.request_id(), prepared.physical_request())
            .await
    }

    pub(super) async fn history_state(&self) -> Result<FencedTransitionV2HistoryState, StoreError> {
        self.bound_journal().await?;
        self.require_v2_boundary().await?;
        self.inner.fenced_transition_v2_history_state().await
    }

    pub(super) async fn page(
        &self,
        after: Option<FencedTransitionRequestId>,
        limit: usize,
    ) -> Result<Vec<(FencedTransitionRequestId, FencedTransitionV2HistoryEpoch)>, StoreError> {
        let (journal, scope) = self.bound_journal().await?;
        Ok(journal
            .page_after(scope, after, limit)
            .await?
            .into_iter()
            .map(|entry| (entry.request_id, entry.history_epoch))
            .collect())
    }

    pub(super) async fn reclaim_retired(
        &self,
        limit: usize,
    ) -> Result<(FencedTransitionV2HistoryState, usize), StoreError> {
        let (journal, scope) = self.bound_journal().await?;
        self.require_v2_boundary().await?;
        let history = self.inner.fenced_transition_v2_history_state().await?;
        let removed = match history.retired_through() {
            Some(floor) => journal.remove_retired_through(scope, floor, limit).await?,
            None => 0,
        };
        Ok((history, removed))
    }

    pub(super) async fn retained(&self) -> Result<usize, StoreError> {
        let (journal, scope) = self.bound_journal().await?;
        journal.live_entries(scope).await
    }
}

/// Reject a #701 V1 preparation whose caller ID is retained by a configured
/// #982 recovery journal on the same wrapper.
///
/// The returned admission must be held through the V1 journal insert, so a
/// concurrent V2 preparation of the same ID cannot pass its own check of the
/// V1 journal in between.
pub(super) async fn reject_v1_id_retained_by_recovery_journal(
    recovery_journal: Option<&Arc<FencedTransitionV2RecoveryJournal>>,
    configured_scope: Option<FencedTransitionV2JournalScope>,
    backend_namespace: &str,
    mode: ProtectedFencedTransitionV2JournalMode,
    request_id: FencedTransitionRequestId,
) -> Result<Option<RecoveryJournalAdmission>, StoreError> {
    let Some(journal) = recovery_journal else {
        return Ok(None);
    };
    let scope =
        protected_fenced_transition_v2_recovery_scope(configured_scope, backend_namespace, mode)?;
    journal.ensure_scope(scope).await?;
    let admission = journal.admit(request_id)?;
    if journal.lookup(scope, request_id).await?.is_some() {
        return Err(StoreError::FencedTransitionRequestConflict);
    }
    Ok(Some(admission))
}

#[async_trait]
impl<B, P> ProtectedFencedTransitionV2Backend for EncryptingSessionBackend<B, P>
where
    B: SessionBackend + 'static + ?Sized,
    P: KeyProvider + 'static + ?Sized,
{
    async fn observe_protected_fenced_transition_v2(
        &self,
        key: &SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        self.v2_recovery_parts()
            .observe(key, |record| self.decrypt_optional_record(record))
            .await
    }

    async fn prepare_protected_fenced_transition_v2(
        &self,
        request: FencedTransitionRequest,
    ) -> Result<PreparedFencedTransitionV2, StoreError> {
        self.v2_recovery_parts()
            .prepare(request, |record| self.encrypt_record(record))
            .await
    }

    async fn recover_protected_fenced_transition_v2(
        &self,
        request_id: FencedTransitionRequestId,
    ) -> Result<PreparedFencedTransitionV2Lookup, StoreError> {
        self.v2_recovery_parts().recover(request_id).await
    }

    async fn preflight_protected_fenced_transition_v2(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<(), StoreError> {
        self.v2_recovery_parts().require_exact(prepared).await
    }

    async fn protected_fenced_transition_v2_effect(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>> {
        self.v2_recovery_parts().effect(prepared).await
    }

    async fn protected_fenced_transition_v2_status(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        self.v2_recovery_parts().status(prepared).await
    }

    async fn discard_protected_fenced_transition_v2(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<bool, StoreError> {
        self.v2_recovery_parts().discard(prepared).await
    }

    async fn protected_fenced_transition_v2_history_state(
        &self,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        self.v2_recovery_parts().history_state().await
    }

    async fn protected_fenced_transition_v2_page(
        &self,
        after: Option<FencedTransitionRequestId>,
        limit: usize,
    ) -> Result<Vec<(FencedTransitionRequestId, FencedTransitionV2HistoryEpoch)>, StoreError> {
        self.v2_recovery_parts().page(after, limit).await
    }

    async fn reclaim_retired_protected_fenced_transitions_v2(
        &self,
        limit: usize,
    ) -> Result<(FencedTransitionV2HistoryState, usize), StoreError> {
        self.v2_recovery_parts().reclaim_retired(limit).await
    }

    async fn retained_protected_fenced_transitions_v2(&self) -> Result<usize, StoreError> {
        self.v2_recovery_parts().retained().await
    }
}

#[async_trait]
impl<B, S> ProtectedFencedTransitionV2Backend for RemoteSealingSessionBackend<B, S>
where
    B: SessionBackend + 'static + ?Sized,
    S: RemoteSealProvider + 'static + ?Sized,
{
    async fn observe_protected_fenced_transition_v2(
        &self,
        key: &SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        self.v2_recovery_parts()
            .observe(key, |record| self.unseal_optional_record(record))
            .await
    }

    async fn prepare_protected_fenced_transition_v2(
        &self,
        request: FencedTransitionRequest,
    ) -> Result<PreparedFencedTransitionV2, StoreError> {
        self.v2_recovery_parts()
            .prepare(request, |record| self.seal_record(record))
            .await
    }

    async fn recover_protected_fenced_transition_v2(
        &self,
        request_id: FencedTransitionRequestId,
    ) -> Result<PreparedFencedTransitionV2Lookup, StoreError> {
        self.v2_recovery_parts().recover(request_id).await
    }

    async fn preflight_protected_fenced_transition_v2(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<(), StoreError> {
        self.v2_recovery_parts().require_exact(prepared).await
    }

    async fn protected_fenced_transition_v2_effect(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>> {
        self.v2_recovery_parts().effect(prepared).await
    }

    async fn protected_fenced_transition_v2_status(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        self.v2_recovery_parts().status(prepared).await
    }

    async fn discard_protected_fenced_transition_v2(
        &self,
        prepared: &PreparedFencedTransitionV2,
    ) -> Result<bool, StoreError> {
        self.v2_recovery_parts().discard(prepared).await
    }

    async fn protected_fenced_transition_v2_history_state(
        &self,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        self.v2_recovery_parts().history_state().await
    }

    async fn protected_fenced_transition_v2_page(
        &self,
        after: Option<FencedTransitionRequestId>,
        limit: usize,
    ) -> Result<Vec<(FencedTransitionRequestId, FencedTransitionV2HistoryEpoch)>, StoreError> {
        self.v2_recovery_parts().page(after, limit).await
    }

    async fn reclaim_retired_protected_fenced_transitions_v2(
        &self,
        limit: usize,
    ) -> Result<(FencedTransitionV2HistoryState, usize), StoreError> {
        self.v2_recovery_parts().reclaim_retired(limit).await
    }

    async fn retained_protected_fenced_transitions_v2(&self) -> Result<usize, StoreError> {
        self.v2_recovery_parts().retained().await
    }
}
