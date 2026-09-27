//! Store-side evidence for #982 protected V2 transitions recoverable by
//! caller-stable identity.
//!
//! The physical double below retains every V2 receipt and follows the V2
//! consensus classification order: retired floor, exact receipt, active
//! epoch, and active-epoch capacity. It lets these tests drive preparation,
//! exact dispatch, status, restart recovery, and reclamation across more
//! epochs than the retained V2 history holds.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use opc_key::{
    EncryptedPayload, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose,
    MemoryKeyProvider, MemoryRemoteSealProvider, RemoteSealProvider, Zeroizing,
    AES_256_GCM_SIV_KEY_LEN,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

use crate::fenced_transition::FencedTransitionV2Effect;
use crate::{
    checked_session_deadline, AtomicFencedTransitionCapability, BackendCapabilities, CompareAndSet,
    CompareAndSetResult, EncryptedSessionPayload, EncryptingSessionBackend, FenceToken,
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
    FencedTransitionObservation, FencedTransitionOutcome, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionV2Capability, FencedTransitionV2HistoryEpoch,
    FencedTransitionV2HistoryState, FencedTransitionV2JournalScope,
    FencedTransitionV2RecoveryJournal, FencedTransitionV2RecoveryJournalKey,
    FencedTransitionV2Request, FencedTransitionV2Status, Generation, LeaseGuard, OwnerId,
    PreparedFencedTransition, PreparedFencedTransitionJournal, PreparedFencedTransitionJournalKey,
    PreparedFencedTransitionV2Lookup, ProtectedFencedTransitionV2Backend,
    RemoteSealingSessionBackend, SessionBackend, SessionKey, SessionKeyType, SessionOp,
    SessionOpResult, SessionPayloadEncoding, StateClass, StateType, StoreError,
    StoredSessionRecord, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS, FENCED_TRANSITION_V2_RECOVERY_RECLAIM_BATCH_MAX,
};

const NAMESPACE: &str = "protected-v2-recovery";
const PAYLOAD: &[u8] = b"synthetic-opaque-v2-payload";

fn tenant() -> TenantId {
    TenantId::from_static("protected-v2-recovery")
}

fn key(label: u8) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![0x6b, label])
            .try_into()
            .expect("valid stable ID"),
    }
}

fn owner() -> OwnerId {
    OwnerId::new("protected-v2-recovery-owner").expect("valid owner")
}

fn request_id(ordinal: u64) -> FencedTransitionRequestId {
    let mut bytes = [0x7a_u8; 16];
    bytes[8..].copy_from_slice(&ordinal.to_be_bytes());
    FencedTransitionRequestId::from_bytes(bytes)
}

fn create_request(id: FencedTransitionRequestId, label: u8) -> FencedTransitionRequest {
    let key = key(label);
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner(),
        FenceToken::new(0),
        Duration::from_secs(60),
    )
    .expect("valid acquire");
    FencedTransitionRequest::new(
        id,
        lease,
        FencedTransitionMutation::create(StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: owner(),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("protected-v2-recovery-state"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(PAYLOAD),
        }),
    )
    .expect("valid create request")
}

fn renew_guard(label: u8) -> LeaseGuard {
    let acquired_at = Timestamp::now_utc();
    LeaseGuard::new(
        key(label),
        owner(),
        FenceToken::new(1),
        acquired_at,
        checked_session_deadline(acquired_at, Duration::from_secs(60)).expect("lease expiry"),
        1,
    )
}

fn delete_request(id: FencedTransitionRequestId, label: u8) -> FencedTransitionRequest {
    FencedTransitionRequest::new(
        id,
        FencedTransitionLease::renew(renew_guard(label), Duration::from_secs(60))
            .expect("valid renewal"),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .expect("valid delete request")
}

fn refresh_request(id: FencedTransitionRequestId, label: u8) -> FencedTransitionRequest {
    FencedTransitionRequest::new(
        id,
        FencedTransitionLease::renew(renew_guard(label), Duration::from_secs(60))
            .expect("valid renewal"),
        FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
            .expect("valid refresh"),
    )
    .expect("valid refresh request")
}

fn epoch(value: u64) -> FencedTransitionV2HistoryEpoch {
    FencedTransitionV2HistoryEpoch::new(value).expect("valid V2 epoch")
}

/// Active epoch `active` with the retired floor that keeps at most eight
/// retained epochs, as the V2 lifecycle does once rotation has begun.
fn history(active: u64, bound_entries: usize) -> FencedTransitionV2HistoryState {
    let retained = FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS as u64 + 1;
    let retired = active
        .checked_sub(retained)
        .filter(|floor| *floor > 0)
        .map(epoch);
    FencedTransitionV2HistoryState::new(
        Some(epoch(active)),
        retired,
        None,
        0,
        active,
        bound_entries,
        0,
    )
    .expect("valid V2 history state")
}

fn outcome_for(request: &FencedTransitionV2Request) -> FencedTransitionOutcome {
    let recorded_at = Timestamp::now_utc();
    let lease = match request.lease() {
        FencedTransitionLease::Acquire {
            key, owner, ttl, ..
        } => LeaseGuard::new(
            key.clone(),
            owner.clone(),
            request.lease().committed_fence().expect("committed fence"),
            recorded_at,
            checked_session_deadline(recorded_at, *ttl).expect("lease expiry"),
            7,
        ),
        // A renewal keeps the credential's fence, ID, and acquisition time.
        FencedTransitionLease::Renew { lease, ttl } => LeaseGuard::new(
            lease.key().clone(),
            lease.owner().clone(),
            lease.fence(),
            lease.acquired_at(),
            checked_session_deadline(recorded_at, *ttl).expect("lease expiry"),
            lease.credential_id(),
        ),
    };
    let mutation = match request.mutation() {
        FencedTransitionMutation::Create { .. } => FencedTransitionMutationResult::Created,
        FencedTransitionMutation::Update { .. } => FencedTransitionMutationResult::Updated,
        FencedTransitionMutation::Delete { .. } => FencedTransitionMutationResult::Deleted,
        FencedTransitionMutation::RefreshTtl { ttl, .. } => {
            FencedTransitionMutationResult::TtlRefreshed {
                expires_at: checked_session_deadline(recorded_at, *ttl).expect("refresh expiry"),
            }
        }
    };
    let generation = request.mutation().record().map_or_else(
        || {
            request
                .mutation()
                .expected_generation()
                .expect("existing generation")
        },
        |record| record.generation,
    );
    FencedTransitionOutcome::new(lease, generation, mutation, recorded_at).expect("valid outcome")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SpyEffect {
    Commit,
    NotTransmitted,
    CommitThenUnknown,
    UnknownWithoutCommit,
}

struct HistorySpyState {
    v2_capability: bool,
    history: FencedTransitionV2HistoryState,
    receipts: HashMap<[u8; 56], (FencedTransitionV2Request, FencedTransitionOutcome)>,
    executed: Vec<FencedTransitionV2Request>,
    next_effects: Vec<SpyEffect>,
    observed: Option<StoredSessionRecord>,
    statuses: usize,
    history_reads: usize,
    preflights: usize,
    observations: usize,
}

/// Multi-receipt V2 physical boundary with explicit history control.
struct HistorySpy {
    state: Mutex<HistorySpyState>,
}

impl HistorySpy {
    fn new(active: u64) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(HistorySpyState {
                v2_capability: true,
                history: history(active, 0),
                receipts: HashMap::new(),
                executed: Vec::new(),
                next_effects: Vec::new(),
                observed: None,
                statuses: 0,
                history_reads: 0,
                preflights: 0,
                observations: 0,
            }),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, HistorySpyState> {
        self.state.lock().expect("history spy lock")
    }

    fn set_history(&self, history: FencedTransitionV2HistoryState) {
        self.state().history = history;
    }

    fn push_effect(&self, effect: SpyEffect) {
        self.state().next_effects.push(effect);
    }

    fn executed(&self) -> Vec<FencedTransitionV2Request> {
        self.state().executed.clone()
    }

    fn classify(
        state: &HistorySpyState,
        request: &FencedTransitionV2Request,
    ) -> Result<Option<FencedTransitionOutcome>, StoreError> {
        request.validate()?;
        let epoch = request.request_id().epoch();
        if state
            .history
            .retired_through()
            .is_some_and(|floor| epoch <= floor)
        {
            return Err(StoreError::FencedTransitionHistoryEpochRetired);
        }
        if let Some((bound, outcome)) = state.receipts.get(&request.request_id().to_bytes()) {
            return if bound.matches(request) {
                Ok(Some(outcome.clone()))
            } else {
                Err(StoreError::FencedTransitionRequestConflict)
            };
        }
        if state.history.active_epoch() != Some(epoch) {
            return Err(StoreError::FencedTransitionHistoryEpochNotActive);
        }
        if state.history.bound_entries() >= FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
            return Err(StoreError::FencedTransitionHistoryFull);
        }
        Ok(None)
    }
}

#[async_trait]
impl SessionBackend for HistorySpy {
    fn fenced_transition_preserves_protected_payloads(&self) -> bool {
        true
    }

    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::minimal()
    }

    async fn preflight_record_expiry(
        &self,
        _preflights: &[crate::RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        self.state().preflights += 1;
        Ok(())
    }

    async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        Ok(None)
    }

    async fn observe_fenced_transition(
        &self,
        _key: &SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        let mut state = self.state();
        state.observations += 1;
        let fence = state
            .observed
            .as_ref()
            .map_or(FenceToken::new(0), |record| record.fence);
        FencedTransitionObservation::new(state.observed.clone(), fence)
    }

    async fn fenced_transition_capability(
        &self,
    ) -> Result<Option<AtomicFencedTransitionCapability>, StoreError> {
        Ok(None)
    }

    async fn fenced_transition_v2_capability(
        &self,
    ) -> Result<Option<FencedTransitionV2Capability>, StoreError> {
        Ok(self
            .state()
            .v2_capability
            .then_some(FencedTransitionV2Capability::V2))
    }

    async fn fenced_transition_v2_history_state(
        &self,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        let mut state = self.state();
        state.history_reads += 1;
        Ok(state.history)
    }

    async fn fenced_transition_v2_effect(
        &self,
        request: FencedTransitionV2Request,
    ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>> {
        let mut state = self.state();
        let effect = if state.next_effects.is_empty() {
            SpyEffect::Commit
        } else {
            state.next_effects.remove(0)
        };
        if effect == SpyEffect::NotTransmitted {
            return FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(
                "synthetic V2 pre-dispatch failure".into(),
            ));
        }
        state.executed.push(request.clone());
        if effect == SpyEffect::UnknownWithoutCommit {
            return FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: vec![request.request_id()],
            };
        }
        let result = match Self::classify(&state, &request) {
            Ok(Some(outcome)) => Ok(outcome),
            Ok(None) => {
                let outcome = outcome_for(&request);
                state.receipts.insert(
                    request.request_id().to_bytes(),
                    (request.clone(), outcome.clone()),
                );
                Ok(outcome)
            }
            Err(error) => Err(error),
        };
        if effect == SpyEffect::CommitThenUnknown {
            return FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: vec![request.request_id()],
            };
        }
        FencedTransitionV2Effect::Resolved(result)
    }

    async fn fenced_transition_v2_status(
        &self,
        request: &FencedTransitionV2Request,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        let mut state = self.state();
        state.statuses += 1;
        Ok(match Self::classify(&state, request) {
            Ok(Some(outcome)) => FencedTransitionV2Status::Recorded(Box::new(Ok(outcome))),
            Ok(None) => FencedTransitionV2Status::NotFound,
            Err(StoreError::FencedTransitionHistoryEpochRetired) => {
                FencedTransitionV2Status::Retired
            }
            Err(StoreError::FencedTransitionRequestConflict) => {
                FencedTransitionV2Status::RequestConflict
            }
            Err(StoreError::FencedTransitionHistoryEpochNotActive) => {
                FencedTransitionV2Status::EpochNotActive
            }
            Err(StoreError::FencedTransitionHistoryFull) => FencedTransitionV2Status::HistoryFull,
            Err(error) => return Err(error),
        })
    }

    async fn compare_and_set(&self, _op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        Err(StoreError::CapabilityNotSupported("history spy CAS".into()))
    }

    async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "history spy delete".into(),
        ))
    }

    async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "history spy refresh".into(),
        ))
    }

    async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "history spy batch".into(),
        ))
    }
}

struct CountingKeyProvider {
    inner: Arc<MemoryKeyProvider>,
    calls: AtomicUsize,
}

impl CountingKeyProvider {
    fn with_key(id: &str, fill: u8) -> Arc<Self> {
        let inner = Arc::new(MemoryKeyProvider::new());
        inner
            .insert_active_key(
                KeyId::new(id).expect("valid key ID"),
                KeyPurpose::Session,
                tenant(),
                Zeroizing::new([fill; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("insert active key");
        Arc::new(Self {
            inner,
            calls: AtomicUsize::new(0),
        })
    }

    fn empty() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(MemoryKeyProvider::new()),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeyProvider for CountingKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.rotate_key(purpose, tenant).await
    }
}

struct CountingRemoteProvider {
    inner: Arc<MemoryRemoteSealProvider>,
    calls: AtomicUsize,
}

impl CountingRemoteProvider {
    fn with_key(id: &str, fill: u8) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(MemoryRemoteSealProvider::new(
                KeyId::new(id).expect("valid key ID"),
                KeyPurpose::Session,
                tenant(),
                Zeroizing::new([fill; AES_256_GCM_SIV_KEY_LEN]),
            )),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RemoteSealProvider for CountingRemoteProvider {
    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.seal(aad, plaintext).await
    }

    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.unseal(key_id, aad, ciphertext_and_tag).await
    }
}

struct RecoveryFixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    legacy_path: PathBuf,
    key: [u8; 32],
}

impl RecoveryFixture {
    fn new(fill: u8) -> Self {
        let directory = tempfile::tempdir().expect("recovery test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private recovery test directory");
        }
        let path = directory.path().join("recovery-v2.sqlite3");
        let legacy_path = directory.path().join("prepared-v1.sqlite3");
        Self {
            _directory: directory,
            path,
            legacy_path,
            key: [fill; 32],
        }
    }

    fn open(&self) -> Arc<FencedTransitionV2RecoveryJournal> {
        let key = FencedTransitionV2RecoveryJournalKey::from_bytes(self.key);
        Arc::new(
            if self.path.exists() {
                FencedTransitionV2RecoveryJournal::open_existing(&self.path, key)
            } else {
                FencedTransitionV2RecoveryJournal::create_new(&self.path, key)
            }
            .expect("open recovery journal"),
        )
    }

    fn open_legacy(&self) -> Arc<PreparedFencedTransitionJournal> {
        let key = PreparedFencedTransitionJournalKey::from_bytes(self.key);
        Arc::new(
            if self.legacy_path.exists() {
                PreparedFencedTransitionJournal::open_existing(&self.legacy_path, key)
            } else {
                PreparedFencedTransitionJournal::create_new(&self.legacy_path, key)
            }
            .expect("open legacy V1 journal"),
        )
    }

    fn scope(&self) -> FencedTransitionV2JournalScope {
        FencedTransitionV2JournalScope::from_bytes([self.key[0] ^ 0x3c; 32])
    }

    fn local<B>(
        &self,
        inner: Arc<B>,
        provider: Arc<CountingKeyProvider>,
        journal: Arc<FencedTransitionV2RecoveryJournal>,
    ) -> EncryptingSessionBackend<B, CountingKeyProvider>
    where
        B: SessionBackend + 'static,
    {
        EncryptingSessionBackend::new(inner, provider, NAMESPACE)
            .with_fenced_transition_v2_recovery_journal(journal)
            .with_fenced_transition_v2_journal_scope(self.scope())
    }
}

fn found(lookup: PreparedFencedTransitionV2Lookup) -> crate::PreparedFencedTransitionV2 {
    match lookup {
        PreparedFencedTransitionV2Lookup::Found(prepared) => prepared,
        PreparedFencedTransitionV2Lookup::Absent => panic!("retained transition was absent"),
    }
}

#[tokio::test]
async fn protected_v2_recovery_prepares_in_the_active_epoch_and_dispatches_exact_rows() {
    let fixture = RecoveryFixture::new(0x81);
    let spy = HistorySpy::new(3);
    let provider = CountingKeyProvider::with_key("v2-recovery-active", 0x81);
    let wrapper = fixture.local(Arc::clone(&spy), Arc::clone(&provider), fixture.open());
    let id = request_id(1);
    let caller_request = create_request(id, 1);
    let prepared = wrapper
        .prepare_protected_fenced_transition_v2(caller_request.clone())
        .await
        .expect("prepare in the linearized active epoch");
    assert_eq!(prepared.request_id(), id);
    assert_eq!(
        prepared.history_epoch(),
        epoch(3),
        "the facade names the active epoch"
    );
    assert_eq!(provider.calls(), 1, "create is sealed exactly once");
    assert_eq!(
        spy.state().preflights,
        1,
        "expiry preflight precedes the seal"
    );
    assert!(spy.executed().is_empty(), "preparation never dispatches");
    assert_eq!(
        wrapper
            .retained_protected_fenced_transitions_v2()
            .await
            .expect("retained count"),
        1
    );
    assert!(
        found(
            wrapper
                .recover_protected_fenced_transition_v2(id)
                .await
                .expect("recover by caller ID")
        ) == prepared,
        "recovery returns the exact retained sealed request"
    );

    let outcome = match wrapper
        .protected_fenced_transition_v2_effect(&prepared)
        .await
    {
        FencedTransitionV2Effect::Resolved(Ok(outcome)) => outcome,
        other => panic!("expected one exact commit, got {other:?}"),
    };
    assert!(outcome.matches_request(&caller_request));
    let executed = spy.executed();
    assert_eq!(executed.len(), 1);
    let physical = &executed[0];
    assert_eq!(physical.request_id().epoch(), epoch(3));
    assert_eq!(
        physical
            .mutation()
            .record()
            .expect("create record")
            .payload
            .encoding(),
        SessionPayloadEncoding::EnvelopeV1,
        "only the sealed body crosses the physical boundary"
    );
    assert!(matches!(
        wrapper
            .protected_fenced_transition_v2_status(&prepared)
            .await
            .expect("exact status"),
        FencedTransitionV2Status::Recorded(result) if result.is_ok()
    ));
    assert!(matches!(
        wrapper
            .protected_fenced_transition_v2_effect(&prepared)
            .await,
        FencedTransitionV2Effect::Resolved(Ok(_))
    ));
    let executed = spy.executed();
    assert_eq!(executed.len(), 2);
    assert!(
        executed[0].matches(&executed[1]),
        "a retry replays identical bytes"
    );
    assert_eq!(
        spy.state().receipts.len(),
        1,
        "exact replay creates no second receipt"
    );

    assert_eq!(
        wrapper
            .prepare_protected_fenced_transition_v2(create_request(id, 2))
            .await,
        Err(StoreError::FencedTransitionRequestConflict),
        "a retained caller ID never starts a second lineage"
    );
    assert_eq!(provider.calls(), 1, "the conflict precedes provider work");

    for request in [
        delete_request(request_id(2), 1),
        refresh_request(request_id(3), 1),
    ] {
        wrapper
            .prepare_protected_fenced_transition_v2(request)
            .await
            .expect("record-free preparation");
    }
    assert_eq!(
        provider.calls(),
        1,
        "delete and refresh perform no provider work"
    );
}

#[tokio::test]
async fn protected_v2_recovery_restart_recovers_exact_sealed_body_without_a_provider() {
    let fixture = RecoveryFixture::new(0x82);
    let spy = HistorySpy::new(1);
    spy.push_effect(SpyEffect::CommitThenUnknown);
    let id = request_id(11);
    let first_provider = CountingKeyProvider::with_key("v2-recovery-before-restart", 0x82);
    let first = fixture.local(
        Arc::clone(&spy),
        Arc::clone(&first_provider),
        fixture.open(),
    );
    let prepared = first
        .prepare_protected_fenced_transition_v2(create_request(id, 11))
        .await
        .expect("prepare before the crash");
    assert!(matches!(
        first.protected_fenced_transition_v2_effect(&prepared).await,
        FencedTransitionV2Effect::OutcomeUnknown { .. }
    ));
    assert_eq!(first_provider.calls(), 1);
    drop(prepared);
    drop(first);

    // A fresh process retains only the caller-stable ID. It has neither the
    // plaintext body nor the original key provider.
    let restarted_provider = CountingKeyProvider::empty();
    let restarted = fixture.local(
        Arc::clone(&spy),
        Arc::clone(&restarted_provider),
        fixture.open(),
    );
    let recovered = found(
        restarted
            .recover_protected_fenced_transition_v2(id)
            .await
            .expect("recover by caller-stable ID"),
    );
    assert!(matches!(
        restarted
            .protected_fenced_transition_v2_status(&recovered)
            .await
            .expect("receipt-only status"),
        FencedTransitionV2Status::Recorded(result) if result.is_ok()
    ));
    assert_eq!(
        restarted_provider.calls(),
        0,
        "recovery never reseals or unseals"
    );
    assert_eq!(
        spy.executed().len(),
        1,
        "status never dispatches the mutation"
    );
    assert!(matches!(
        restarted
            .recover_protected_fenced_transition_v2(request_id(12))
            .await
            .expect("absent lookup"),
        PreparedFencedTransitionV2Lookup::Absent
    ));
}

#[tokio::test]
async fn protected_v2_recovery_fails_closed_before_provider_journal_or_dispatch_effects() {
    let spy = HistorySpy::new(1);
    let provider = CountingKeyProvider::with_key("v2-recovery-fail-closed", 0x83);
    let request = create_request(request_id(21), 21);

    let fixture = RecoveryFixture::new(0x83);
    let without_journal =
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
            .with_fenced_transition_v2_journal_scope(fixture.scope());
    let without_scope =
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
            .with_fenced_transition_v2_recovery_journal(fixture.open());
    let invalid_namespace =
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), "")
            .with_fenced_transition_v2_recovery_journal(RecoveryFixture::new(0x84).open())
            .with_fenced_transition_v2_journal_scope(fixture.scope());
    for result in [
        without_journal
            .prepare_protected_fenced_transition_v2(request.clone())
            .await,
        without_scope
            .prepare_protected_fenced_transition_v2(request.clone())
            .await,
        invalid_namespace
            .prepare_protected_fenced_transition_v2(request.clone())
            .await,
    ] {
        assert!(matches!(
            result,
            Err(StoreError::CapabilityNotSupported(capability))
                if capability == "protected_fenced_transition_v2_recovery"
        ));
    }
    assert_eq!(
        provider.calls(),
        0,
        "misconfiguration fails before provider work"
    );
    assert_eq!(spy.state().history_reads, 0);

    let full = RecoveryFixture::new(0x85);
    spy.set_history(history(1, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES));
    let wrapper = full.local(Arc::clone(&spy), Arc::clone(&provider), full.open());
    assert_eq!(
        wrapper
            .prepare_protected_fenced_transition_v2(request.clone())
            .await,
        Err(StoreError::FencedTransitionHistoryFull),
        "a full active epoch cannot bind before maintenance opens its successor"
    );
    assert_eq!(
        wrapper
            .retained_protected_fenced_transitions_v2()
            .await
            .expect("count"),
        0
    );
    assert_eq!(
        provider.calls(),
        0,
        "a full epoch is rejected before provider work"
    );
    spy.set_history(history(1, 0));
    spy.state().v2_capability = false;
    assert!(wrapper
        .prepare_protected_fenced_transition_v2(request.clone())
        .await
        .is_err());
    assert_eq!(provider.calls(), 0);
    spy.state().v2_capability = true;
    let mut record = create_request(request_id(22), 22)
        .mutation()
        .record()
        .expect("create record")
        .clone();
    record.payload = EncryptedSessionPayload::encrypt(provider.as_ref(), &record, NAMESPACE)
        .await
        .expect("synthetic caller envelope");
    let calls_before_envelope_input = provider.calls();
    let envelope_caller = FencedTransitionRequest::new(
        request_id(22),
        FencedTransitionLease::acquire(
            key(22),
            owner(),
            FenceToken::new(0),
            Duration::from_secs(60),
        )
        .expect("valid acquire"),
        FencedTransitionMutation::create(record),
    )
    .expect("structurally valid envelope request");
    assert!(
        matches!(
            wrapper
                .prepare_protected_fenced_transition_v2(envelope_caller)
                .await,
            Err(StoreError::CapabilityNotSupported(_))
        ),
        "only caller plaintext may enter the single sealing boundary"
    );
    assert_eq!(provider.calls(), calls_before_envelope_input);
    assert!(spy.executed().is_empty());

    let prepared = wrapper
        .prepare_protected_fenced_transition_v2(request)
        .await
        .expect("prepare a retained row");
    assert!(wrapper
        .discard_protected_fenced_transition_v2(&prepared)
        .await
        .expect("remove the retained row"));
    assert!(matches!(
        wrapper
            .protected_fenced_transition_v2_effect(&prepared)
            .await,
        FencedTransitionV2Effect::NotTransmitted(_)
    ));
    assert!(wrapper
        .protected_fenced_transition_v2_status(&prepared)
        .await
        .is_err());
    assert!(
        spy.executed().is_empty(),
        "a missing row is never dispatched"
    );
}

#[tokio::test]
async fn protected_v2_recovery_rejects_a_substituted_row_before_dispatch() {
    let spy = HistorySpy::new(1);
    let provider = CountingKeyProvider::with_key("v2-recovery-substitution", 0x86);
    let left = RecoveryFixture::new(0x86);
    let right = RecoveryFixture::new(0x87);
    let left_wrapper = left.local(Arc::clone(&spy), Arc::clone(&provider), left.open());
    let right_wrapper = right.local(Arc::clone(&spy), Arc::clone(&provider), right.open());
    let id = request_id(31);
    let left_prepared = left_wrapper
        .prepare_protected_fenced_transition_v2(create_request(id, 31))
        .await
        .expect("prepare left");
    let right_prepared = right_wrapper
        .prepare_protected_fenced_transition_v2(create_request(id, 32))
        .await
        .expect("prepare right under the same caller ID");
    assert!(matches!(
        left_wrapper
            .protected_fenced_transition_v2_effect(&right_prepared)
            .await,
        FencedTransitionV2Effect::NotTransmitted(StoreError::FencedTransitionRequestConflict)
    ));
    assert_eq!(
        left_wrapper
            .protected_fenced_transition_v2_status(&right_prepared)
            .await,
        Err(StoreError::FencedTransitionRequestConflict)
    );
    assert!(!left_wrapper
        .discard_protected_fenced_transition_v2(&right_prepared)
        .await
        .expect("compare-and-delete"));
    assert!(spy.executed().is_empty());
    assert!(matches!(
        left_wrapper
            .protected_fenced_transition_v2_effect(&left_prepared)
            .await,
        FencedTransitionV2Effect::Resolved(Ok(_))
    ));
}

#[tokio::test]
async fn protected_v2_recovery_and_legacy_v1_reject_each_others_retained_ids() {
    let fixture = RecoveryFixture::new(0x88);
    let spy = Arc::new(LegacyAndV2Spy::new());
    let provider = CountingKeyProvider::with_key("v2-recovery-legacy", 0x88);
    let wrapper = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
        .with_fenced_transition_journal(fixture.open_legacy())
        .with_fenced_transition_v2_recovery_journal(fixture.open())
        .with_fenced_transition_v2_journal_scope(fixture.scope());

    let legacy_id = request_id(41);
    wrapper
        .prepare_fenced_transition(create_request(legacy_id, 41))
        .await
        .expect("prepare one retained V1 transition before upgrade");
    let calls = provider.calls();
    assert_eq!(
        wrapper
            .prepare_protected_fenced_transition_v2(create_request(legacy_id, 42))
            .await,
        Err(StoreError::FencedTransitionRequestConflict),
        "a retained V1 row keeps its caller ID after upgrade"
    );
    assert_eq!(
        provider.calls(),
        calls,
        "the conflict precedes provider work"
    );

    let v2_id = request_id(43);
    wrapper
        .prepare_protected_fenced_transition_v2(create_request(v2_id, 43))
        .await
        .expect("prepare one V2 transition");
    let calls = provider.calls();
    assert_eq!(
        wrapper
            .prepare_fenced_transition(create_request(v2_id, 44))
            .await,
        Err(StoreError::FencedTransitionRequestConflict),
        "a retained V2 row is never rebound by the V1 composition"
    );
    assert_eq!(provider.calls(), calls);
    assert!(matches!(
        wrapper
            .recover_prepared_fenced_transition(legacy_id)
            .await
            .expect("legacy V1 recovery"),
        crate::PreparedFencedTransitionLookup::Found(_)
    ));
}

#[tokio::test]
async fn protected_v2_recovery_remote_seal_prepares_once_and_observes_unprotected_records() {
    let fixture = RecoveryFixture::new(0x89);
    let spy = HistorySpy::new(2);
    let provider = CountingRemoteProvider::with_key("v2-recovery-remote", 0x89);
    let wrapper =
        RemoteSealingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
            .with_fenced_transition_v2_recovery_journal(fixture.open())
            .with_fenced_transition_v2_journal_scope(fixture.scope());
    let observed = wrapper
        .observe_protected_fenced_transition_v2(&key(51))
        .await
        .expect("observe an absent record");
    assert!(observed.record().is_none());
    assert_eq!(provider.calls(), 0, "an absent record performs no unseal");

    let prepared = wrapper
        .prepare_protected_fenced_transition_v2(create_request(request_id(51), 51))
        .await
        .expect("remote-seal preparation");
    assert_eq!(
        provider.calls(),
        1,
        "create is remotely sealed exactly once"
    );
    assert!(matches!(
        wrapper
            .protected_fenced_transition_v2_effect(&prepared)
            .await,
        FencedTransitionV2Effect::Resolved(Ok(_))
    ));
    let sealed = spy.executed()[0]
        .mutation()
        .record()
        .expect("sealed create record")
        .clone();
    assert_eq!(
        sealed.payload.encoding(),
        SessionPayloadEncoding::EnvelopeV1
    );
    spy.state().observed = Some(sealed);
    let observed = wrapper
        .observe_protected_fenced_transition_v2(&key(51))
        .await
        .expect("observe the committed record");
    let record = observed.record().expect("present record");
    assert_eq!(record.payload.encoding(), SessionPayloadEncoding::Plaintext);
    assert_eq!(record.payload.as_bytes(), PAYLOAD);
    assert_eq!(observed.current_fence(), FenceToken::new(1));
    assert_eq!(
        provider.calls(),
        2,
        "observation unseals the present record once"
    );
}

/// Sustained operation beyond the V2 retained-epoch ceiling. Every epoch
/// prepares, dispatches, and resolves transitions while one transition per
/// epoch stays unresolved until its epoch closes. The recovery journal stays
/// bounded while the total number of prepared transitions grows without
/// limit, and no V2 identity ever executes twice.
#[tokio::test]
async fn protected_v2_recovery_sustains_operation_beyond_retained_epochs_with_bounded_rows() {
    const EPOCHS: u64 = FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS as u64 + 5;
    const RESOLVED_PER_EPOCH: u64 = 6;
    let fixture = RecoveryFixture::new(0x8a);
    let spy = HistorySpy::new(1);
    let provider = CountingKeyProvider::with_key("v2-recovery-sustained", 0x8a);
    let wrapper = fixture.local(Arc::clone(&spy), Arc::clone(&provider), fixture.open());
    let mut unresolved: Vec<crate::PreparedFencedTransitionV2> = Vec::new();
    let mut ordinal = 0_u64;
    let mut peak = 0_usize;
    for active in 1..=EPOCHS {
        spy.set_history(history(active, 0));
        // Rows left unresolved in a closed epoch are now provably unable to
        // bind: their status is EpochNotActive (or Retired below the floor).
        let mut still_open = Vec::new();
        for prepared in unresolved.drain(..) {
            match wrapper
                .protected_fenced_transition_v2_status(&prepared)
                .await
                .expect("status of a closed-epoch row")
            {
                FencedTransitionV2Status::EpochNotActive | FencedTransitionV2Status::Retired => {
                    assert!(prepared.history_epoch() < epoch(active));
                    assert!(wrapper
                        .discard_protected_fenced_transition_v2(&prepared)
                        .await
                        .expect("discard an excluded row"));
                }
                FencedTransitionV2Status::NotFound => still_open.push(prepared),
                other => panic!("unexpected closed-epoch status {other:?}"),
            }
        }
        unresolved = still_open;
        for _ in 0..RESOLVED_PER_EPOCH {
            ordinal += 1;
            let prepared = wrapper
                .prepare_protected_fenced_transition_v2(delete_request(request_id(ordinal), 1))
                .await
                .expect("prepare in the current active epoch");
            assert_eq!(prepared.history_epoch(), epoch(active));
            assert!(matches!(
                wrapper
                    .protected_fenced_transition_v2_effect(&prepared)
                    .await,
                FencedTransitionV2Effect::Resolved(Ok(_))
            ));
            peak = peak.max(
                wrapper
                    .retained_protected_fenced_transitions_v2()
                    .await
                    .expect("count"),
            );
            assert!(wrapper
                .discard_protected_fenced_transition_v2(&prepared)
                .await
                .expect("release a resolved row"));
        }
        ordinal += 1;
        let pending = wrapper
            .prepare_protected_fenced_transition_v2(delete_request(request_id(ordinal), 1))
            .await
            .expect("prepare one transition that is never dispatched");
        assert_eq!(
            wrapper
                .protected_fenced_transition_v2_status(&pending)
                .await
                .expect("pending status"),
            FencedTransitionV2Status::NotFound,
            "NotFound in the active epoch stays non-exclusionary"
        );
        unresolved.push(pending);
        peak = peak.max(
            wrapper
                .retained_protected_fenced_transitions_v2()
                .await
                .expect("count"),
        );
    }
    assert_eq!(ordinal, EPOCHS * (RESOLVED_PER_EPOCH + 1));
    assert!(
        peak <= 2,
        "retention is bounded by unresolved transitions, not lifetime (peak {peak})"
    );
    assert_eq!(unresolved.len(), 1);
    let executed = spy.executed();
    let mut identities = executed
        .iter()
        .map(|request| request.request_id().to_bytes())
        .collect::<Vec<_>>();
    identities.sort_unstable();
    identities.dedup();
    assert_eq!(
        identities.len(),
        executed.len(),
        "no V2 identity executed twice"
    );
    assert_eq!(executed.len() as u64, EPOCHS * RESOLVED_PER_EPOCH);
    assert!(
        executed
            .iter()
            .map(|request| request.request_id().epoch())
            .max()
            > Some(epoch(FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS as u64 + 1)),
        "operation continued beyond the eight-epoch retained V2 window"
    );

    // Retired-floor reclamation needs no status read.
    let retired = unresolved.pop().expect("final pending row");
    spy.set_history(history(retired.history_epoch().get() + 8, 0));
    let statuses = spy.state().statuses;
    let (observed, removed) = wrapper
        .reclaim_retired_protected_fenced_transitions_v2(
            FENCED_TRANSITION_V2_RECOVERY_RECLAIM_BATCH_MAX,
        )
        .await
        .expect("retired-floor discard");
    assert_eq!(
        observed.retired_through(),
        Some(retired.history_epoch()),
        "the floor is the one linearized by the physical boundary"
    );
    assert_eq!(removed, 1);
    assert_eq!(spy.state().statuses, statuses);
    assert_eq!(
        wrapper
            .retained_protected_fenced_transitions_v2()
            .await
            .expect("count"),
        0
    );
}

/// A key provider whose first active-key lookup waits for the test, so a
/// preparation can be held between its absence checks and its insert.
struct GatedKeyProvider {
    inner: MemoryKeyProvider,
    first: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    gate: tokio::sync::Semaphore,
}

impl GatedKeyProvider {
    fn with_key(id: &str, fill: u8) -> Arc<Self> {
        let inner = MemoryKeyProvider::new();
        inner
            .insert_active_key(
                KeyId::new(id).expect("valid key ID"),
                KeyPurpose::Session,
                tenant(),
                Zeroizing::new([fill; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("insert active key");
        Arc::new(Self {
            inner,
            first: std::sync::atomic::AtomicBool::new(true),
            entered: tokio::sync::Notify::new(),
            gate: tokio::sync::Semaphore::new(0),
        })
    }
}

#[async_trait]
impl KeyProvider for GatedKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        if self.first.swap(false, Ordering::AcqRel) {
            self.entered.notify_one();
            self.gate
                .acquire()
                .await
                .expect("test gate stays open")
                .forget();
        }
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.inner.rotate_key(purpose, tenant).await
    }
}

/// Concurrent V1 and V2 preparations of one caller ID on an upgraded wrapper
/// each check the other journal before either inserts. Exactly one may bind.
#[tokio::test]
async fn protected_v2_recovery_and_legacy_v1_exclude_one_concurrent_caller_id() {
    for v2_first in [true, false] {
        let fixture = RecoveryFixture::new(0x8a);
        let spy = Arc::new(LegacyAndV2Spy::new());
        let provider = GatedKeyProvider::with_key("v2-recovery-concurrent", 0x8a);
        let wrapper =
            EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
                .with_fenced_transition_journal(fixture.open_legacy())
                .with_fenced_transition_v2_recovery_journal(fixture.open())
                .with_fenced_transition_v2_journal_scope(fixture.scope());
        let id = request_id(45);
        let held = async {
            if v2_first {
                wrapper
                    .prepare_protected_fenced_transition_v2(create_request(id, 45))
                    .await
                    .map(|_| ())
            } else {
                wrapper
                    .prepare_fenced_transition(create_request(id, 45))
                    .await
                    .map(|_| ())
            }
        };
        let racing = async {
            // The held preparation is sealing: it passed every absence check
            // and has not inserted its row yet.
            provider.entered.notified().await;
            let result = if v2_first {
                wrapper
                    .prepare_fenced_transition(create_request(id, 46))
                    .await
                    .map(|_| ())
            } else {
                wrapper
                    .prepare_protected_fenced_transition_v2(create_request(id, 46))
                    .await
                    .map(|_| ())
            };
            provider.gate.add_permits(1);
            result
        };
        let (held, racing) = tokio::join!(held, racing);
        held.expect("the first preparation binds the caller ID");
        assert_eq!(
            racing,
            Err(StoreError::FencedTransitionRequestConflict),
            "a concurrent preparation in the other composition must not bind the same ID \
             (V2 first: {v2_first})"
        );
        let v1_retained = matches!(
            wrapper
                .recover_prepared_fenced_transition(id)
                .await
                .expect("V1 lookup"),
            crate::PreparedFencedTransitionLookup::Found(_)
        );
        let v2_retained = matches!(
            wrapper
                .recover_protected_fenced_transition_v2(id)
                .await
                .expect("V2 lookup"),
            PreparedFencedTransitionV2Lookup::Found(_)
        );
        assert_eq!(
            (v1_retained, v2_retained),
            (!v2_first, v2_first),
            "exactly one journal binds the caller ID"
        );
    }
}

/// A physical double that also implements the frozen V1 prepared-token hooks
/// so one wrapper can hold both a #701 journal and a #982 journal.
struct LegacyAndV2Spy {
    v2: Arc<HistorySpy>,
}

impl LegacyAndV2Spy {
    fn new() -> Self {
        Self {
            v2: HistorySpy::new(1),
        }
    }
}

#[async_trait]
impl SessionBackend for LegacyAndV2Spy {
    fn fenced_transition_preserves_protected_payloads(&self) -> bool {
        true
    }

    fn fenced_transition_accepts_prepared_physical_token(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> bool {
        prepared.request_for_unprotected_backend().is_ok()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::minimal()
    }

    async fn preflight_record_expiry(
        &self,
        preflights: &[crate::RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        self.v2.preflight_record_expiry(preflights).await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.v2.get(key).await
    }

    async fn fenced_transition_capability(
        &self,
    ) -> Result<Option<AtomicFencedTransitionCapability>, StoreError> {
        Ok(Some(AtomicFencedTransitionCapability::V1))
    }

    async fn prepare_fenced_transition(
        &self,
        request: FencedTransitionRequest,
    ) -> Result<PreparedFencedTransition, StoreError> {
        PreparedFencedTransition::from_unprotected_request(request)
    }

    async fn fenced_transition_v2_capability(
        &self,
    ) -> Result<Option<FencedTransitionV2Capability>, StoreError> {
        self.v2.fenced_transition_v2_capability().await
    }

    async fn fenced_transition_v2_history_state(
        &self,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        self.v2.fenced_transition_v2_history_state().await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.v2.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.v2.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        self.v2.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        self.v2.batch(ops).await
    }
}
