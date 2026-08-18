use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
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

use crate::{
    checked_session_deadline, AtomicFencedTransitionCapability, BackendCapabilities, CompareAndSet,
    CompareAndSetResult, EncryptedSessionPayload, EncryptingSessionBackend, FenceToken,
    FencedTransitionExecuteError, FencedTransitionLease, FencedTransitionMutation,
    FencedTransitionMutationResult, FencedTransitionObservation, FencedTransitionOutcome,
    FencedTransitionRequest, FencedTransitionRequestId, FencedTransitionStatus, Generation,
    LeaseError, LeaseGuard, OwnerId, PreparedFencedTransition, PreparedFencedTransitionJournal,
    PreparedFencedTransitionJournalKey, PreparedFencedTransitionLookup,
    RemoteSealingSessionBackend, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager,
    SessionOp, SessionOpResult, SessionPayloadEncoding, SessionStore, StateClass, StateType,
    StoreError, StoredSessionRecord, FENCED_TRANSITION_MAX_PREPARED_BYTES,
};

const NAMESPACE: &str = "protected-fenced-transition";
const SYNTHETIC_PAYLOAD: &[u8] = b"synthetic-opaque-payload";

struct JournalFixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    key: [u8; 32],
}

impl JournalFixture {
    fn new(fill: u8) -> Self {
        let directory = tempfile::tempdir().expect("journal directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private journal directory");
        }
        let path = directory.path().join("prepared.sqlite3");
        Self {
            _directory: directory,
            path,
            key: [fill; 32],
        }
    }

    fn open(&self) -> Arc<PreparedFencedTransitionJournal> {
        Arc::new(
            PreparedFencedTransitionJournal::open(
                &self.path,
                PreparedFencedTransitionJournalKey::from_bytes(self.key),
            )
            .expect("open prepared journal"),
        )
    }

    fn replace_token_with_oversized_blob(&self) {
        let connection = rusqlite::Connection::open(&self.path)
            .expect("open journal fixture for bounded corruption");
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("enable bounded corruption fixture");
        let blob_len = FENCED_TRANSITION_MAX_PREPARED_BYTES
            .checked_add(4096)
            .and_then(|length| i64::try_from(length).ok())
            .expect("bounded oversized fixture length");
        assert_eq!(
            connection
                .execute(
                    "UPDATE prepared_fenced_transition_journal \
                     SET prepared_token = zeroblob(?1)",
                    [blob_len],
                )
                .expect("replace token with oversized fixture"),
            1
        );
    }
}

fn tenant() -> TenantId {
    TenantId::from_static("protected-fenced-transition")
}

fn key() -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"protected-fenced-transition-key")
            .try_into()
            .expect("valid stable ID"),
    }
}

fn owner() -> OwnerId {
    OwnerId::new("protected-fenced-transition-owner").expect("valid owner")
}

fn record(
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    generation: u64,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner,
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("protected-fenced-transition-state"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(SYNTHETIC_PAYLOAD),
    }
}

fn create_request(id: u8) -> FencedTransitionRequest {
    create_request_with_payload(id, SYNTHETIC_PAYLOAD)
}

fn create_request_with_payload(id: u8, payload: &[u8]) -> FencedTransitionRequest {
    let key = key();
    let owner = owner();
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        Duration::from_secs(60),
    )
    .expect("valid acquire");
    let mut record = record(key, owner, FenceToken::new(1), 1);
    record.payload = EncryptedSessionPayload::new(payload);
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([id; 16]),
        lease,
        FencedTransitionMutation::create(record),
    )
    .expect("valid create request")
}

fn update_request(id: u8) -> FencedTransitionRequest {
    let key = key();
    let owner = owner();
    let acquired_at = Timestamp::now_utc();
    let lease = LeaseGuard::new(
        key.clone(),
        owner.clone(),
        FenceToken::new(1),
        acquired_at,
        checked_session_deadline(acquired_at, Duration::from_secs(60)).expect("lease expiry"),
        1,
    );
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([id; 16]),
        FencedTransitionLease::renew(lease, Duration::from_secs(60)).expect("valid renewal"),
        FencedTransitionMutation::update(
            Generation::new(1),
            record(key, owner, FenceToken::new(1), 2),
        ),
    )
    .expect("valid update request")
}

fn delete_request(id: u8) -> FencedTransitionRequest {
    let key = key();
    let acquired_at = Timestamp::now_utc();
    let lease = LeaseGuard::new(
        key,
        owner(),
        FenceToken::new(1),
        acquired_at,
        checked_session_deadline(acquired_at, Duration::from_secs(60)).expect("lease expiry"),
        1,
    );
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([id; 16]),
        FencedTransitionLease::renew(lease, Duration::from_secs(60)).expect("valid renewal"),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .expect("valid delete request")
}

fn refresh_request(id: u8) -> FencedTransitionRequest {
    let key = key();
    let acquired_at = Timestamp::now_utc();
    let lease = LeaseGuard::new(
        key,
        owner(),
        FenceToken::new(1),
        acquired_at,
        checked_session_deadline(acquired_at, Duration::from_secs(60)).expect("lease expiry"),
        1,
    );
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([id; 16]),
        FencedTransitionLease::renew(lease, Duration::from_secs(60)).expect("valid renewal"),
        FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
            .expect("valid refresh"),
    )
    .expect("valid refresh request")
}

#[derive(Default)]
struct SpyState {
    capability: Option<AtomicFencedTransitionCapability>,
    reject_expiry_preflight: bool,
    observed: Option<StoredSessionRecord>,
    prepared: Vec<FencedTransitionRequest>,
    executed: Vec<FencedTransitionRequest>,
    statuses: Vec<FencedTransitionRequest>,
    preflight_calls: usize,
    get_calls: usize,
    dispatches: usize,
    delay_ambiguous_commit: bool,
    emit_nonphysical_prepared_token: bool,
    pending: Option<FencedTransitionRequest>,
    receipt: Option<(FencedTransitionRequest, FencedTransitionOutcome)>,
}

/// A deliberately adversarial atomic boundary: first dispatch is definitely
/// absent, second commits but reports ambiguity, and later exact retries
/// recover the retained receipt.
#[derive(Default)]
struct AtomicSpy {
    state: Mutex<SpyState>,
    reject_physical_tokens: AtomicBool,
}

impl AtomicSpy {
    fn new() -> Self {
        let spy = Self::default();
        spy.state.lock().expect("spy lock").capability = Some(AtomicFencedTransitionCapability::V1);
        spy
    }

    fn prepared(&self) -> Vec<FencedTransitionRequest> {
        self.state.lock().expect("spy lock").prepared.clone()
    }

    fn executed(&self) -> Vec<FencedTransitionRequest> {
        self.state.lock().expect("spy lock").executed.clone()
    }

    fn statuses(&self) -> Vec<FencedTransitionRequest> {
        self.state.lock().expect("spy lock").statuses.clone()
    }

    fn dispatches(&self) -> usize {
        self.state.lock().expect("spy lock").dispatches
    }

    fn preflight_calls(&self) -> usize {
        self.state.lock().expect("spy lock").preflight_calls
    }

    fn get_calls(&self) -> usize {
        self.state.lock().expect("spy lock").get_calls
    }

    fn set_observed(&self, record: Option<StoredSessionRecord>) {
        self.state.lock().expect("spy lock").observed = record;
    }

    fn reject_expiry_preflight(&self) {
        self.state.lock().expect("spy lock").reject_expiry_preflight = true;
    }

    fn delay_ambiguous_commit(&self) {
        self.state.lock().expect("spy lock").delay_ambiguous_commit = true;
    }

    fn commit_delayed(&self) {
        let mut state = self.state.lock().expect("spy lock");
        let request = state.pending.take().expect("pending transition");
        let outcome = outcome_for(&request);
        state.receipt = Some((request, outcome));
    }

    fn disable_capability(&self) {
        self.state.lock().expect("spy lock").capability = None;
    }

    fn emit_nonphysical_prepared_token(&self) {
        self.state
            .lock()
            .expect("spy lock")
            .emit_nonphysical_prepared_token = true;
    }

    fn reject_physical_tokens(&self) {
        self.reject_physical_tokens.store(true, Ordering::SeqCst);
    }
}

fn outcome_for(request: &FencedTransitionRequest) -> FencedTransitionOutcome {
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
        FencedTransitionLease::Renew { lease, ttl } => LeaseGuard::new(
            lease.key().clone(),
            lease.owner().clone(),
            lease.fence(),
            recorded_at,
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

#[async_trait]
impl SessionBackend for AtomicSpy {
    fn fenced_transition_preserves_protected_payloads(&self) -> bool {
        true
    }

    fn fenced_transition_accepts_prepared_physical_token(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> bool {
        !self.reject_physical_tokens.load(Ordering::SeqCst)
            && prepared.request_for_unprotected_backend().is_ok()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::minimal()
    }

    async fn preflight_record_expiry(
        &self,
        _preflights: &[crate::RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().expect("spy lock");
        state.preflight_calls += 1;
        if state.reject_expiry_preflight {
            return Err(StoreError::InvalidRecordExpiry);
        }
        Ok(())
    }

    async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.state.lock().expect("spy lock").get_calls += 1;
        Ok(None)
    }

    async fn observe_fenced_transition(
        &self,
        _key: &SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        let state = self.state.lock().expect("spy lock");
        let fence = state
            .observed
            .as_ref()
            .map_or(FenceToken::new(0), |record| record.fence);
        FencedTransitionObservation::new(state.observed.clone(), fence)
    }

    async fn fenced_transition_capability(
        &self,
    ) -> Result<Option<AtomicFencedTransitionCapability>, StoreError> {
        Ok(self.state.lock().expect("spy lock").capability)
    }

    async fn prepare_fenced_transition(
        &self,
        request: FencedTransitionRequest,
    ) -> Result<PreparedFencedTransition, StoreError> {
        let emit_nonphysical_prepared_token = {
            let mut state = self.state.lock().expect("spy lock");
            state.prepared.push(request.clone());
            state.emit_nonphysical_prepared_token
        };
        let prepared = PreparedFencedTransition::from_unprotected_request(request)?;
        if emit_nonphysical_prepared_token {
            prepared.with_authenticated_consumer_binding([0; 32])
        } else {
            Ok(prepared)
        }
    }

    async fn fenced_transition(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionOutcome, FencedTransitionExecuteError> {
        let request = prepared
            .request_for_unprotected_backend()
            .map_err(FencedTransitionExecuteError::Rejected)?;
        let request_id = request.request_id();
        let mut state = self.state.lock().expect("spy lock");
        state.executed.push(request.clone());
        state.dispatches += 1;
        if let Some((bound, outcome)) = &state.receipt {
            return if bound == &request {
                Ok(outcome.clone())
            } else if bound.request_id() == request.request_id() {
                Err(FencedTransitionExecuteError::Rejected(
                    StoreError::FencedTransitionRequestConflict,
                ))
            } else {
                Err(FencedTransitionExecuteError::OutcomeUnknown { request_id })
            };
        }
        if state.dispatches == 1 {
            return Err(FencedTransitionExecuteError::NotTransmitted);
        }
        if state.delay_ambiguous_commit {
            state.pending = Some(request);
            return Err(FencedTransitionExecuteError::OutcomeUnknown { request_id });
        }
        let outcome = outcome_for(&request);
        state.receipt = Some((request, outcome));
        Err(FencedTransitionExecuteError::OutcomeUnknown { request_id })
    }

    async fn fenced_transition_status(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionStatus, StoreError> {
        let request = prepared.request_for_unprotected_backend()?;
        let mut state = self.state.lock().expect("spy lock");
        state.statuses.push(request.clone());
        Ok(match &state.receipt {
            Some((bound, outcome)) if bound == &request => {
                FencedTransitionStatus::Recorded(Box::new(Ok(outcome.clone())))
            }
            Some((bound, _)) if bound.request_id() == request.request_id() => {
                FencedTransitionStatus::RequestConflict
            }
            _ => FencedTransitionStatus::NotFound,
        })
    }

    async fn compare_and_set(&self, _op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        Err(StoreError::CapabilityNotSupported("atomic spy CAS".into()))
    }

    async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
        Ok(())
    }

    async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
        Ok(())
    }

    async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "atomic spy batch".into(),
        ))
    }
}

#[async_trait]
impl SessionLeaseManager for AtomicSpy {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        let now = Timestamp::now_utc();
        Ok(LeaseGuard::new(
            key.clone(),
            owner,
            FenceToken::new(1),
            now,
            checked_session_deadline(now, ttl).map_err(LeaseError::from)?,
            1,
        ))
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        let now = Timestamp::now_utc();
        Ok(LeaseGuard::new(
            lease.key().clone(),
            lease.owner().clone(),
            lease.fence(),
            now,
            checked_session_deadline(now, ttl).map_err(LeaseError::from)?,
            lease.credential_id(),
        ))
    }

    async fn release(&self, _lease: LeaseGuard) -> Result<(), LeaseError> {
        Ok(())
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

#[tokio::test]
async fn protected_fenced_transition_rejects_nonphysical_inner_token_before_journaling() {
    let local_spy = Arc::new(AtomicSpy::new());
    local_spy.emit_nonphysical_prepared_token();
    let local_journal = JournalFixture::new(0x8d);
    let local_inner: Arc<dyn SessionBackend> =
        Arc::new(SessionStore::from_arc(Arc::clone(&local_spy)));
    let local = EncryptingSessionBackend::new(
        local_inner,
        CountingKeyProvider::with_key("local-nonphysical", 0x14),
        NAMESPACE,
    )
    .with_fenced_transition_journal(local_journal.open());
    let local_request = create_request(41);
    assert!(matches!(
        local.prepare_fenced_transition(local_request.clone()).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        local_journal
            .open()
            .lookup(local_request.request_id())
            .await
            .expect("journal lookup"),
        PreparedFencedTransitionLookup::Absent
    ));

    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.emit_nonphysical_prepared_token();
    let remote_journal = JournalFixture::new(0x8e);
    let remote_inner: Arc<dyn SessionBackend> =
        Arc::new(SessionStore::from_arc(Arc::clone(&remote_spy)));
    let remote = RemoteSealingSessionBackend::new(
        remote_inner,
        CountingRemoteProvider::with_key("remote-nonphysical", 0x15),
        NAMESPACE,
    )
    .with_fenced_transition_journal(remote_journal.open());
    let remote_request = create_request(42);
    assert!(matches!(
        remote
            .prepare_fenced_transition(remote_request.clone())
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        remote_journal
            .open()
            .lookup(remote_request.request_id())
            .await
            .expect("journal lookup"),
        PreparedFencedTransitionLookup::Absent
    ));
}

#[tokio::test]
async fn protected_fenced_transition_rejects_same_kind_physical_substitution_before_effects() {
    let local_a = Arc::new(AtomicSpy::new());
    let local_journal = JournalFixture::new(0x8f);
    let local_a_inner: Arc<dyn SessionBackend> =
        Arc::new(SessionStore::from_arc(Arc::clone(&local_a)));
    let local_a_backend: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(Arc::new(
        EncryptingSessionBackend::new(
            local_a_inner,
            CountingKeyProvider::with_key("local-physical-a", 0x16),
            NAMESPACE,
        )
        .with_fenced_transition_journal(local_journal.open()),
    )));
    let local_token = local_a_backend
        .prepare_fenced_transition(create_request(43))
        .await
        .expect("prepare local token");
    let local_b = Arc::new(AtomicSpy::new());
    local_b.reject_physical_tokens();
    let local_b_provider = CountingKeyProvider::with_key("local-physical-b", 0x17);
    let local_b_inner: Arc<dyn SessionBackend> =
        Arc::new(SessionStore::from_arc(Arc::clone(&local_b)));
    let local_b_backend: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(Arc::new(
        EncryptingSessionBackend::new(local_b_inner, Arc::clone(&local_b_provider), NAMESPACE)
            .with_fenced_transition_journal(local_journal.open()),
    )));
    assert!(matches!(
        local_b_backend
            .recover_prepared_fenced_transition(local_token.request_id())
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        local_b_backend.fenced_transition_status(&local_token).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        local_b_backend.fenced_transition(&local_token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert_eq!(local_b.dispatches(), 0);
    assert!(local_b.statuses().is_empty());
    assert_eq!(local_b_provider.calls(), 0);

    let remote_a = Arc::new(AtomicSpy::new());
    let remote_journal = JournalFixture::new(0x90);
    let remote_a_inner: Arc<dyn SessionBackend> =
        Arc::new(SessionStore::from_arc(Arc::clone(&remote_a)));
    let remote_a_backend: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(Arc::new(
        RemoteSealingSessionBackend::new(
            remote_a_inner,
            CountingRemoteProvider::with_key("remote-physical-a", 0x18),
            NAMESPACE,
        )
        .with_fenced_transition_journal(remote_journal.open()),
    )));
    let remote_token = remote_a_backend
        .prepare_fenced_transition(create_request(44))
        .await
        .expect("prepare remote token");
    let remote_b = Arc::new(AtomicSpy::new());
    remote_b.reject_physical_tokens();
    let remote_b_provider = CountingRemoteProvider::with_key("remote-physical-b", 0x19);
    let remote_b_inner: Arc<dyn SessionBackend> =
        Arc::new(SessionStore::from_arc(Arc::clone(&remote_b)));
    let remote_b_backend: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(Arc::new(
        RemoteSealingSessionBackend::new(remote_b_inner, Arc::clone(&remote_b_provider), NAMESPACE)
            .with_fenced_transition_journal(remote_journal.open()),
    )));
    assert!(matches!(
        remote_b_backend
            .recover_prepared_fenced_transition(remote_token.request_id())
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        remote_b_backend
            .fenced_transition_status(&remote_token)
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        remote_b_backend.fenced_transition(&remote_token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert_eq!(remote_b.dispatches(), 0);
    assert!(remote_b.statuses().is_empty());
    assert_eq!(remote_b_provider.calls(), 0);
}

#[tokio::test]
async fn protected_fenced_transition_rejects_oversized_journal_row_without_effects() {
    let local_spy = Arc::new(AtomicSpy::new());
    let local_provider = CountingKeyProvider::with_key("local-corrupt-journal", 0x1a);
    let local_journal = JournalFixture::new(0x9a);
    let local: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(Arc::new(
        EncryptingSessionBackend::new(
            Arc::clone(&local_spy),
            Arc::clone(&local_provider),
            NAMESPACE,
        )
        .with_fenced_transition_journal(local_journal.open()),
    )));
    let local_token = local
        .prepare_fenced_transition(create_request(45))
        .await
        .expect("prepare local corruption fixture");
    let local_provider_calls = local_provider.calls();
    local_journal.replace_token_with_oversized_blob();
    assert!(matches!(
        local.fenced_transition(&local_token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        local
            .recover_prepared_fenced_transition(local_token.request_id())
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert!(matches!(
        local.fenced_transition_status(&local_token).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(local_provider.calls(), local_provider_calls);
    assert_eq!(local_spy.dispatches(), 0);
    assert!(local_spy.statuses().is_empty());

    let remote_spy = Arc::new(AtomicSpy::new());
    let remote_provider = CountingRemoteProvider::with_key("remote-corrupt-journal", 0x1b);
    let remote_journal = JournalFixture::new(0x9b);
    let remote: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(Arc::new(
        RemoteSealingSessionBackend::new(
            Arc::clone(&remote_spy),
            Arc::clone(&remote_provider),
            NAMESPACE,
        )
        .with_fenced_transition_journal(remote_journal.open()),
    )));
    let remote_token = remote
        .prepare_fenced_transition(create_request(46))
        .await
        .expect("prepare remote corruption fixture");
    let remote_provider_calls = remote_provider.calls();
    remote_journal.replace_token_with_oversized_blob();
    assert!(matches!(
        remote.fenced_transition(&remote_token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        remote
            .recover_prepared_fenced_transition(remote_token.request_id())
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert!(matches!(
        remote.fenced_transition_status(&remote_token).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(remote_provider.calls(), remote_provider_calls);
    assert_eq!(remote_spy.dispatches(), 0);
    assert!(remote_spy.statuses().is_empty());
}

#[tokio::test]
async fn protected_fenced_transition_local_prepares_once_and_recovers_exact_physical_request() {
    let spy = Arc::new(AtomicSpy::new());
    spy.delay_ambiguous_commit();
    let provider = CountingKeyProvider::with_key("local-before-rotation", 0x11);
    let journal = JournalFixture::new(0x91);
    let wrapper = Arc::new(
        EncryptingSessionBackend::new(
            Arc::clone(&spy) as Arc<dyn SessionBackend>,
            Arc::clone(&provider),
            NAMESPACE,
        )
        .with_fenced_transition_journal(journal.open()),
    );
    let backend: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(wrapper));
    assert_eq!(
        backend
            .fenced_transition_capability()
            .await
            .expect("capability"),
        Some(AtomicFencedTransitionCapability::V2),
        "dynamic local composition must expose durable protected recovery"
    );

    let prepared = backend
        .prepare_fenced_transition(create_request(1))
        .await
        .expect("prepare local create");
    let _update = backend
        .prepare_fenced_transition(update_request(10))
        .await
        .expect("prepare local update");
    assert_eq!(
        provider.calls(),
        2,
        "local create and update each seal exactly once"
    );
    let physical = spy.prepared();
    assert_eq!(physical.len(), 2);
    for request in &physical {
        let payload = &request.mutation().record().expect("record").payload;
        assert_eq!(payload.encoding(), SessionPayloadEncoding::EnvelopeV1);
        assert!(
            payload.as_bytes() != SYNTHETIC_PAYLOAD,
            "the physical local request must not expose the logical payload"
        );
    }
    let serialized_capacity = prepared
        .as_bytes()
        .len()
        .checked_mul(4)
        .and_then(|size| size.checked_add(2))
        .expect("bounded JSON capacity");
    let mut serialized = Zeroizing::new(Vec::with_capacity(serialized_capacity));
    serde_json::to_writer(&mut *serialized, &prepared).expect("serialize opaque token");
    let restored: PreparedFencedTransition =
        serde_json::from_slice(&serialized).expect("deserialize opaque token");
    assert_eq!(restored, prepared);
    assert!(format!("{prepared:?}").contains("redacted"));
    assert!(!format!("{prepared:?}")
        .contains(std::str::from_utf8(SYNTHETIC_PAYLOAD).expect("synthetic payload is UTF-8")));

    assert!(matches!(
        backend.fenced_transition(&restored).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        backend.fenced_transition(&restored).await,
        Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        backend.fenced_transition_status(&restored).await,
        Ok(FencedTransitionStatus::NotFound)
    ));

    let request_id = prepared.request_id();
    let rotated = CountingKeyProvider::with_key("local-after-rotation", 0x22);
    drop(backend);
    drop(restored);
    drop(prepared);
    drop(serialized);
    let reconstructed =
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&rotated), NAMESPACE)
            .with_fenced_transition_journal(journal.open());
    let recovered = match reconstructed
        .recover_prepared_fenced_transition(request_id)
        .await
        .expect("recover by stable ID after restart")
    {
        PreparedFencedTransitionLookup::Found(prepared) => prepared,
        PreparedFencedTransitionLookup::Absent => panic!("durable prepared request was lost"),
    };
    spy.commit_delayed();
    let replay = reconstructed
        .fenced_transition(&recovered)
        .await
        .expect("exact replay after rotation");
    assert!(replay.matches_request(&physical[0]));
    assert!(matches!(
        reconstructed.fenced_transition_status(&recovered).await,
        Ok(FencedTransitionStatus::Recorded(_))
    ));
    assert_eq!(
        rotated.calls(),
        0,
        "execute/retry/status never use rotated keys"
    );
    assert_eq!(
        spy.executed(),
        vec![
            physical[0].clone(),
            physical[0].clone(),
            physical[0].clone()
        ]
    );
    assert_eq!(
        spy.statuses(),
        vec![physical[0].clone(), physical[0].clone()]
    );
    assert_eq!(
        spy.get_calls(),
        0,
        "recovery must not reconstruct by readback"
    );

    assert!(matches!(
        reconstructed
            .prepare_fenced_transition(create_request_with_payload(1, b"fresh-local-body"))
            .await,
        Err(StoreError::FencedTransitionRequestConflict)
    ));
    assert_eq!(
        rotated.calls(),
        0,
        "replacement rejection precedes the rotated provider"
    );
    assert_eq!(spy.prepared().len(), 2);
    assert_eq!(spy.get_calls(), 0, "conflict recovery must not read back");
}

#[tokio::test]
async fn protected_fenced_transition_remote_prepares_create_and_update_once_with_dynamic_composition(
) {
    let spy = Arc::new(AtomicSpy::new());
    spy.delay_ambiguous_commit();
    let provider = CountingRemoteProvider::with_key("remote-before-rotation", 0x31);
    let journal = JournalFixture::new(0x92);
    let wrapper = Arc::new(
        RemoteSealingSessionBackend::new(
            Arc::clone(&spy) as Arc<dyn SessionBackend>,
            Arc::clone(&provider),
            NAMESPACE,
        )
        .with_fenced_transition_journal(journal.open()),
    );
    let backend: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(wrapper));
    assert_eq!(
        backend
            .fenced_transition_capability()
            .await
            .expect("capability"),
        Some(AtomicFencedTransitionCapability::V2),
        "dynamic remote composition must expose durable protected recovery"
    );

    let create = backend
        .prepare_fenced_transition(create_request(2))
        .await
        .expect("prepare remote create");
    let _update = backend
        .prepare_fenced_transition(update_request(3))
        .await
        .expect("prepare remote update");
    assert_eq!(
        provider.calls(),
        2,
        "create and update each seal exactly once"
    );
    let physical = spy.prepared();
    assert_eq!(physical.len(), 2);
    for request in &physical {
        let payload = &request.mutation().record().expect("record").payload;
        assert_eq!(payload.encoding(), SessionPayloadEncoding::EnvelopeV1);
        assert!(
            payload.as_bytes() != SYNTHETIC_PAYLOAD,
            "the physical remote request must not expose the logical payload"
        );
    }
    let restored =
        PreparedFencedTransition::try_from_bytes(create.as_bytes()).expect("token round trip");
    assert_eq!(restored, create);
    assert!(matches!(
        backend.fenced_transition(&restored).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        backend.fenced_transition(&restored).await,
        Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        backend.fenced_transition_status(&restored).await,
        Ok(FencedTransitionStatus::NotFound)
    ));

    let request_id = create.request_id();
    let rotated = CountingRemoteProvider::with_key("remote-after-rotation", 0x32);
    drop(backend);
    drop(restored);
    drop(create);
    let reconstructed =
        RemoteSealingSessionBackend::new(Arc::clone(&spy), Arc::clone(&rotated), NAMESPACE)
            .with_fenced_transition_journal(journal.open());
    let recovered = match reconstructed
        .recover_prepared_fenced_transition(request_id)
        .await
        .expect("recover remote prepared request")
    {
        PreparedFencedTransitionLookup::Found(prepared) => prepared,
        PreparedFencedTransitionLookup::Absent => panic!("remote prepared request was lost"),
    };
    spy.commit_delayed();
    assert!(reconstructed
        .fenced_transition(&recovered)
        .await
        .expect("exact remote replay")
        .matches_request(&physical[0]));
    assert!(matches!(
        reconstructed.fenced_transition_status(&recovered).await,
        Ok(FencedTransitionStatus::Recorded(_))
    ));
    assert_eq!(
        rotated.calls(),
        0,
        "recovery does not invoke a rotated remote provider"
    );
    assert_eq!(
        spy.executed()[..3],
        [
            physical[0].clone(),
            physical[0].clone(),
            physical[0].clone()
        ]
    );
    assert_eq!(
        reconstructed
            .prepare_fenced_transition(create_request_with_payload(2, b"fresh-remote-body"))
            .await,
        Err(StoreError::FencedTransitionRequestConflict)
    );
    assert_eq!(rotated.calls(), 0, "conflict precedes provider work");
    assert_eq!(spy.prepared().len(), 2);
    assert_eq!(spy.get_calls(), 0, "remote recovery must not read back");
}

#[tokio::test]
async fn protected_fenced_transition_observation_unprotects_once_preserves_fence_and_none_is_inert()
{
    let spy = Arc::new(AtomicSpy::new());
    let provider = CountingKeyProvider::with_key("observe-local", 0x41);
    let local_journal = JournalFixture::new(0x93);
    let backend = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
        .with_fenced_transition_journal(local_journal.open());
    let token = backend
        .prepare_fenced_transition(create_request(4))
        .await
        .expect("prepare protected observation fixture");
    let protected = spy.prepared().pop().expect("captured protected request");
    spy.set_observed(protected.mutation().record().cloned());
    let unavailable_provider = CountingKeyProvider::with_key("observe-local-unavailable", 0x43);
    let unavailable = EncryptingSessionBackend::new(
        Arc::clone(&spy),
        Arc::clone(&unavailable_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(local_journal.open());
    let error = unavailable
        .observe_fenced_transition(&key())
        .await
        .expect_err("missing key must fail observation");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert!(
        !format!("{error} {error:?}")
            .contains(std::str::from_utf8(SYNTHETIC_PAYLOAD).expect("synthetic payload is UTF-8")),
        "observation failure must not become a plaintext oracle"
    );
    let calls_before_observation = provider.calls();
    let observation = backend
        .observe_fenced_transition(&key())
        .await
        .expect("observe plaintext");
    assert_eq!(observation.current_fence(), FenceToken::new(1));
    assert!(
        observation.record().expect("record").payload.as_bytes() == SYNTHETIC_PAYLOAD,
        "local observation must return the logical payload"
    );
    assert_eq!(
        provider.calls(),
        calls_before_observation + 1,
        "exactly one unprotect"
    );
    assert!(format!("{observation:?}").contains("redacted"));
    assert!(!format!("{observation:?}")
        .contains(std::str::from_utf8(SYNTHETIC_PAYLOAD).expect("synthetic payload is UTF-8")));
    spy.set_observed(None);
    let calls_before_none = provider.calls();
    let none = backend
        .observe_fenced_transition(&key())
        .await
        .expect("observe absent");
    assert!(none.record().is_none());
    assert_eq!(none.current_fence(), FenceToken::new(0));
    assert_eq!(
        provider.calls(),
        calls_before_none,
        "None must not unprotect"
    );
    drop(token);

    let remote_spy = Arc::new(AtomicSpy::new());
    let remote_provider = CountingRemoteProvider::with_key("observe-remote", 0x42);
    let remote_journal = JournalFixture::new(0x94);
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(remote_journal.open());
    remote
        .prepare_fenced_transition(create_request(11))
        .await
        .expect("prepare remote observation fixture");
    let remote_protected = remote_spy
        .prepared()
        .pop()
        .expect("captured remote protected request");
    remote_spy.set_observed(remote_protected.mutation().record().cloned());
    let calls_before_remote_observation = remote_provider.calls();
    let remote_observation = remote
        .observe_fenced_transition(&key())
        .await
        .expect("remote observe plaintext");
    assert!(
        remote_observation
            .record()
            .expect("record")
            .payload
            .as_bytes()
            == SYNTHETIC_PAYLOAD,
        "remote observation must return the logical payload"
    );
    assert_eq!(remote_observation.current_fence(), FenceToken::new(1));
    assert_eq!(remote_provider.calls(), calls_before_remote_observation + 1);
    remote_spy.set_observed(None);
    let calls_before_remote_none = remote_provider.calls();
    assert!(remote
        .observe_fenced_transition(&key())
        .await
        .expect("remote observe absent")
        .record()
        .is_none());
    assert_eq!(remote_provider.calls(), calls_before_remote_none);
}

#[tokio::test]
async fn protected_fenced_transition_full_surface_forwards_through_session_store_without_readback()
{
    let spy = Arc::new(AtomicSpy::new());
    let provider = CountingKeyProvider::with_key("session-store-before-rotation", 0x53);
    let journal = JournalFixture::new(0x95);
    let wrapper = Arc::new(
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
            .with_fenced_transition_journal(journal.open()),
    );
    let store = SessionStore::from_arc(wrapper);

    assert_eq!(
        store
            .fenced_transition_capability()
            .await
            .expect("SessionStore capability"),
        Some(AtomicFencedTransitionCapability::V2)
    );
    let prepared = store
        .prepare_fenced_transition(create_request(17))
        .await
        .expect("prepare create through SessionStore");
    let request_id = prepared.request_id();
    let durable = Zeroizing::new(prepared.as_bytes().to_vec());
    let physical = spy.prepared().pop().expect("captured physical request");
    assert_eq!(
        physical
            .mutation()
            .record()
            .expect("physical record")
            .payload
            .encoding(),
        SessionPayloadEncoding::EnvelopeV1
    );
    assert_eq!(provider.calls(), 1, "SessionStore preparation seals once");
    assert!(matches!(
        store.fenced_transition(&prepared).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));

    let rotated = CountingKeyProvider::with_key("session-store-after-rotation", 0x54);
    let reconstructed = SessionStore::from_arc(Arc::new(
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&rotated), NAMESPACE)
            .with_fenced_transition_journal(journal.open()),
    ));
    let restored = match reconstructed
        .recover_prepared_fenced_transition(request_id)
        .await
        .expect("recover through SessionStore")
    {
        PreparedFencedTransitionLookup::Found(prepared) => prepared,
        PreparedFencedTransitionLookup::Absent => panic!("durable prepared request was lost"),
    };
    assert!(
        restored.as_bytes() == durable.as_slice(),
        "SessionStore recovery must preserve the exact opaque token"
    );
    assert!(matches!(
        reconstructed.fenced_transition(&restored).await,
        Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        reconstructed.fenced_transition_status(&restored).await,
        Ok(FencedTransitionStatus::Recorded(_))
    ));
    assert_eq!(rotated.calls(), 0, "recovery must not use the rotated key");
    assert_eq!(
        spy.get_calls(),
        0,
        "SessionStore recovery must not read back"
    );

    spy.set_observed(physical.mutation().record().cloned());
    let observation = store
        .observe_fenced_transition(&key())
        .await
        .expect("observe through SessionStore");
    assert!(
        observation
            .record()
            .expect("observed record")
            .payload
            .as_bytes()
            == SYNTHETIC_PAYLOAD,
        "SessionStore observation must return the logical payload"
    );
    assert_eq!(observation.current_fence(), FenceToken::new(1));
}

#[tokio::test]
async fn protected_fenced_transition_delete_and_refresh_are_provider_free_through_session_store() {
    let remote_spy = Arc::new(AtomicSpy::new());
    let remote_provider = CountingRemoteProvider::with_key("remote-no-record", 0x51);
    let remote_journal = JournalFixture::new(0x96);
    let wrapper = Arc::new(
        RemoteSealingSessionBackend::new(
            Arc::clone(&remote_spy),
            Arc::clone(&remote_provider),
            NAMESPACE,
        )
        .with_fenced_transition_journal(remote_journal.open()),
    );
    let store = SessionStore::from_arc(wrapper);

    let delete = store
        .prepare_fenced_transition(delete_request(5))
        .await
        .expect("prepare delete via SessionStore");
    let remote_refresh = store
        .prepare_fenced_transition(refresh_request(6))
        .await
        .expect("prepare refresh via SessionStore");
    assert_eq!(
        remote_provider.calls(),
        0,
        "record-free mutations must not seal"
    );
    assert!(remote_spy.prepared()[0].mutation().record().is_none());
    assert!(remote_spy.prepared()[1].mutation().record().is_none());
    assert!(matches!(
        store.fenced_transition(&delete).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        store.fenced_transition_status(&delete).await,
        Ok(FencedTransitionStatus::NotFound)
    ));
    assert!(matches!(
        store.fenced_transition(&remote_refresh).await,
        Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        store.fenced_transition_status(&remote_refresh).await,
        Ok(FencedTransitionStatus::Recorded(_))
    ));
    assert_eq!(
        remote_provider.calls(),
        0,
        "remote delete/refresh prepare, execute, and status must be provider-free"
    );
    assert!(
        remote_spy
            .state
            .lock()
            .expect("spy lock")
            .observed
            .is_none(),
        "no record was fabricated"
    );

    let local_spy = Arc::new(AtomicSpy::new());
    let local_provider = CountingKeyProvider::with_key("local-no-record", 0x52);
    let local_journal = JournalFixture::new(0x97);
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(local_journal.open());
    let local_delete = local
        .prepare_fenced_transition(delete_request(12))
        .await
        .expect("prepare local delete");
    let local_refresh = local
        .prepare_fenced_transition(refresh_request(13))
        .await
        .expect("prepare local refresh");
    assert!(matches!(
        local.fenced_transition(&local_delete).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        local.fenced_transition_status(&local_delete).await,
        Ok(FencedTransitionStatus::NotFound)
    ));
    assert!(matches!(
        local.fenced_transition(&local_refresh).await,
        Err(FencedTransitionExecuteError::OutcomeUnknown { .. })
    ));
    assert!(matches!(
        local.fenced_transition_status(&local_refresh).await,
        Ok(FencedTransitionStatus::Recorded(_))
    ));
    assert!(local_spy
        .prepared()
        .iter()
        .all(|request| request.mutation().record().is_none()));
    assert_eq!(
        local_provider.calls(),
        0,
        "local delete/refresh prepare, execute, and status must be provider-free"
    );
}

#[tokio::test]
async fn protected_fenced_transition_rejects_both_nested_protection_orders() {
    let local_over_remote_spy = Arc::new(AtomicSpy::new());
    let inner_remote_provider = CountingRemoteProvider::with_key("nested-inner-remote", 0x71);
    let outer_local_provider = CountingKeyProvider::with_key("nested-outer-local", 0x72);
    let inner_remote = Arc::new(RemoteSealingSessionBackend::new(
        Arc::clone(&local_over_remote_spy),
        Arc::clone(&inner_remote_provider),
        NAMESPACE,
    ));
    let local_over_remote_journal = JournalFixture::new(0x98);
    let local_over_remote =
        EncryptingSessionBackend::new(inner_remote, Arc::clone(&outer_local_provider), NAMESPACE)
            .with_fenced_transition_journal(local_over_remote_journal.open());

    assert_eq!(
        local_over_remote
            .fenced_transition_capability()
            .await
            .expect("nested capability"),
        None
    );
    assert!(matches!(
        local_over_remote
            .prepare_fenced_transition(create_request(19))
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        local_over_remote.observe_fenced_transition(&key()).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    let raw_local_token = PreparedFencedTransition::from_unprotected_request(create_request(21))
        .expect("raw test token");
    assert!(matches!(
        local_over_remote.fenced_transition(&raw_local_token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        local_over_remote
            .recover_prepared_fenced_transition(raw_local_token.request_id())
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        local_over_remote
            .fenced_transition_status(&raw_local_token)
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert_eq!(outer_local_provider.calls(), 0);
    assert_eq!(inner_remote_provider.calls(), 0);
    assert_eq!(local_over_remote_spy.preflight_calls(), 0);
    assert!(local_over_remote_spy.prepared().is_empty());
    assert_eq!(local_over_remote_spy.dispatches(), 0);
    assert!(local_over_remote_spy.statuses().is_empty());

    let remote_over_local_spy = Arc::new(AtomicSpy::new());
    let inner_local_provider = CountingKeyProvider::with_key("nested-inner-local", 0x73);
    let outer_remote_provider = CountingRemoteProvider::with_key("nested-outer-remote", 0x74);
    let inner_local = Arc::new(EncryptingSessionBackend::new(
        Arc::clone(&remote_over_local_spy),
        Arc::clone(&inner_local_provider),
        NAMESPACE,
    ));
    let remote_over_local_journal = JournalFixture::new(0x99);
    let remote_over_local = RemoteSealingSessionBackend::new(
        inner_local,
        Arc::clone(&outer_remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(remote_over_local_journal.open());

    assert_eq!(
        remote_over_local
            .fenced_transition_capability()
            .await
            .expect("nested capability"),
        None
    );
    assert!(matches!(
        remote_over_local
            .prepare_fenced_transition(create_request(20))
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        remote_over_local.observe_fenced_transition(&key()).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    let raw_remote_token = PreparedFencedTransition::from_unprotected_request(create_request(22))
        .expect("raw test token");
    assert!(matches!(
        remote_over_local.fenced_transition(&raw_remote_token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        remote_over_local
            .recover_prepared_fenced_transition(raw_remote_token.request_id())
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        remote_over_local
            .fenced_transition_status(&raw_remote_token)
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert_eq!(outer_remote_provider.calls(), 0);
    assert_eq!(inner_local_provider.calls(), 0);
    assert_eq!(remote_over_local_spy.preflight_calls(), 0);
    assert!(remote_over_local_spy.prepared().is_empty());
    assert_eq!(remote_over_local_spy.dispatches(), 0);
    assert!(remote_over_local_spy.statuses().is_empty());
}

#[tokio::test]
async fn protected_fenced_transition_capability_preflight_and_token_binding_fail_closed_before_effects(
) {
    let spy = Arc::new(AtomicSpy::new());
    let provider = CountingKeyProvider::with_key("local-validation", 0x61);
    let unjournaled =
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE);
    assert_eq!(
        unjournaled
            .fenced_transition_capability()
            .await
            .expect("unjournaled capability"),
        None
    );
    assert!(matches!(
        unjournaled
            .prepare_fenced_transition(create_request(23))
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    let local_journal = JournalFixture::new(0xa0);
    let backend = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
        .with_fenced_transition_journal(local_journal.open());
    assert_eq!(
        backend
            .fenced_transition_capability()
            .await
            .expect("capability"),
        Some(AtomicFencedTransitionCapability::V2)
    );
    spy.disable_capability();
    assert_eq!(
        backend
            .fenced_transition_capability()
            .await
            .expect("capability"),
        None
    );
    assert!(matches!(
        backend.prepare_fenced_transition(create_request(7)).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert_eq!(provider.calls(), 0);
    assert_eq!(spy.preflight_calls(), 0);
    assert!(spy.prepared().is_empty());

    spy.state.lock().expect("spy lock").capability = Some(AtomicFencedTransitionCapability::V1);
    spy.reject_expiry_preflight();
    assert!(matches!(
        backend.prepare_fenced_transition(create_request(8)).await,
        Err(StoreError::InvalidRecordExpiry)
    ));
    assert_eq!(
        provider.calls(),
        0,
        "expiry rejection precedes local encryption"
    );
    assert!(
        spy.prepared().is_empty(),
        "expiry rejection precedes inner prepare/dispatch"
    );
    assert_eq!(spy.preflight_calls(), 1);

    spy.state.lock().expect("spy lock").reject_expiry_preflight = false;
    let valid = create_request(9);
    let mut malformed = serde_json::to_value(&valid).expect("serialize request");
    malformed["request_id"] = serde_json::json!(vec![0_u8; 16]);
    let malformed: FencedTransitionRequest =
        serde_json::from_value(malformed).expect("deserialize raw request");
    assert!(matches!(
        backend.prepare_fenced_transition(malformed).await,
        Err(StoreError::InvalidKey(_))
    ));
    assert_eq!(
        provider.calls(),
        0,
        "structural rejection precedes provider work"
    );
    assert_eq!(
        spy.preflight_calls(),
        1,
        "structural rejection precedes expiry preflight"
    );
    assert!(spy.prepared().is_empty());

    let invalid_namespace_provider = CountingKeyProvider::with_key("invalid-namespace", 0x64);
    let invalid_namespace_journal = JournalFixture::new(0xa1);
    let invalid_namespace = EncryptingSessionBackend::new(
        Arc::clone(&spy),
        Arc::clone(&invalid_namespace_provider),
        "",
    )
    .with_fenced_transition_journal(invalid_namespace_journal.open());
    assert_eq!(
        invalid_namespace
            .fenced_transition_capability()
            .await
            .expect("invalid namespace capability"),
        None
    );
    assert!(matches!(
        invalid_namespace
            .prepare_fenced_transition(create_request(14))
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert_eq!(invalid_namespace_provider.calls(), 0);
    assert_eq!(spy.preflight_calls(), 1);
    assert!(spy.prepared().is_empty());

    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.reject_expiry_preflight();
    let remote_provider = CountingRemoteProvider::with_key("remote-validation", 0x65);
    let remote_journal = JournalFixture::new(0xa2);
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(remote_journal.open());
    assert!(matches!(
        remote.prepare_fenced_transition(create_request(15)).await,
        Err(StoreError::InvalidRecordExpiry)
    ));
    assert_eq!(remote_provider.calls(), 0);
    assert_eq!(remote_spy.preflight_calls(), 1);
    assert!(remote_spy.prepared().is_empty());
    remote_spy.disable_capability();
    assert_eq!(
        remote
            .fenced_transition_capability()
            .await
            .expect("remote disabled capability"),
        None
    );
    assert!(matches!(
        remote.prepare_fenced_transition(create_request(16)).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert_eq!(remote_provider.calls(), 0);
    assert_eq!(remote_spy.preflight_calls(), 1);

    let token = backend
        .prepare_fenced_transition(valid)
        .await
        .expect("prepare valid local token");
    let wrong_namespace_provider = CountingKeyProvider::with_key("wrong-namespace", 0x62);
    let wrong_namespace = EncryptingSessionBackend::new(
        Arc::clone(&spy),
        Arc::clone(&wrong_namespace_provider),
        "other-protected-fenced-transition",
    )
    .with_fenced_transition_journal(local_journal.open());
    let dispatches_before = spy.dispatches();
    assert!(matches!(
        wrong_namespace.fenced_transition(&token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert_eq!(wrong_namespace_provider.calls(), 0);
    assert_eq!(spy.dispatches(), dispatches_before);
    let wrong_mode_provider = CountingRemoteProvider::with_key("wrong-mode", 0x63);
    let wrong_mode = RemoteSealingSessionBackend::new(
        Arc::clone(&spy),
        Arc::clone(&wrong_mode_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(local_journal.open());
    assert!(matches!(
        wrong_mode.fenced_transition(&token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        wrong_mode.fenced_transition_status(&token).await,
        Err(StoreError::Serialization(_))
    ));
    assert_eq!(wrong_mode_provider.calls(), 0);
    assert_eq!(spy.dispatches(), dispatches_before);
    assert_eq!(spy.get_calls(), 0, "fail-closed paths must not read back");
}
