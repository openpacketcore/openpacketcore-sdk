use std::{
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

use crate::{
    checked_session_deadline, AtomicFencedTransitionCapability, BackendCapabilities, CompareAndSet,
    CompareAndSetResult, EncryptedSessionPayload, EncryptingSessionBackend, FenceToken,
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
    FencedTransitionObservation, FencedTransitionOutcome, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionStatus, Generation, LeaseError, LeaseGuard, OwnerId,
    PreparedFencedTransition, RemoteSealingSessionBackend, SessionBackend, SessionKey,
    SessionKeyType, SessionLeaseManager, SessionOp, SessionOpResult, SessionStore, StateClass,
    StateType, StoreError, StoredSessionRecord,
};

const NAMESPACE: &str = "protected-fenced-transition";
const PLAINTEXT: &[u8] = b"protected-fenced-transition-secret";

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
        payload: EncryptedSessionPayload::new(PLAINTEXT),
    }
}

fn create_request(id: u8) -> FencedTransitionRequest {
    create_request_with_payload(id, PLAINTEXT)
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
    dispatches: usize,
    receipt: Option<(FencedTransitionRequest, FencedTransitionOutcome)>,
}

/// A deliberately adversarial atomic boundary: first dispatch is definitely
/// absent, second commits but reports ambiguity, and later exact retries
/// recover the retained receipt.
#[derive(Default)]
struct AtomicSpy {
    state: Mutex<SpyState>,
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

    fn set_observed(&self, record: Option<StoredSessionRecord>) {
        self.state.lock().expect("spy lock").observed = record;
    }

    fn reject_expiry_preflight(&self) {
        self.state.lock().expect("spy lock").reject_expiry_preflight = true;
    }

    fn disable_capability(&self) {
        self.state.lock().expect("spy lock").capability = None;
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
        self.state
            .lock()
            .expect("spy lock")
            .prepared
            .push(request.clone());
        PreparedFencedTransition::from_unprotected_request(request)
    }

    async fn fenced_transition(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionOutcome, StoreError> {
        let request = prepared.request_for_unprotected_backend()?;
        let mut state = self.state.lock().expect("spy lock");
        state.executed.push(request.clone());
        state.dispatches += 1;
        if let Some((bound, outcome)) = &state.receipt {
            return if bound == &request {
                Ok(outcome.clone())
            } else if bound.request_id() == request.request_id() {
                Err(StoreError::FencedTransitionRequestConflict)
            } else {
                Err(StoreError::FencedTransitionOutcomeUnknown)
            };
        }
        if state.dispatches == 1 {
            return Err(StoreError::BackendUnavailable("not transmitted".into()));
        }
        let outcome = outcome_for(&request);
        state.receipt = Some((request, outcome));
        Err(StoreError::FencedTransitionOutcomeUnknown)
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
async fn protected_fenced_transition_local_prepares_once_and_recovers_exact_physical_request() {
    let spy = Arc::new(AtomicSpy::new());
    let provider = CountingKeyProvider::with_key("local-before-rotation", 0x11);
    let backend: Arc<dyn SessionBackend> = Arc::new(EncryptingSessionBackend::new(
        Arc::clone(&spy) as Arc<dyn SessionBackend>,
        Arc::clone(&provider),
        NAMESPACE,
    ));

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
        assert_ne!(
            request
                .mutation()
                .record()
                .expect("record")
                .payload
                .as_bytes(),
            PLAINTEXT
        );
    }
    let restored: PreparedFencedTransition =
        serde_json::from_slice(&serde_json::to_vec(&prepared).expect("serialize opaque token"))
            .expect("deserialize opaque token");
    assert_eq!(restored, prepared);
    assert!(format!("{prepared:?}").contains("redacted"));
    assert!(!format!("{prepared:?}").contains("protected-fenced-transition-secret"));

    assert!(matches!(
        backend.fenced_transition(&restored).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert!(matches!(
        backend.fenced_transition(&restored).await,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    ));

    let rotated = CountingKeyProvider::with_key("local-after-rotation", 0x22);
    let reconstructed =
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&rotated), NAMESPACE);
    let replay = reconstructed
        .fenced_transition(&restored)
        .await
        .expect("exact replay after rotation");
    assert!(replay.matches_request(&physical[0]));
    assert!(matches!(
        reconstructed.fenced_transition_status(&restored).await,
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
    assert_eq!(spy.statuses(), vec![physical[0].clone()]);

    let fresh = backend
        .prepare_fenced_transition(create_request_with_payload(1, b"fresh-local-body"))
        .await
        .expect("fresh encryption under same ID is structurally valid");
    assert_eq!(provider.calls(), 3, "fresh request reseals once");
    assert!(matches!(
        backend.fenced_transition(&fresh).await,
        Err(StoreError::FencedTransitionRequestConflict)
    ));
    assert_ne!(
        spy.prepared()[2],
        physical[0],
        "a freshly sealed different body must not rebind an existing request ID"
    );
}

#[tokio::test]
async fn protected_fenced_transition_remote_prepares_create_and_update_once_with_dynamic_composition(
) {
    let spy = Arc::new(AtomicSpy::new());
    let provider = CountingRemoteProvider::with_key("remote-before-rotation", 0x31);
    let backend: Arc<dyn SessionBackend> = Arc::new(RemoteSealingSessionBackend::new(
        Arc::clone(&spy) as Arc<dyn SessionBackend>,
        Arc::clone(&provider),
        NAMESPACE,
    ));
    assert_eq!(
        backend
            .fenced_transition_capability()
            .await
            .expect("capability"),
        Some(AtomicFencedTransitionCapability::V1),
        "dynamic remote composition must preserve the exact V1 contract"
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
        assert_ne!(
            request
                .mutation()
                .record()
                .expect("record")
                .payload
                .as_bytes(),
            PLAINTEXT
        );
    }
    let restored =
        PreparedFencedTransition::try_from_bytes(create.as_bytes()).expect("token round trip");
    assert_eq!(restored, create);
    assert!(matches!(
        backend.fenced_transition(&restored).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert!(matches!(
        backend.fenced_transition(&restored).await,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    ));

    let rotated = CountingRemoteProvider::with_key("remote-after-rotation", 0x32);
    let reconstructed =
        RemoteSealingSessionBackend::new(Arc::clone(&spy), Arc::clone(&rotated), NAMESPACE);
    assert!(reconstructed
        .fenced_transition(&restored)
        .await
        .expect("exact remote replay")
        .matches_request(&physical[0]));
    assert!(matches!(
        reconstructed.fenced_transition_status(&restored).await,
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
    let fresh = backend
        .prepare_fenced_transition(create_request_with_payload(2, b"fresh-remote-body"))
        .await
        .expect("fresh remote same-ID preparation");
    assert_eq!(
        provider.calls(),
        3,
        "fresh remote request seals exactly once"
    );
    assert!(matches!(
        backend.fenced_transition(&fresh).await,
        Err(StoreError::FencedTransitionRequestConflict)
    ));
    assert_ne!(
        spy.prepared()[2],
        physical[0],
        "same request ID may not bind a newly sealed remote body"
    );
}

#[tokio::test]
async fn protected_fenced_transition_observation_unprotects_once_preserves_fence_and_none_is_inert()
{
    let spy = Arc::new(AtomicSpy::new());
    let provider = CountingKeyProvider::with_key("observe-local", 0x41);
    let backend = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE);
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
    );
    let error = unavailable
        .observe_fenced_transition(&key())
        .await
        .expect_err("missing key must fail observation");
    assert!(matches!(error, StoreError::Crypto(_)));
    assert!(
        !format!("{error} {error:?}").contains("protected-fenced-transition-secret"),
        "observation failure must not become a plaintext oracle"
    );
    let calls_before_observation = provider.calls();
    let observation = backend
        .observe_fenced_transition(&key())
        .await
        .expect("observe plaintext");
    assert_eq!(observation.current_fence(), FenceToken::new(1));
    assert_eq!(
        observation.record().expect("record").payload.as_bytes(),
        PLAINTEXT
    );
    assert_eq!(
        provider.calls(),
        calls_before_observation + 1,
        "exactly one unprotect"
    );
    assert!(format!("{observation:?}").contains("redacted"));
    assert!(!format!("{observation:?}").contains("protected-fenced-transition-secret"));
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
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    );
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
    assert_eq!(
        remote_observation
            .record()
            .expect("record")
            .payload
            .as_bytes(),
        PLAINTEXT
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
async fn protected_fenced_transition_delete_and_refresh_are_provider_free_through_session_store() {
    let remote_spy = Arc::new(AtomicSpy::new());
    let remote_provider = CountingRemoteProvider::with_key("remote-no-record", 0x51);
    let wrapper = Arc::new(RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    ));
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
        Err(StoreError::BackendUnavailable(_))
    ));
    assert!(matches!(
        store.fenced_transition_status(&delete).await,
        Ok(FencedTransitionStatus::NotFound)
    ));
    assert!(matches!(
        store.fenced_transition(&remote_refresh).await,
        Err(StoreError::FencedTransitionOutcomeUnknown)
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
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_provider),
        NAMESPACE,
    );
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
        Err(StoreError::BackendUnavailable(_))
    ));
    assert!(matches!(
        local.fenced_transition_status(&local_delete).await,
        Ok(FencedTransitionStatus::NotFound)
    ));
    assert!(matches!(
        local.fenced_transition(&local_refresh).await,
        Err(StoreError::FencedTransitionOutcomeUnknown)
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
    let local_over_remote =
        EncryptingSessionBackend::new(inner_remote, Arc::clone(&outer_local_provider), NAMESPACE);

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
    let remote_over_local = RemoteSealingSessionBackend::new(
        inner_local,
        Arc::clone(&outer_remote_provider),
        NAMESPACE,
    );

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
    let backend = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE);
    assert_eq!(
        backend
            .fenced_transition_capability()
            .await
            .expect("capability"),
        Some(AtomicFencedTransitionCapability::V1)
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
    let invalid_namespace = EncryptingSessionBackend::new(
        Arc::clone(&spy),
        Arc::clone(&invalid_namespace_provider),
        "",
    );
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
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    );
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
    );
    let dispatches_before = spy.dispatches();
    assert!(matches!(
        wrong_namespace.fenced_transition(&token).await,
        Err(StoreError::Serialization(_))
    ));
    assert_eq!(wrong_namespace_provider.calls(), 0);
    assert_eq!(spy.dispatches(), dispatches_before);
    let wrong_mode_provider = CountingRemoteProvider::with_key("wrong-mode", 0x63);
    let wrong_mode = RemoteSealingSessionBackend::new(
        Arc::clone(&spy),
        Arc::clone(&wrong_mode_provider),
        NAMESPACE,
    );
    assert!(matches!(
        wrong_mode.fenced_transition_status(&token).await,
        Err(StoreError::Serialization(_))
    ));
    assert_eq!(wrong_mode_provider.calls(), 0);
    assert_eq!(spy.dispatches(), dispatches_before);
}
