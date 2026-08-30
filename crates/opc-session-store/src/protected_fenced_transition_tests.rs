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

use crate::fenced_transition::FencedTransitionV2Effect;
use crate::{
    checked_session_deadline, validate_consensus_physical_fenced_transition_request,
    AtomicFencedTransitionCapability, BackendCapabilities, CompareAndSet, CompareAndSetResult,
    EncryptedSessionPayload, EncryptingSessionBackend, FenceToken, FencedTransitionExecuteError,
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
    FencedTransitionObservation, FencedTransitionOutcome, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionStatus, FencedTransitionV2CallerNonce,
    FencedTransitionV2Capability, FencedTransitionV2HistoryEpoch, FencedTransitionV2HistoryState,
    FencedTransitionV2JournalScope, FencedTransitionV2PreparedJournal,
    FencedTransitionV2PreparedJournalKey, FencedTransitionV2Request, FencedTransitionV2Status,
    Generation, LeaseError, LeaseGuard, OwnerId, PreparedFencedTransition,
    PreparedFencedTransitionJournal, PreparedFencedTransitionJournalKey,
    PreparedFencedTransitionLookup, ProtectedSessionBackend, RemoteSealingSessionBackend,
    SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, SessionOp, SessionOpResult,
    SessionPayloadEncoding, SessionStore, StateClass, StateType, StoreError, StoredSessionRecord,
    FENCED_TRANSITION_MAX_PREPARED_BYTES,
};

const NAMESPACE: &str = "protected-fenced-transition";
const SYNTHETIC_PAYLOAD: &[u8] = b"synthetic-opaque-payload";

struct JournalFixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    v2_path: PathBuf,
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
        let v2_path = directory.path().join("prepared-v2.sqlite3");
        Self {
            _directory: directory,
            path,
            v2_path,
            key: [fill; 32],
        }
    }

    fn open(&self) -> Arc<PreparedFencedTransitionJournal> {
        let key = PreparedFencedTransitionJournalKey::from_bytes(self.key);
        Arc::new(
            if self.path.exists() {
                PreparedFencedTransitionJournal::open_existing(&self.path, key)
            } else {
                PreparedFencedTransitionJournal::create_new(&self.path, key)
            }
            .expect("open prepared journal"),
        )
    }

    fn open_v2(&self) -> Arc<FencedTransitionV2PreparedJournal> {
        let key = FencedTransitionV2PreparedJournalKey::from_bytes(self.key);
        Arc::new(
            if self.v2_path.exists() {
                FencedTransitionV2PreparedJournal::open_existing(&self.v2_path, key)
            } else {
                FencedTransitionV2PreparedJournal::create_new(&self.v2_path, key)
            }
            .expect("open V2 prepared journal"),
        )
    }

    fn v2_scope(&self) -> FencedTransitionV2JournalScope {
        FencedTransitionV2JournalScope::from_bytes([self.key[0] ^ 0x5a; 32])
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

    fn delete_prepared_token(&self) {
        let connection =
            rusqlite::Connection::open(&self.path).expect("open journal fixture for deletion");
        assert_eq!(
            connection
                .execute("DELETE FROM prepared_fenced_transition_journal", [])
                .expect("delete prepared fixture token"),
            1
        );
    }

    fn substitute_prepared_token(
        &self,
        target: FencedTransitionRequestId,
        replacement: FencedTransitionRequestId,
    ) {
        let connection =
            rusqlite::Connection::open(&self.path).expect("open journal fixture for substitution");
        assert_eq!(
            connection
                .execute(
                    "UPDATE prepared_fenced_transition_journal \
                     SET prepared_schema_version = (SELECT prepared_schema_version \
                         FROM prepared_fenced_transition_journal WHERE request_id = ?1), \
                         prepared_token = (SELECT prepared_token \
                         FROM prepared_fenced_transition_journal WHERE request_id = ?1), \
                         integrity_tag = (SELECT integrity_tag \
                         FROM prepared_fenced_transition_journal WHERE request_id = ?1) \
                     WHERE request_id = ?2",
                    rusqlite::params![replacement.as_bytes(), target.as_bytes()],
                )
                .expect("substitute a different journaled prepared token"),
            1
        );
    }
}

fn protected_v2_journal_scope_for<B: SessionBackend + ?Sized>(
    backend: &B,
    scope: FencedTransitionV2JournalScope,
    namespace: &str,
    mode: crate::backend::ProtectedFencedTransitionV2JournalMode,
) -> [u8; 32] {
    crate::backend::protected_fenced_transition_v2_journal_scope(
        backend,
        Some(scope),
        namespace,
        mode,
    )
    .expect("valid protected V2 test scope")
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
    create_request_with_encoded_payload(id, EncryptedSessionPayload::new(payload))
}

fn create_request_with_encoded_payload(
    id: u8,
    payload: EncryptedSessionPayload,
) -> FencedTransitionRequest {
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
    record.payload = payload;
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes([id; 16]),
        lease,
        FencedTransitionMutation::create(record),
    )
    .expect("valid create request")
}

fn update_request(id: u8) -> FencedTransitionRequest {
    update_request_with_encoded_payload(id, EncryptedSessionPayload::new(SYNTHETIC_PAYLOAD))
}

fn update_request_with_encoded_payload(
    id: u8,
    payload: EncryptedSessionPayload,
) -> FencedTransitionRequest {
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
        FencedTransitionMutation::update(Generation::new(1), {
            let mut record = record(key, owner, FenceToken::new(1), 2);
            record.payload = payload;
            record
        }),
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

fn initial_v2_epoch() -> FencedTransitionV2HistoryEpoch {
    FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch")
}

fn active_v2_history(epoch: FencedTransitionV2HistoryEpoch) -> FencedTransitionV2HistoryState {
    FencedTransitionV2HistoryState::new(Some(epoch), None, None, 0, 1, 0, 0)
        .expect("active V2 history")
}

fn create_v2_request(id: u8, epoch: FencedTransitionV2HistoryEpoch) -> FencedTransitionV2Request {
    let request = create_request(id);
    FencedTransitionV2Request::new(
        epoch,
        FencedTransitionV2CallerNonce::from_bytes([id; 16]),
        request.lease().clone(),
        request.mutation().clone(),
    )
    .expect("valid V2 create request")
}

fn create_v2_request_with_payload(
    id: u8,
    epoch: FencedTransitionV2HistoryEpoch,
    payload: &[u8],
) -> FencedTransitionV2Request {
    let request = create_request_with_payload(id, payload);
    FencedTransitionV2Request::new(
        epoch,
        FencedTransitionV2CallerNonce::from_bytes([id; 16]),
        request.lease().clone(),
        request.mutation().clone(),
    )
    .expect("valid V2 create request with payload")
}

#[derive(Default)]
struct SpyState {
    capability: Option<AtomicFencedTransitionCapability>,
    capability_calls: usize,
    v2_capability: Option<FencedTransitionV2Capability>,
    v2_history: Option<FencedTransitionV2HistoryState>,
    v2_executed: Vec<FencedTransitionV2Request>,
    v2_statuses: Vec<FencedTransitionV2Request>,
    v2_delay_ambiguous_commit: bool,
    v2_not_transmitted: usize,
    v2_not_transmitted_gate: Option<V2NotTransmittedGate>,
    v2_not_transmitted_error: Option<StoreError>,
    v2_pending: Option<FencedTransitionV2Request>,
    v2_receipt: Option<(FencedTransitionV2Request, FencedTransitionOutcome)>,
    reject_expiry_preflight: bool,
    observed: Option<StoredSessionRecord>,
    observation_calls: usize,
    prepared: Vec<FencedTransitionRequest>,
    executed: Vec<FencedTransitionRequest>,
    statuses: Vec<FencedTransitionRequest>,
    preflight_calls: usize,
    get_calls: usize,
    dispatches: usize,
    delay_ambiguous_commit: bool,
    emit_nonphysical_prepared_token: bool,
    enforce_physical_admission: bool,
    pending: Option<FencedTransitionRequest>,
    receipt: Option<(FencedTransitionRequest, FencedTransitionOutcome)>,
}

#[derive(Clone)]
struct V2NotTransmittedGate {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
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

    fn capability_calls(&self) -> usize {
        self.state.lock().expect("spy lock").capability_calls
    }

    fn observation_calls(&self) -> usize {
        self.state.lock().expect("spy lock").observation_calls
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

    fn enforce_physical_admission(&self) {
        self.state
            .lock()
            .expect("spy lock")
            .enforce_physical_admission = true;
    }

    fn reject_physical_tokens(&self) {
        self.reject_physical_tokens.store(true, Ordering::SeqCst);
    }

    fn enable_v2(&self) {
        let mut state = self.state.lock().expect("spy lock");
        state.v2_capability = Some(FencedTransitionV2Capability::V2);
        state.v2_history = Some(active_v2_history(initial_v2_epoch()));
    }

    fn set_v2_history(&self, history: FencedTransitionV2HistoryState) {
        self.state.lock().expect("spy lock").v2_history = Some(history);
    }

    fn delay_v2_ambiguous_commit(&self) {
        self.state
            .lock()
            .expect("spy lock")
            .v2_delay_ambiguous_commit = true;
    }

    fn not_transmit_v2_once(&self) {
        self.state.lock().expect("spy lock").v2_not_transmitted += 1;
    }

    fn reject_v2_preproposal_once(&self) {
        let mut state = self.state.lock().expect("spy lock");
        state.v2_not_transmitted += 1;
        state.v2_not_transmitted_error = Some(StoreError::PayloadTooLarge { actual: 2, max: 1 });
    }

    fn block_next_v2_not_transmitted(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let mut state = self.state.lock().expect("spy lock");
        state.v2_not_transmitted += 1;
        state.v2_not_transmitted_gate = Some(V2NotTransmittedGate {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        (entered, release)
    }

    fn take_v2_not_transmitted_gate(&self) -> Option<(Option<V2NotTransmittedGate>, StoreError)> {
        let mut state = self.state.lock().expect("spy lock");
        if state.v2_not_transmitted == 0 {
            return None;
        }
        state.v2_not_transmitted -= 1;
        Some((
            state.v2_not_transmitted_gate.take(),
            state.v2_not_transmitted_error.take().unwrap_or_else(|| {
                StoreError::BackendUnavailable("synthetic V2 pre-dispatch failure".into())
            }),
        ))
    }

    fn commit_v2_delayed(&self) {
        let mut state = self.state.lock().expect("spy lock");
        let request = state.v2_pending.take().expect("pending V2 transition");
        let outcome = v2_outcome_for(&request);
        state.v2_receipt = Some((request, outcome));
    }

    fn clear_v2_receipt(&self) {
        self.state.lock().expect("spy lock").v2_receipt = None;
    }

    fn v2_executed(&self) -> Vec<FencedTransitionV2Request> {
        self.state.lock().expect("spy lock").v2_executed.clone()
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

fn v2_outcome_for(request: &FencedTransitionV2Request) -> FencedTransitionOutcome {
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
        let mut state = self.state.lock().expect("spy lock");
        state.observation_calls += 1;
        let fence = state
            .observed
            .as_ref()
            .map_or(FenceToken::new(0), |record| record.fence);
        FencedTransitionObservation::new(state.observed.clone(), fence)
    }

    async fn fenced_transition_capability(
        &self,
    ) -> Result<Option<AtomicFencedTransitionCapability>, StoreError> {
        let mut state = self.state.lock().expect("spy lock");
        state.capability_calls += 1;
        Ok(state.capability)
    }

    async fn fenced_transition_v2_capability(
        &self,
    ) -> Result<Option<FencedTransitionV2Capability>, StoreError> {
        Ok(self.state.lock().expect("spy lock").v2_capability)
    }

    async fn fenced_transition_v2_history_state(
        &self,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        self.state
            .lock()
            .expect("spy lock")
            .v2_history
            .ok_or_else(|| {
                StoreError::CapabilityNotSupported(
                    "atomic_fenced_transition_epoch_history_v2".into(),
                )
            })
    }

    async fn fenced_transition_v2(
        &self,
        request: FencedTransitionV2Request,
    ) -> Result<FencedTransitionOutcome, StoreError> {
        request.validate()?;
        let mut state = self.state.lock().expect("spy lock");
        let history = state.v2_history.ok_or_else(|| {
            StoreError::CapabilityNotSupported("atomic_fenced_transition_epoch_history_v2".into())
        })?;
        let epoch = request.request_id().epoch();
        if history
            .retired_through()
            .is_some_and(|floor| epoch <= floor)
        {
            return Err(StoreError::FencedTransitionHistoryEpochRetired);
        }
        if let Some((bound, outcome)) = state.v2_receipt.clone() {
            state.v2_executed.push(request.clone());
            return if bound.matches(&request) {
                Ok(outcome)
            } else if bound.request_id() == request.request_id() {
                Err(StoreError::FencedTransitionRequestConflict)
            } else {
                Err(StoreError::FencedTransitionOutcomeUnknown)
            };
        }
        if history.active_epoch() != Some(epoch) {
            return Err(StoreError::FencedTransitionHistoryEpochNotActive);
        }
        state.v2_executed.push(request.clone());
        if state.v2_delay_ambiguous_commit {
            state.v2_pending = Some(request);
            return Err(StoreError::FencedTransitionOutcomeUnknown);
        }
        let outcome = v2_outcome_for(&request);
        state.v2_receipt = Some((request, outcome.clone()));
        Ok(outcome)
    }

    async fn fenced_transition_v2_effect(
        &self,
        request: FencedTransitionV2Request,
    ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>> {
        let request_id = request.request_id();
        if let Some((gate, error)) = self.take_v2_not_transmitted_gate() {
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            return FencedTransitionV2Effect::NotTransmitted(error);
        }
        match self.fenced_transition_v2(request).await {
            Ok(outcome) => FencedTransitionV2Effect::Resolved(Ok(outcome)),
            Err(StoreError::FencedTransitionOutcomeUnknown) => {
                FencedTransitionV2Effect::OutcomeUnknown {
                    request_ids: vec![request_id],
                }
            }
            Err(error) => FencedTransitionV2Effect::Resolved(Err(error)),
        }
    }

    async fn fenced_transition_v2_batch(
        &self,
        requests: Vec<FencedTransitionV2Request>,
    ) -> Result<Vec<Result<FencedTransitionOutcome, StoreError>>, StoreError> {
        crate::consensus::types::validate_fenced_transition_v2_batch(&requests)?;
        let mut outcomes = Vec::with_capacity(requests.len());
        for request in requests {
            outcomes.push(self.fenced_transition_v2(request).await);
        }
        Ok(outcomes)
    }

    async fn fenced_transition_v2_batch_effect(
        &self,
        requests: Vec<FencedTransitionV2Request>,
    ) -> FencedTransitionV2Effect<
        Result<Vec<Result<FencedTransitionOutcome, StoreError>>, StoreError>,
    > {
        if let Err(error) = crate::consensus::types::validate_fenced_transition_v2_batch(&requests)
        {
            return FencedTransitionV2Effect::Resolved(Err(error));
        }
        if let Some((gate, error)) = self.take_v2_not_transmitted_gate() {
            if let Some(gate) = gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            return FencedTransitionV2Effect::NotTransmitted(error);
        }
        let request_ids = requests
            .iter()
            .map(FencedTransitionV2Request::request_id)
            .collect();
        match self.fenced_transition_v2_batch(requests).await {
            Ok(outcomes) => FencedTransitionV2Effect::Resolved(Ok(outcomes)),
            Err(StoreError::FencedTransitionOutcomeUnknown) => {
                FencedTransitionV2Effect::OutcomeUnknown { request_ids }
            }
            Err(error) => FencedTransitionV2Effect::Resolved(Err(error)),
        }
    }

    async fn fenced_transition_v2_status(
        &self,
        request: &FencedTransitionV2Request,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        if let Err(error) = request.validate() {
            return if matches!(error, StoreError::FencedTransitionRequestConflict) {
                Ok(FencedTransitionV2Status::RequestConflict)
            } else {
                Err(error)
            };
        }
        let mut state = self.state.lock().expect("spy lock");
        let history = state.v2_history.ok_or_else(|| {
            StoreError::CapabilityNotSupported("atomic_fenced_transition_epoch_history_v2".into())
        })?;
        let epoch = request.request_id().epoch();
        if history
            .retired_through()
            .is_some_and(|floor| epoch <= floor)
        {
            return Ok(FencedTransitionV2Status::Retired);
        }
        let status = match &state.v2_receipt {
            Some((bound, outcome)) if bound.matches(request) => {
                FencedTransitionV2Status::Recorded(Box::new(Ok(outcome.clone())))
            }
            Some((bound, _)) if bound.request_id() == request.request_id() => {
                FencedTransitionV2Status::RequestConflict
            }
            _ if history.active_epoch() == Some(epoch) => FencedTransitionV2Status::NotFound,
            _ => FencedTransitionV2Status::EpochNotActive,
        };
        state.v2_statuses.push(request.clone());
        Ok(status)
    }

    async fn prepare_fenced_transition(
        &self,
        request: FencedTransitionRequest,
    ) -> Result<PreparedFencedTransition, StoreError> {
        let emit_nonphysical_prepared_token = {
            let mut state = self.state.lock().expect("spy lock");
            if state.enforce_physical_admission {
                validate_consensus_physical_fenced_transition_request(&request)?;
            }
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

fn conflicting_v2_request(request: &FencedTransitionV2Request) -> FencedTransitionV2Request {
    let mut wire = serde_json::to_value(request).expect("serialize V2 request");
    let body_commitment = wire
        .get_mut("request_id")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|request_id| request_id.get_mut("body_commitment"))
        .and_then(serde_json::Value::as_array_mut)
        .expect("fixed-width V2 body commitment");
    let last = body_commitment
        .last()
        .and_then(serde_json::Value::as_u64)
        .expect("V2 body commitment byte");
    *body_commitment
        .last_mut()
        .expect("last V2 body commitment byte") = serde_json::json!(last ^ 1);
    serde_json::from_value(wire).expect("wire retains conflicting V2 request")
}

fn conflicting_v2_body_request(
    identity: &FencedTransitionV2Request,
    substituted_body: &FencedTransitionV2Request,
) -> FencedTransitionV2Request {
    let mut wire = serde_json::to_value(substituted_body).expect("serialize substituted V2 body");
    wire.as_object_mut().expect("V2 request object").insert(
        "request_id".into(),
        serde_json::to_value(identity.request_id()).expect("serialize V2 request ID"),
    );
    serde_json::from_value(wire).expect("wire retains same-ID conflicting V2 body")
}

#[tokio::test]
async fn protected_v2_batches_reuse_existing_mappings_and_seal_only_missing_items() {
    let epoch = initial_v2_epoch();

    let local_spy = Arc::new(AtomicSpy::new());
    local_spy.enable_v2();
    let local_fixture = JournalFixture::new(0xc1);
    let local_provider = CountingKeyProvider::with_key("local-v2-batch", 0x91);
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(local_fixture.open_v2())
    .with_fenced_transition_v2_journal_scope(local_fixture.v2_scope());
    let local_batch = vec![
        create_v2_request(0x41, epoch),
        create_v2_request(0x42, epoch),
        create_v2_request(0x43, epoch),
    ];
    assert!(local
        .fenced_transition_v2(local_batch[0].clone())
        .await
        .is_ok());
    assert_eq!(local_provider.calls(), 1);
    assert!(local
        .fenced_transition_v2_batch(local_batch.clone())
        .await
        .is_ok());
    assert_eq!(local_provider.calls(), 3, "only the two missing items seal");
    assert!(local.fenced_transition_v2_batch(local_batch).await.is_ok());
    assert_eq!(local_provider.calls(), 3, "exact replay does not reseal");
    let local_physical = local_spy.v2_executed();
    assert_eq!(local_physical.len(), 7);
    assert!(local_physical[0].matches(&local_physical[1]));
    assert!(local_physical[1].matches(&local_physical[4]));
    assert!(local_physical[2].matches(&local_physical[5]));
    assert!(local_physical[3].matches(&local_physical[6]));

    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.enable_v2();
    let remote_fixture = JournalFixture::new(0xc2);
    let remote_provider = CountingRemoteProvider::with_key("remote-v2-batch", 0x92);
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(remote_fixture.open_v2())
    .with_fenced_transition_v2_journal_scope(remote_fixture.v2_scope());
    let remote_batch = vec![
        create_v2_request(0x44, epoch),
        create_v2_request(0x45, epoch),
        create_v2_request(0x46, epoch),
    ];
    assert!(remote
        .fenced_transition_v2(remote_batch[0].clone())
        .await
        .is_ok());
    assert_eq!(remote_provider.calls(), 1);
    assert!(remote
        .fenced_transition_v2_batch(remote_batch.clone())
        .await
        .is_ok());
    assert_eq!(
        remote_provider.calls(),
        3,
        "only the two missing items seal"
    );
    assert!(remote
        .fenced_transition_v2_batch(remote_batch)
        .await
        .is_ok());
    assert_eq!(remote_provider.calls(), 3, "exact replay does not reseal");
    let remote_physical = remote_spy.v2_executed();
    assert_eq!(remote_physical.len(), 7);
    assert!(remote_physical[0].matches(&remote_physical[1]));
    assert!(remote_physical[1].matches(&remote_physical[4]));
    assert!(remote_physical[2].matches(&remote_physical[5]));
    assert!(remote_physical[3].matches(&remote_physical[6]));
}

#[tokio::test]
async fn protected_v2_batch_conflicts_are_synthetic_and_never_dispatched() {
    let epoch = initial_v2_epoch();

    let inert_local_spy = Arc::new(AtomicSpy::new());
    let inert_local_provider = CountingKeyProvider::with_key("local-v2-conflict-inert", 0xd1);
    let inert_local = EncryptingSessionBackend::new(
        Arc::clone(&inert_local_spy),
        Arc::clone(&inert_local_provider),
        NAMESPACE,
    );
    let inert_local_outcomes = inert_local
        .fenced_transition_v2_batch(vec![conflicting_v2_request(&create_v2_request(
            0xd1, epoch,
        ))])
        .await
        .expect("an all-conflict local batch is resolved without infrastructure");
    assert!(matches!(
        inert_local_outcomes.as_slice(),
        [Err(StoreError::FencedTransitionRequestConflict)]
    ));
    assert_eq!(inert_local_provider.calls(), 0);
    assert!(inert_local_spy.v2_executed().is_empty());

    let inert_remote_spy = Arc::new(AtomicSpy::new());
    let inert_remote_provider = CountingRemoteProvider::with_key("remote-v2-conflict-inert", 0xd2);
    let inert_remote = RemoteSealingSessionBackend::new(
        Arc::clone(&inert_remote_spy),
        Arc::clone(&inert_remote_provider),
        NAMESPACE,
    );
    let inert_remote_outcomes = inert_remote
        .fenced_transition_v2_batch(vec![conflicting_v2_request(&create_v2_request(
            0xd2, epoch,
        ))])
        .await
        .expect("an all-conflict remote batch is resolved without infrastructure");
    assert!(matches!(
        inert_remote_outcomes.as_slice(),
        [Err(StoreError::FencedTransitionRequestConflict)]
    ));
    assert_eq!(inert_remote_provider.calls(), 0);
    assert!(inert_remote_spy.v2_executed().is_empty());

    let local_spy = Arc::new(AtomicSpy::new());
    local_spy.enable_v2();
    let local_fixture = JournalFixture::new(0xd3);
    let local_journal = local_fixture.open_v2();
    let local_provider = CountingKeyProvider::with_key("local-v2-batch-conflict", 0xd3);
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&local_journal))
    .with_fenced_transition_v2_journal_scope(local_fixture.v2_scope());
    let local_seed = create_v2_request(0xd3, epoch);
    local
        .fenced_transition_v2(local_seed.clone())
        .await
        .expect("seed local journal mapping");
    local_spy.clear_v2_receipt();
    let local_missing_conflict = conflicting_v2_request(&create_v2_request(0xd4, epoch));
    let local_valid = create_v2_request(0xd5, epoch);
    let local_existing_conflict = conflicting_v2_body_request(
        &local_seed,
        &create_v2_request_with_payload(0xd6, epoch, b"substituted-local-body"),
    );
    let local_outcomes = local
        .fenced_transition_v2_batch(vec![
            local_missing_conflict.clone(),
            local_valid.clone(),
            local_existing_conflict,
        ])
        .await
        .expect("mixed local batch");
    assert!(matches!(
        local_outcomes.as_slice(),
        [
            Err(StoreError::FencedTransitionRequestConflict),
            Ok(_),
            Err(StoreError::FencedTransitionRequestConflict)
        ]
    ));
    assert_eq!(
        local_provider.calls(),
        2,
        "only the seed and valid slot seal"
    );
    assert_eq!(local_spy.v2_executed().len(), 2);
    let local_scope = protected_v2_journal_scope_for(
        local_spy.as_ref(),
        local_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
    );
    assert!(local_journal
        .lookup(local_scope, local_missing_conflict.request_id())
        .await
        .expect("local conflict lookup")
        .is_none());
    assert!(local_journal
        .lookup(local_scope, local_seed.request_id())
        .await
        .expect("local seed lookup")
        .is_some());
    assert!(local_journal
        .lookup(local_scope, local_valid.request_id())
        .await
        .expect("local valid lookup")
        .is_some());

    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.enable_v2();
    let remote_fixture = JournalFixture::new(0xd7);
    let remote_journal = remote_fixture.open_v2();
    let remote_provider = CountingRemoteProvider::with_key("remote-v2-batch-conflict", 0xd7);
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&remote_journal))
    .with_fenced_transition_v2_journal_scope(remote_fixture.v2_scope());
    let remote_seed = create_v2_request(0xd7, epoch);
    remote
        .fenced_transition_v2(remote_seed.clone())
        .await
        .expect("seed remote journal mapping");
    remote_spy.clear_v2_receipt();
    let remote_missing_conflict = conflicting_v2_request(&create_v2_request(0xd8, epoch));
    let remote_valid = create_v2_request(0xd9, epoch);
    let remote_existing_conflict = conflicting_v2_body_request(
        &remote_seed,
        &create_v2_request_with_payload(0xda, epoch, b"substituted-remote-body"),
    );
    let remote_outcomes = remote
        .fenced_transition_v2_batch(vec![
            remote_missing_conflict.clone(),
            remote_valid.clone(),
            remote_existing_conflict,
        ])
        .await
        .expect("mixed remote batch");
    assert!(matches!(
        remote_outcomes.as_slice(),
        [
            Err(StoreError::FencedTransitionRequestConflict),
            Ok(_),
            Err(StoreError::FencedTransitionRequestConflict)
        ]
    ));
    assert_eq!(
        remote_provider.calls(),
        2,
        "only the seed and valid slot seal"
    );
    assert_eq!(remote_spy.v2_executed().len(), 2);
    let remote_scope = protected_v2_journal_scope_for(
        remote_spy.as_ref(),
        remote_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::RemoteSeal,
    );
    assert!(remote_journal
        .lookup(remote_scope, remote_missing_conflict.request_id())
        .await
        .expect("remote conflict lookup")
        .is_none());
    assert!(remote_journal
        .lookup(remote_scope, remote_seed.request_id())
        .await
        .expect("remote seed lookup")
        .is_some());
    assert!(remote_journal
        .lookup(remote_scope, remote_valid.request_id())
        .await
        .expect("remote valid lookup")
        .is_some());
}

#[tokio::test]
async fn protected_v2_proven_not_transmitted_and_preproposal_rejection_recover_capacity() {
    let epoch = initial_v2_epoch();

    let local_spy = Arc::new(AtomicSpy::new());
    local_spy.enable_v2();
    local_spy.reject_v2_preproposal_once();
    let local_fixture = JournalFixture::new(0xa1);
    let local_journal = local_fixture.open_v2();
    let local_provider = CountingKeyProvider::with_key("local-v2-not-transmitted", 0xa1);
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&local_journal))
    .with_fenced_transition_v2_journal_scope(local_fixture.v2_scope());
    let local_request = create_v2_request(0x71, epoch);
    assert!(matches!(
        local.fenced_transition_v2(local_request.clone()).await,
        Err(StoreError::PayloadTooLarge { actual: 2, max: 1 })
    ));
    let local_scope = protected_v2_journal_scope_for(
        local_spy.as_ref(),
        local_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
    );
    assert!(local_journal
        .lookup(local_scope, local_request.request_id())
        .await
        .expect("local not-transmitted journal lookup")
        .is_none());
    assert!(local
        .fenced_transition_v2(local_request.clone())
        .await
        .is_ok());
    assert_eq!(
        local_provider.calls(),
        2,
        "retry reseals only after cleanup"
    );

    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.enable_v2();
    remote_spy.not_transmit_v2_once();
    let remote_fixture = JournalFixture::new(0xa2);
    let remote_journal = remote_fixture.open_v2();
    let remote_provider = CountingRemoteProvider::with_key("remote-v2-not-transmitted", 0xa2);
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&remote_journal))
    .with_fenced_transition_v2_journal_scope(remote_fixture.v2_scope());
    let remote_request = create_v2_request(0x72, epoch);
    assert!(matches!(
        remote.fenced_transition_v2(remote_request.clone()).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    let remote_scope = protected_v2_journal_scope_for(
        remote_spy.as_ref(),
        remote_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::RemoteSeal,
    );
    assert!(remote_journal
        .lookup(remote_scope, remote_request.request_id())
        .await
        .expect("remote not-transmitted journal lookup")
        .is_none());
    assert!(remote
        .fenced_transition_v2(remote_request.clone())
        .await
        .is_ok());
    assert_eq!(
        remote_provider.calls(),
        2,
        "retry reseals only after cleanup"
    );

    let local_batch_spy = Arc::new(AtomicSpy::new());
    local_batch_spy.enable_v2();
    local_batch_spy.not_transmit_v2_once();
    let local_batch_fixture = JournalFixture::new(0xa3);
    let local_batch_journal = local_batch_fixture.open_v2();
    let local_batch_provider =
        CountingKeyProvider::with_key("local-v2-batch-not-transmitted", 0xa3);
    let local_batch_backend = EncryptingSessionBackend::new(
        Arc::clone(&local_batch_spy),
        Arc::clone(&local_batch_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&local_batch_journal))
    .with_fenced_transition_v2_journal_scope(local_batch_fixture.v2_scope());
    let local_batch = vec![
        create_v2_request(0x73, epoch),
        create_v2_request(0x74, epoch),
    ];
    assert!(matches!(
        local_batch_backend
            .fenced_transition_v2_batch(local_batch.clone())
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    let local_batch_scope = protected_v2_journal_scope_for(
        local_batch_spy.as_ref(),
        local_batch_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
    );
    for request in &local_batch {
        assert!(local_batch_journal
            .lookup(local_batch_scope, request.request_id())
            .await
            .expect("local batch not-transmitted journal lookup")
            .is_none());
    }
    assert!(local_batch_backend
        .fenced_transition_v2_batch(local_batch)
        .await
        .is_ok());
    assert_eq!(
        local_batch_provider.calls(),
        4,
        "batch retry reseals every conditionally removed mapping"
    );

    let remote_batch_spy = Arc::new(AtomicSpy::new());
    remote_batch_spy.enable_v2();
    remote_batch_spy.reject_v2_preproposal_once();
    let remote_batch_fixture = JournalFixture::new(0xa4);
    let remote_batch_journal = remote_batch_fixture.open_v2();
    let remote_batch_provider =
        CountingRemoteProvider::with_key("remote-v2-batch-not-transmitted", 0xa4);
    let remote_batch_backend = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_batch_spy),
        Arc::clone(&remote_batch_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&remote_batch_journal))
    .with_fenced_transition_v2_journal_scope(remote_batch_fixture.v2_scope());
    let remote_batch = vec![
        create_v2_request(0x75, epoch),
        create_v2_request(0x76, epoch),
    ];
    assert!(matches!(
        remote_batch_backend
            .fenced_transition_v2_batch(remote_batch.clone())
            .await,
        Err(StoreError::PayloadTooLarge { actual: 2, max: 1 })
    ));
    let remote_batch_scope = protected_v2_journal_scope_for(
        remote_batch_spy.as_ref(),
        remote_batch_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::RemoteSeal,
    );
    for request in &remote_batch {
        assert!(remote_batch_journal
            .lookup(remote_batch_scope, request.request_id())
            .await
            .expect("remote batch not-transmitted journal lookup")
            .is_none());
    }
    assert!(remote_batch_backend
        .fenced_transition_v2_batch(remote_batch)
        .await
        .is_ok());
    assert_eq!(
        remote_batch_provider.calls(),
        4,
        "batch retry reseals every conditionally removed mapping"
    );
}

#[tokio::test]
async fn protected_v2_not_transmitted_cleanup_cannot_remove_a_same_id_retry_mapping() {
    let epoch = initial_v2_epoch();
    let spy = Arc::new(AtomicSpy::new());
    spy.enable_v2();
    let (entered, release) = spy.block_next_v2_not_transmitted();
    let fixture = JournalFixture::new(0xa5);
    let journal = fixture.open_v2();
    let provider = CountingKeyProvider::with_key("local-v2-same-id-cleanup", 0xa5);
    let backend = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
        .with_fenced_transition_v2_journal(Arc::clone(&journal))
        .with_fenced_transition_v2_journal_scope(fixture.v2_scope());
    let request = create_v2_request(0x77, epoch);

    let entered_wait = entered.notified();
    let first_backend = backend.clone();
    let first_request = request.clone();
    let first =
        tokio::spawn(async move { first_backend.fenced_transition_v2(first_request).await });
    entered_wait.await;

    let mut second = Box::pin(backend.fenced_transition_v2(request.clone()));
    assert!(matches!(
        futures_util::poll!(&mut second),
        std::task::Poll::Pending
    ));
    release.notify_one();

    assert!(matches!(
        first.await.expect("first same-ID task joins"),
        Err(StoreError::BackendUnavailable(_))
    ));
    assert!(second.await.is_ok());
    assert_eq!(provider.calls(), 2, "the retry binds after exact cleanup");
    let scope = protected_v2_journal_scope_for(
        spy.as_ref(),
        fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
    );
    assert!(journal
        .lookup(scope, request.request_id())
        .await
        .expect("same-ID journal lookup")
        .is_some());
    assert_eq!(spy.v2_executed().len(), 1);
}

#[tokio::test]
async fn protected_v2_cancellation_retains_a_recoverable_mapping_without_background_work() {
    let epoch = initial_v2_epoch();
    let spy = Arc::new(AtomicSpy::new());
    spy.enable_v2();
    let (entered, _release) = spy.block_next_v2_not_transmitted();
    let fixture = JournalFixture::new(0xa6);
    let journal = fixture.open_v2();
    let provider = CountingKeyProvider::with_key("local-v2-cancellation", 0xa6);
    let backend = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
        .with_fenced_transition_v2_journal(Arc::clone(&journal))
        .with_fenced_transition_v2_journal_scope(fixture.v2_scope());
    let request = create_v2_request(0x78, epoch);

    let entered_wait = entered.notified();
    let cancelled_backend = backend.clone();
    let cancelled_request = request.clone();
    let cancelled = tokio::spawn(async move {
        cancelled_backend
            .fenced_transition_v2(cancelled_request)
            .await
    });
    entered_wait.await;
    cancelled.abort();
    assert!(cancelled
        .await
        .expect_err("cancelled task must not join")
        .is_cancelled());

    let scope = protected_v2_journal_scope_for(
        spy.as_ref(),
        fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
    );
    assert!(journal
        .lookup(scope, request.request_id())
        .await
        .expect("cancelled journal lookup")
        .is_some());
    assert!(backend.fenced_transition_v2(request).await.is_ok());
    assert_eq!(
        provider.calls(),
        1,
        "retry reuses the retained sealed mapping"
    );
}

async fn abort_v2_cleanup_while_final_poll_is_committed<T>(
    mut gate: crate::fenced_transition_journal::V2RemoveIfExactAfterCommitGate,
    task: tokio::task::JoinHandle<T>,
) -> T
where
    T: Send + 'static,
{
    gate.wait_until_committed().await;
    task.abort();
    gate.release();
    task.await
        .expect("no-yield cleanup finalization must complete before cancellation")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_v2_local_not_transmitted_cleanup_finalizes_without_a_cancellation_gap() {
    let epoch = initial_v2_epoch();
    let singleton_spy = Arc::new(AtomicSpy::new());
    singleton_spy.enable_v2();
    singleton_spy.not_transmit_v2_once();
    let singleton_fixture = JournalFixture::new(0xab);
    let singleton_journal = singleton_fixture.open_v2();
    let singleton_provider = CountingKeyProvider::with_key("local-v2-final-singleton", 0xab);
    let singleton_backend = EncryptingSessionBackend::new(
        Arc::clone(&singleton_spy),
        Arc::clone(&singleton_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&singleton_journal))
    .with_fenced_transition_v2_journal_scope(singleton_fixture.v2_scope());
    let singleton_request = create_v2_request(0x79, epoch);
    let gate = crate::fenced_transition_journal::block_next_v2_remove_if_exact_after_commit(
        singleton_journal.as_ref(),
    );
    let task_backend = singleton_backend.clone();
    let task_request = singleton_request.clone();
    let singleton_result = abort_v2_cleanup_while_final_poll_is_committed(
        gate,
        tokio::spawn(async move { task_backend.fenced_transition_v2(task_request).await }),
    )
    .await;
    assert!(matches!(
        singleton_result,
        Err(StoreError::BackendUnavailable(_))
    ));
    let singleton_scope = protected_v2_journal_scope_for(
        singleton_spy.as_ref(),
        singleton_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
    );
    assert!(singleton_journal
        .lookup(singleton_scope, singleton_request.request_id())
        .await
        .expect("completed singleton cleanup lookup")
        .is_none());
    assert!(singleton_backend
        .fenced_transition_v2(singleton_request)
        .await
        .is_ok());
    assert_eq!(singleton_provider.calls(), 2);

    let batch_spy = Arc::new(AtomicSpy::new());
    batch_spy.enable_v2();
    batch_spy.not_transmit_v2_once();
    let batch_fixture = JournalFixture::new(0xac);
    let batch_journal = batch_fixture.open_v2();
    let batch_provider = CountingKeyProvider::with_key("local-v2-final-batch", 0xac);
    let batch_backend = EncryptingSessionBackend::new(
        Arc::clone(&batch_spy),
        Arc::clone(&batch_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&batch_journal))
    .with_fenced_transition_v2_journal_scope(batch_fixture.v2_scope());
    let batch_requests = vec![
        create_v2_request(0x7a, epoch),
        create_v2_request(0x7b, epoch),
    ];
    let gate = crate::fenced_transition_journal::block_next_v2_remove_if_exact_after_commit(
        batch_journal.as_ref(),
    );
    let task_backend = batch_backend.clone();
    let task_requests = batch_requests.clone();
    let batch_result = abort_v2_cleanup_while_final_poll_is_committed(
        gate,
        tokio::spawn(async move { task_backend.fenced_transition_v2_batch(task_requests).await }),
    )
    .await;
    assert!(matches!(
        batch_result,
        Err(StoreError::BackendUnavailable(_))
    ));
    let batch_scope = protected_v2_journal_scope_for(
        batch_spy.as_ref(),
        batch_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
    );
    for request in &batch_requests {
        assert!(batch_journal
            .lookup(batch_scope, request.request_id())
            .await
            .expect("completed batch cleanup lookup")
            .is_none());
    }
    assert!(batch_backend
        .fenced_transition_v2_batch(batch_requests)
        .await
        .is_ok());
    assert_eq!(batch_provider.calls(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_v2_remote_not_transmitted_cleanup_finalizes_without_a_cancellation_gap() {
    let epoch = initial_v2_epoch();
    let singleton_spy = Arc::new(AtomicSpy::new());
    singleton_spy.enable_v2();
    singleton_spy.not_transmit_v2_once();
    let singleton_fixture = JournalFixture::new(0xad);
    let singleton_journal = singleton_fixture.open_v2();
    let singleton_provider = CountingRemoteProvider::with_key("remote-v2-final-singleton", 0xad);
    let singleton_backend = RemoteSealingSessionBackend::new(
        Arc::clone(&singleton_spy),
        Arc::clone(&singleton_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&singleton_journal))
    .with_fenced_transition_v2_journal_scope(singleton_fixture.v2_scope());
    let singleton_request = create_v2_request(0x7c, epoch);
    let gate = crate::fenced_transition_journal::block_next_v2_remove_if_exact_after_commit(
        singleton_journal.as_ref(),
    );
    let task_backend = singleton_backend.clone();
    let task_request = singleton_request.clone();
    let singleton_result = abort_v2_cleanup_while_final_poll_is_committed(
        gate,
        tokio::spawn(async move { task_backend.fenced_transition_v2(task_request).await }),
    )
    .await;
    assert!(matches!(
        singleton_result,
        Err(StoreError::BackendUnavailable(_))
    ));
    let singleton_scope = protected_v2_journal_scope_for(
        singleton_spy.as_ref(),
        singleton_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::RemoteSeal,
    );
    assert!(singleton_journal
        .lookup(singleton_scope, singleton_request.request_id())
        .await
        .expect("completed singleton cleanup lookup")
        .is_none());
    assert!(singleton_backend
        .fenced_transition_v2(singleton_request)
        .await
        .is_ok());
    assert_eq!(singleton_provider.calls(), 2);

    let batch_spy = Arc::new(AtomicSpy::new());
    batch_spy.enable_v2();
    batch_spy.not_transmit_v2_once();
    let batch_fixture = JournalFixture::new(0xae);
    let batch_journal = batch_fixture.open_v2();
    let batch_provider = CountingRemoteProvider::with_key("remote-v2-final-batch", 0xae);
    let batch_backend = RemoteSealingSessionBackend::new(
        Arc::clone(&batch_spy),
        Arc::clone(&batch_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&batch_journal))
    .with_fenced_transition_v2_journal_scope(batch_fixture.v2_scope());
    let batch_requests = vec![
        create_v2_request(0x7d, epoch),
        create_v2_request(0x7e, epoch),
    ];
    let gate = crate::fenced_transition_journal::block_next_v2_remove_if_exact_after_commit(
        batch_journal.as_ref(),
    );
    let task_backend = batch_backend.clone();
    let task_requests = batch_requests.clone();
    let batch_result = abort_v2_cleanup_while_final_poll_is_committed(
        gate,
        tokio::spawn(async move { task_backend.fenced_transition_v2_batch(task_requests).await }),
    )
    .await;
    assert!(matches!(
        batch_result,
        Err(StoreError::BackendUnavailable(_))
    ));
    let batch_scope = protected_v2_journal_scope_for(
        batch_spy.as_ref(),
        batch_fixture.v2_scope(),
        NAMESPACE,
        crate::backend::ProtectedFencedTransitionV2JournalMode::RemoteSeal,
    );
    for request in &batch_requests {
        assert!(batch_journal
            .lookup(batch_scope, request.request_id())
            .await
            .expect("completed batch cleanup lookup")
            .is_none());
    }
    assert!(batch_backend
        .fenced_transition_v2_batch(batch_requests)
        .await
        .is_ok());
    assert_eq!(batch_provider.calls(), 4);
}

#[tokio::test]
async fn protected_wrappers_preserve_v2_exact_replay_across_successor_restart_and_key_rotation() {
    let epoch = initial_v2_epoch();

    let local_spy = Arc::new(AtomicSpy::new());
    local_spy.enable_v2();
    local_spy.delay_v2_ambiguous_commit();
    let local_fixture = JournalFixture::new(0xb1);
    let local_request = create_v2_request(0x31, epoch);
    let local_first_provider = CountingKeyProvider::with_key("local-v2-before-rotation", 0x31);
    let local_first = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_first_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(local_fixture.open_v2())
    .with_fenced_transition_v2_journal_scope(local_fixture.v2_scope());
    assert_eq!(
        local_first
            .fenced_transition_v2_capability()
            .await
            .expect("local V2 capability"),
        Some(FencedTransitionV2Capability::V2)
    );
    assert!(matches!(
        local_first
            .fenced_transition_v2(local_request.clone())
            .await,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    ));
    assert_eq!(local_first_provider.calls(), 1);
    drop(local_first);

    local_spy.commit_v2_delayed();
    local_spy.set_v2_history(
        FencedTransitionV2HistoryState::new(
            Some(FencedTransitionV2HistoryEpoch::new(2).expect("successor epoch")),
            None,
            None,
            0,
            2,
            0,
            0,
        )
        .expect("successor keeps epoch one replayable"),
    );
    let local_rotated_provider = CountingKeyProvider::with_key("local-v2-after-rotation", 0x32);
    let local_reopened = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_rotated_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(local_fixture.open_v2())
    .with_fenced_transition_v2_journal_scope(local_fixture.v2_scope());
    assert!(local_reopened
        .fenced_transition_v2(local_request.clone())
        .await
        .is_ok());
    assert_eq!(
        local_rotated_provider.calls(),
        0,
        "restart recovery reuses the sealed physical V2 request"
    );
    let local_physical = local_spy.v2_executed();
    assert_eq!(local_physical.len(), 2);
    assert!(local_physical[0].matches(&local_physical[1]));
    assert_eq!(
        serde_json::to_vec(&local_physical[0]).expect("serialize first local sealed V2 request"),
        serde_json::to_vec(&local_physical[1]).expect("serialize replayed local sealed V2 request"),
        "rotation retry preserves the exact sealed bytes"
    );
    assert_ne!(local_physical[0].request_id(), local_request.request_id());
    assert_eq!(
        local_reopened
            .fenced_transition_v2_status(&conflicting_v2_request(&local_request))
            .await
            .expect("local conflicting V2 status"),
        FencedTransitionV2Status::RequestConflict
    );
    assert_eq!(local_rotated_provider.calls(), 0);

    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.enable_v2();
    remote_spy.delay_v2_ambiguous_commit();
    let remote_fixture = JournalFixture::new(0xb2);
    let remote_request = create_v2_request(0x32, epoch);
    let remote_first_provider = CountingRemoteProvider::with_key("remote-v2-before-rotation", 0x41);
    let remote_first = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_first_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(remote_fixture.open_v2())
    .with_fenced_transition_v2_journal_scope(remote_fixture.v2_scope());
    assert_eq!(
        remote_first
            .fenced_transition_v2_capability()
            .await
            .expect("remote V2 capability"),
        Some(FencedTransitionV2Capability::V2)
    );
    assert!(matches!(
        remote_first
            .fenced_transition_v2(remote_request.clone())
            .await,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    ));
    assert_eq!(remote_first_provider.calls(), 1);
    drop(remote_first);

    remote_spy.commit_v2_delayed();
    remote_spy.set_v2_history(
        FencedTransitionV2HistoryState::new(
            Some(FencedTransitionV2HistoryEpoch::new(2).expect("successor epoch")),
            None,
            None,
            0,
            2,
            0,
            0,
        )
        .expect("successor keeps epoch one replayable"),
    );
    let remote_rotated_provider =
        CountingRemoteProvider::with_key("remote-v2-after-rotation", 0x42);
    let remote_reopened = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_rotated_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(remote_fixture.open_v2())
    .with_fenced_transition_v2_journal_scope(remote_fixture.v2_scope());
    assert!(remote_reopened
        .fenced_transition_v2(remote_request.clone())
        .await
        .is_ok());
    assert_eq!(
        remote_rotated_provider.calls(),
        0,
        "restart recovery reuses the remotely sealed physical V2 request"
    );
    let remote_physical = remote_spy.v2_executed();
    assert_eq!(remote_physical.len(), 2);
    assert!(remote_physical[0].matches(&remote_physical[1]));
    assert_eq!(
        serde_json::to_vec(&remote_physical[0]).expect("serialize first remote sealed V2 request"),
        serde_json::to_vec(&remote_physical[1])
            .expect("serialize replayed remote sealed V2 request"),
        "rotation retry preserves the exact sealed bytes"
    );
    assert_ne!(remote_physical[0].request_id(), remote_request.request_id());
    assert_eq!(
        remote_reopened
            .fenced_transition_v2_status(&conflicting_v2_request(&remote_request))
            .await
            .expect("remote conflicting V2 status"),
        FencedTransitionV2Status::RequestConflict
    );
    assert_eq!(remote_rotated_provider.calls(), 0);
}

#[tokio::test]
async fn protected_wrappers_reclaim_v2_mappings_only_after_consensus_retires_the_epoch() {
    let epoch = initial_v2_epoch();
    let retired = FencedTransitionV2HistoryState::new(
        Some(FencedTransitionV2HistoryEpoch::new(2).expect("successor epoch")),
        Some(epoch),
        Some(epoch),
        1,
        2,
        0,
        0,
    )
    .expect("retired V2 history");

    let local_spy = Arc::new(AtomicSpy::new());
    local_spy.enable_v2();
    local_spy.delay_v2_ambiguous_commit();
    let local_fixture = JournalFixture::new(0xb3);
    let local_journal = local_fixture.open_v2();
    let local_provider = CountingKeyProvider::with_key("local-v2-retire", 0x51);
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&local_journal))
    .with_fenced_transition_v2_journal_scope(local_fixture.v2_scope());
    let local_request = create_v2_request(0x33, epoch);
    assert!(matches!(
        local.fenced_transition_v2(local_request.clone()).await,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    ));
    assert!(local_journal
        .lookup(
            protected_v2_journal_scope_for(
                local_spy.as_ref(),
                local_fixture.v2_scope(),
                NAMESPACE,
                crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
            ),
            local_request.request_id(),
        )
        .await
        .expect("local V2 journal lookup before retirement")
        .is_some());
    local_spy.set_v2_history(retired);
    assert_eq!(
        local
            .fenced_transition_v2_status(&local_request)
            .await
            .expect("local retired V2 status"),
        FencedTransitionV2Status::Retired
    );
    assert!(local_journal
        .lookup(
            protected_v2_journal_scope_for(
                local_spy.as_ref(),
                local_fixture.v2_scope(),
                NAMESPACE,
                crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
            ),
            local_request.request_id(),
        )
        .await
        .expect("local V2 journal lookup after retirement")
        .is_none());
    assert!(matches!(
        local.fenced_transition_v2(local_request).await,
        Err(StoreError::FencedTransitionHistoryEpochRetired)
    ));
    assert_eq!(local_provider.calls(), 1);
    assert_eq!(local_spy.v2_executed().len(), 1);

    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.enable_v2();
    remote_spy.delay_v2_ambiguous_commit();
    let remote_fixture = JournalFixture::new(0xb4);
    let remote_journal = remote_fixture.open_v2();
    let remote_provider = CountingRemoteProvider::with_key("remote-v2-retire", 0x61);
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&remote_journal))
    .with_fenced_transition_v2_journal_scope(remote_fixture.v2_scope());
    let remote_request = create_v2_request(0x34, epoch);
    assert!(matches!(
        remote.fenced_transition_v2(remote_request.clone()).await,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    ));
    assert!(remote_journal
        .lookup(
            protected_v2_journal_scope_for(
                remote_spy.as_ref(),
                remote_fixture.v2_scope(),
                NAMESPACE,
                crate::backend::ProtectedFencedTransitionV2JournalMode::RemoteSeal,
            ),
            remote_request.request_id(),
        )
        .await
        .expect("remote V2 journal lookup before retirement")
        .is_some());
    remote_spy.set_v2_history(retired);
    assert_eq!(
        remote
            .fenced_transition_v2_status(&remote_request)
            .await
            .expect("remote retired V2 status"),
        FencedTransitionV2Status::Retired
    );
    assert!(remote_journal
        .lookup(
            protected_v2_journal_scope_for(
                remote_spy.as_ref(),
                remote_fixture.v2_scope(),
                NAMESPACE,
                crate::backend::ProtectedFencedTransitionV2JournalMode::RemoteSeal,
            ),
            remote_request.request_id(),
        )
        .await
        .expect("remote V2 journal lookup after retirement")
        .is_none());
    assert!(matches!(
        remote.fenced_transition_v2(remote_request).await,
        Err(StoreError::FencedTransitionHistoryEpochRetired)
    ));
    assert_eq!(remote_provider.calls(), 1);
    assert_eq!(remote_spy.v2_executed().len(), 1);
}

#[tokio::test]
async fn protected_v2_journal_rejects_mixed_formats_and_corrupted_bindings() {
    let legacy_fixture = JournalFixture::new(0xb5);
    drop(legacy_fixture.open());
    assert!(FencedTransitionV2PreparedJournal::open_existing(
        &legacy_fixture.path,
        FencedTransitionV2PreparedJournalKey::from_bytes(legacy_fixture.key),
    )
    .is_err());

    let v2_fixture = JournalFixture::new(0xb6);
    drop(v2_fixture.open_v2());
    assert!(PreparedFencedTransitionJournal::open_existing(
        &v2_fixture.v2_path,
        PreparedFencedTransitionJournalKey::from_bytes(v2_fixture.key),
    )
    .is_err());

    let wrong_key_fixture = JournalFixture::new(0xbe);
    drop(wrong_key_fixture.open_v2());
    assert!(FencedTransitionV2PreparedJournal::open_existing(
        &wrong_key_fixture.v2_path,
        FencedTransitionV2PreparedJournalKey::from_bytes([0xbf; 32]),
    )
    .is_err());

    let spy = Arc::new(AtomicSpy::new());
    spy.enable_v2();
    let fixture = JournalFixture::new(0xb7);
    let request = create_v2_request(0x35, initial_v2_epoch());
    let initial_provider = CountingKeyProvider::with_key("local-v2-corruption", 0x71);
    let wrapper =
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&initial_provider), NAMESPACE)
            .with_fenced_transition_v2_journal(fixture.open_v2())
            .with_fenced_transition_v2_journal_scope(fixture.v2_scope());
    assert!(wrapper.fenced_transition_v2(request.clone()).await.is_ok());
    drop(wrapper);

    let connection = rusqlite::Connection::open(&fixture.v2_path)
        .expect("open V2 journal fixture for corruption");
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .expect("enable V2 corruption fixture");
    assert_eq!(
        connection
            .execute(
                "UPDATE protected_fenced_transition_v2_journal \
                 SET prepared_request = zeroblob(1)",
                [],
            )
            .expect("corrupt V2 prepared request"),
        1
    );
    drop(connection);

    let reopened_provider = CountingKeyProvider::with_key("local-v2-after-corruption", 0x72);
    let reopened =
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&reopened_provider), NAMESPACE)
            .with_fenced_transition_v2_journal(fixture.open_v2())
            .with_fenced_transition_v2_journal_scope(fixture.v2_scope());
    assert!(matches!(
        reopened.fenced_transition_v2_status(&request).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(reopened_provider.calls(), 0);
}

#[tokio::test]
async fn protected_v2_scope_mismatch_stops_before_provider_or_inner() {
    let epoch = initial_v2_epoch();
    let request = create_v2_request(0x36, epoch);
    let fixture = JournalFixture::new(0xb8);
    let journal = fixture.open_v2();
    let scope = fixture.v2_scope();
    let spy = Arc::new(AtomicSpy::new());
    spy.enable_v2();

    let initial_provider = CountingKeyProvider::with_key("v2-scope-initial", 0x81);
    let initial =
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&initial_provider), NAMESPACE)
            .with_fenced_transition_v2_journal(Arc::clone(&journal))
            .with_fenced_transition_v2_journal_scope(scope);
    assert!(initial.fenced_transition_v2(request.clone()).await.is_ok());
    assert_eq!(initial_provider.calls(), 1);
    let dispatched = spy.v2_executed().len();
    drop(initial);

    let wrong_namespace_provider = CountingKeyProvider::with_key("v2-scope-namespace", 0x82);
    let wrong_namespace = EncryptingSessionBackend::new(
        Arc::clone(&spy),
        Arc::clone(&wrong_namespace_provider),
        "protected-fenced-transition-other",
    )
    .with_fenced_transition_v2_journal(Arc::clone(&journal))
    .with_fenced_transition_v2_journal_scope(scope);
    assert!(matches!(
        wrong_namespace.fenced_transition_v2(request.clone()).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(wrong_namespace_provider.calls(), 0);
    assert_eq!(spy.v2_executed().len(), dispatched);

    let remote_provider = CountingRemoteProvider::with_key("v2-scope-remote", 0x83);
    let wrong_mode =
        RemoteSealingSessionBackend::new(Arc::clone(&spy), Arc::clone(&remote_provider), NAMESPACE)
            .with_fenced_transition_v2_journal(Arc::clone(&journal))
            .with_fenced_transition_v2_journal_scope(scope);
    assert!(matches!(
        wrong_mode.fenced_transition_v2(request.clone()).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(remote_provider.calls(), 0);
    assert_eq!(spy.v2_executed().len(), dispatched);

    let wrong_cluster_provider = CountingKeyProvider::with_key("v2-scope-cluster", 0x84);
    let wrong_cluster = EncryptingSessionBackend::new(
        Arc::clone(&spy),
        Arc::clone(&wrong_cluster_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&journal))
    .with_fenced_transition_v2_journal_scope(FencedTransitionV2JournalScope::from_bytes(
        [0xc8; 32],
    ));
    assert!(matches!(
        wrong_cluster.fenced_transition_v2(request.clone()).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(wrong_cluster_provider.calls(), 0);
    assert_eq!(spy.v2_executed().len(), dispatched);

    assert!(matches!(
        journal
            .lookup(
                protected_v2_journal_scope_for(
                    spy.as_ref(),
                    FencedTransitionV2JournalScope::from_bytes([0xc8; 32]),
                    NAMESPACE,
                    crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
                ),
                request.request_id(),
            )
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));
}

fn corrupt_v2_index_root(path: &std::path::Path, index_name: &str) {
    let connection = rusqlite::Connection::open(path).expect("open V2 index-corruption fixture");
    connection
        .execute_batch("PRAGMA writable_schema = ON;")
        .expect("enable V2 index corruption fixture");
    assert_eq!(
        connection
            .execute(
                "UPDATE sqlite_schema SET rootpage = 0 WHERE name = ?1",
                [index_name],
            )
            .expect("corrupt V2 index root"),
        1
    );
    connection
        .execute_batch("PRAGMA writable_schema = OFF;")
        .expect("finish V2 index corruption fixture");
}

fn remove_v2_index(path: &std::path::Path, index_name: &str) {
    let connection = rusqlite::Connection::open(path).expect("open V2 index-removal fixture");
    connection
        .execute(&format!("DROP INDEX {index_name}"), [])
        .expect("remove V2 index");
}

#[tokio::test]
async fn protected_v2_primary_index_corruption_fails_closed_on_direct_journal_reopen() {
    let fixture = JournalFixture::new(0xb9);
    let scope = fixture.v2_scope();
    let journal = fixture.open_v2();
    let spy = Arc::new(AtomicSpy::new());
    spy.enable_v2();
    let request = create_v2_request(0x37, initial_v2_epoch());
    let provider = CountingKeyProvider::with_key("v2-primary-index", 0x85);
    let wrapper = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
        .with_fenced_transition_v2_journal(Arc::clone(&journal))
        .with_fenced_transition_v2_journal_scope(scope);
    assert!(wrapper.fenced_transition_v2(request.clone()).await.is_ok());
    drop(wrapper);
    drop(journal);
    corrupt_v2_index_root(
        &fixture.v2_path,
        "sqlite_autoindex_protected_fenced_transition_v2_journal_1",
    );
    assert!(FencedTransitionV2PreparedJournal::open_existing(
        &fixture.v2_path,
        FencedTransitionV2PreparedJournalKey::from_bytes(fixture.key),
    )
    .is_err());
}

#[tokio::test]
async fn protected_v2_index_divergence_fails_closed_before_reseal_or_dispatch() {
    let epoch = initial_v2_epoch();

    let local_fixture = JournalFixture::new(0xb9);
    let local_scope = local_fixture.v2_scope();
    let local_journal = local_fixture.open_v2();
    let local_spy = Arc::new(AtomicSpy::new());
    local_spy.enable_v2();
    let local_request = create_v2_request(0x37, epoch);
    let local_initial_provider = CountingKeyProvider::with_key("v2-index-local", 0x85);
    let local_initial = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_initial_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&local_journal))
    .with_fenced_transition_v2_journal_scope(local_scope);
    assert!(local_initial
        .fenced_transition_v2(local_request.clone())
        .await
        .is_ok());
    drop(local_initial);
    let local_dispatched = local_spy.v2_executed().len();
    remove_v2_index(
        &local_fixture.v2_path,
        "protected_fenced_transition_v2_journal_membership_idx",
    );
    assert!(matches!(
        local_journal
            .lookup(
                protected_v2_journal_scope_for(
                    local_spy.as_ref(),
                    local_scope,
                    NAMESPACE,
                    crate::backend::ProtectedFencedTransitionV2JournalMode::LocalAead,
                ),
                local_request.request_id(),
            )
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    let local_retry_provider = CountingKeyProvider::with_key("v2-index-local-retry", 0x86);
    let local_retry = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_retry_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&local_journal))
    .with_fenced_transition_v2_journal_scope(local_scope);
    assert!(matches!(
        local_retry.fenced_transition_v2(local_request).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(local_retry_provider.calls(), 0);
    assert_eq!(local_spy.v2_executed().len(), local_dispatched);

    let remote_fixture = JournalFixture::new(0xba);
    let remote_scope = remote_fixture.v2_scope();
    let remote_journal = remote_fixture.open_v2();
    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.enable_v2();
    let remote_request = create_v2_request(0x38, epoch);
    let remote_initial_provider = CountingRemoteProvider::with_key("v2-index-remote", 0x87);
    let remote_initial = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_initial_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&remote_journal))
    .with_fenced_transition_v2_journal_scope(remote_scope);
    assert!(remote_initial
        .fenced_transition_v2(remote_request.clone())
        .await
        .is_ok());
    drop(remote_initial);
    let remote_dispatched = remote_spy.v2_executed().len();
    remove_v2_index(
        &remote_fixture.v2_path,
        "protected_fenced_transition_v2_journal_epoch_idx",
    );
    assert!(matches!(
        remote_journal
            .lookup(
                protected_v2_journal_scope_for(
                    remote_spy.as_ref(),
                    remote_scope,
                    NAMESPACE,
                    crate::backend::ProtectedFencedTransitionV2JournalMode::RemoteSeal,
                ),
                remote_request.request_id(),
            )
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    let remote_retry_provider = CountingRemoteProvider::with_key("v2-index-remote-retry", 0x88);
    let remote_retry = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_retry_provider),
        NAMESPACE,
    )
    .with_fenced_transition_v2_journal(Arc::clone(&remote_journal))
    .with_fenced_transition_v2_journal_scope(remote_scope);
    assert!(matches!(
        remote_retry.fenced_transition_v2(remote_request).await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(remote_retry_provider.calls(), 0);
    assert_eq!(remote_spy.v2_executed().len(), remote_dispatched);
}

#[tokio::test]
async fn protected_fenced_transition_rejects_nonphysical_inner_token_before_journaling() {
    let local_spy = Arc::new(AtomicSpy::new());
    local_spy.emit_nonphysical_prepared_token();
    let local_journal_fixture = JournalFixture::new(0x8d);
    let local_journal = local_journal_fixture.open();
    let local_inner: Arc<dyn SessionBackend> =
        Arc::new(SessionStore::from_arc(Arc::clone(&local_spy)));
    let local = EncryptingSessionBackend::new(
        local_inner,
        CountingKeyProvider::with_key("local-nonphysical", 0x14),
        NAMESPACE,
    )
    .with_fenced_transition_journal(Arc::clone(&local_journal));
    let local_request = create_request(41);
    assert!(matches!(
        local.prepare_fenced_transition(local_request.clone()).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        local_journal
            .lookup(local_request.request_id())
            .await
            .expect("journal lookup"),
        PreparedFencedTransitionLookup::Absent
    ));

    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.emit_nonphysical_prepared_token();
    let remote_journal_fixture = JournalFixture::new(0x8e);
    let remote_journal = remote_journal_fixture.open();
    let remote_inner: Arc<dyn SessionBackend> =
        Arc::new(SessionStore::from_arc(Arc::clone(&remote_spy)));
    let remote = RemoteSealingSessionBackend::new(
        remote_inner,
        CountingRemoteProvider::with_key("remote-nonphysical", 0x15),
        NAMESPACE,
    )
    .with_fenced_transition_journal(Arc::clone(&remote_journal));
    let remote_request = create_request(42);
    assert!(matches!(
        remote
            .prepare_fenced_transition(remote_request.clone())
            .await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        remote_journal
            .lookup(remote_request.request_id())
            .await
            .expect("journal lookup"),
        PreparedFencedTransitionLookup::Absent
    ));
}

#[tokio::test]
async fn protected_fenced_transition_rejects_oversized_physical_envelopes_before_journaling() {
    let payload = vec![0x91; crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES];

    let local_spy = Arc::new(AtomicSpy::new());
    local_spy.enforce_physical_admission();
    let local_provider = CountingKeyProvider::with_key("local-oversized-physical", 0x19);
    let local_fixture = JournalFixture::new(0x95);
    let local_journal = local_fixture.open();
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(Arc::clone(&local_journal));
    let local_request = create_request_with_payload(0x51, &payload);
    assert!(matches!(
        local.prepare_fenced_transition(local_request.clone()).await,
        Err(StoreError::PayloadTooLarge { .. })
    ));
    assert_eq!(local_provider.calls(), 1);
    assert!(local_spy.prepared().is_empty());
    assert!(local_spy.executed().is_empty());
    assert_eq!(local_spy.dispatches(), 0);
    assert!(matches!(
        local_journal
            .lookup(local_request.request_id())
            .await
            .expect("journal lookup"),
        PreparedFencedTransitionLookup::Absent
    ));

    let remote_spy = Arc::new(AtomicSpy::new());
    remote_spy.enforce_physical_admission();
    let remote_provider = CountingRemoteProvider::with_key("remote-oversized-physical", 0x1a);
    let remote_fixture = JournalFixture::new(0x96);
    let remote_journal = remote_fixture.open();
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(Arc::clone(&remote_journal));
    let remote_request = create_request_with_payload(0x52, &payload);
    assert!(matches!(
        remote
            .prepare_fenced_transition(remote_request.clone())
            .await,
        Err(StoreError::PayloadTooLarge { .. })
    ));
    assert_eq!(remote_provider.calls(), 1);
    assert!(remote_spy.prepared().is_empty());
    assert!(remote_spy.executed().is_empty());
    assert_eq!(remote_spy.dispatches(), 0);
    assert!(matches!(
        remote_journal
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
    drop(local_a_backend);
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
    drop(remote_a_backend);
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
async fn protected_fenced_transition_router_projection_rejects_substituted_journal_token() {
    let spy = Arc::new(AtomicSpy::new());
    let journal = JournalFixture::new(0xc3);
    let wrapper = Arc::new(
        RemoteSealingSessionBackend::new(
            Arc::clone(&spy),
            CountingRemoteProvider::with_key("projection-substitution", 0xc3),
            NAMESPACE,
        )
        .with_fenced_transition_journal(journal.open()),
    );
    let first = wrapper
        .prepare_fenced_transition(create_request(0xc3))
        .await
        .expect("prepare first protected transition");
    let second = wrapper
        .prepare_fenced_transition(create_request(0xc4))
        .await
        .expect("prepare replacement protected transition");
    journal.substitute_prepared_token(first.request_id(), second.request_id());

    assert!(matches!(
        ProtectedSessionBackend::project_fenced_transition_for_authenticated_consumer_router(
            wrapper.as_ref(),
            &first,
        )
        .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(spy.dispatches(), 0);
    assert!(spy.statuses().is_empty());
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
    assert_eq!(
        backend
            .fenced_transition_v2_capability()
            .await
            .expect("V2 capability without a V2 journal"),
        None,
        "the V1 prepared journal must never be reinterpreted as V2 state"
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
async fn protected_fenced_transition_router_projection_rechecks_the_journal_before_dispatch() {
    let local_spy = Arc::new(AtomicSpy::new());
    let local_journal = JournalFixture::new(0xc1);
    let local = Arc::new(
        EncryptingSessionBackend::new(
            Arc::clone(&local_spy),
            CountingKeyProvider::with_key("projection-local", 0xc1),
            NAMESPACE,
        )
        .with_fenced_transition_journal(local_journal.open()),
    );
    let local_prepared = local
        .prepare_fenced_transition(create_request(0xc1))
        .await
        .expect("prepare local protected transition");
    assert!(
        ProtectedSessionBackend::project_fenced_transition_for_authenticated_consumer_router(
            local.as_ref(),
            &local_prepared,
        )
        .await
        .is_ok()
    );
    local_journal.delete_prepared_token();
    assert!(matches!(
        ProtectedSessionBackend::project_fenced_transition_for_authenticated_consumer_router(
            local.as_ref(),
            &local_prepared,
        )
        .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(local_spy.dispatches(), 0);
    assert!(local_spy.statuses().is_empty());

    let remote_spy = Arc::new(AtomicSpy::new());
    let remote_journal = JournalFixture::new(0xc2);
    let remote = Arc::new(
        RemoteSealingSessionBackend::new(
            Arc::clone(&remote_spy),
            CountingRemoteProvider::with_key("projection-remote", 0xc2),
            NAMESPACE,
        )
        .with_fenced_transition_journal(remote_journal.open()),
    );
    let remote_prepared = remote
        .prepare_fenced_transition(create_request(0xc2))
        .await
        .expect("prepare remote protected transition");
    assert!(
        ProtectedSessionBackend::project_fenced_transition_for_authenticated_consumer_router(
            remote.as_ref(),
            &remote_prepared,
        )
        .await
        .is_ok()
    );
    remote_journal.delete_prepared_token();
    assert!(matches!(
        ProtectedSessionBackend::project_fenced_transition_for_authenticated_consumer_router(
            remote.as_ref(),
            &remote_prepared,
        )
        .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(remote_spy.dispatches(), 0);
    assert!(remote_spy.statuses().is_empty());
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
    let local_journal_fixture = JournalFixture::new(0x93);
    let local_journal = local_journal_fixture.open();
    let backend = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
        .with_fenced_transition_journal(Arc::clone(&local_journal));
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
    .with_fenced_transition_journal(Arc::clone(&local_journal));
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
async fn protected_fenced_transition_rejects_nonplaintext_callers_before_effects() {
    let local_spy = Arc::new(AtomicSpy::new());
    let local_provider = CountingKeyProvider::with_key("local-caller-encoding", 0x66);
    let local_journal = JournalFixture::new(0xa3);
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(local_journal.open());
    local
        .prepare_fenced_transition(create_request(60))
        .await
        .expect("prepare plaintext local request");
    let local_envelope = local_spy.prepared()[0]
        .mutation()
        .record()
        .expect("physical record")
        .payload
        .clone();
    let local_capabilities = local_spy.capability_calls();
    let local_preflights = local_spy.preflight_calls();
    for (id, payload) in [
        (61, local_envelope.clone()),
        (62, EncryptedSessionPayload::legacy_plaintext([0x62])),
        (63, EncryptedSessionPayload::unclassified([0x63])),
    ] {
        assert!(matches!(
            local
                .prepare_fenced_transition(create_request_with_encoded_payload(id, payload.clone()))
                .await,
            Err(StoreError::CapabilityNotSupported(_))
        ));
        assert!(matches!(
            local
                .prepare_fenced_transition(update_request_with_encoded_payload(id + 10, payload))
                .await,
            Err(StoreError::CapabilityNotSupported(_))
        ));
    }
    assert_eq!(local_provider.calls(), 1);
    assert_eq!(local_spy.capability_calls(), local_capabilities);
    assert_eq!(local_spy.preflight_calls(), local_preflights);
    assert_eq!(local_spy.prepared().len(), 1);
    local
        .prepare_fenced_transition(delete_request(64))
        .await
        .expect("delete remains payload-free");
    local
        .prepare_fenced_transition(refresh_request(65))
        .await
        .expect("refresh remains payload-free");
    assert_eq!(local_provider.calls(), 1);

    let remote_spy = Arc::new(AtomicSpy::new());
    let remote_provider = CountingRemoteProvider::with_key("remote-caller-encoding", 0x67);
    let remote_journal = JournalFixture::new(0xa4);
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(remote_journal.open());
    remote
        .prepare_fenced_transition(create_request(70))
        .await
        .expect("prepare plaintext remote request");
    let remote_envelope = remote_spy.prepared()[0]
        .mutation()
        .record()
        .expect("physical record")
        .payload
        .clone();
    let remote_capabilities = remote_spy.capability_calls();
    let remote_preflights = remote_spy.preflight_calls();
    for (id, payload) in [
        (71, remote_envelope.clone()),
        (72, EncryptedSessionPayload::legacy_plaintext([0x72])),
        (73, EncryptedSessionPayload::unclassified([0x73])),
    ] {
        assert!(matches!(
            remote
                .prepare_fenced_transition(create_request_with_encoded_payload(id, payload.clone()))
                .await,
            Err(StoreError::CapabilityNotSupported(_))
        ));
        assert!(matches!(
            remote
                .prepare_fenced_transition(update_request_with_encoded_payload(id + 10, payload))
                .await,
            Err(StoreError::CapabilityNotSupported(_))
        ));
    }
    assert_eq!(remote_provider.calls(), 1);
    assert_eq!(remote_spy.capability_calls(), remote_capabilities);
    assert_eq!(remote_spy.preflight_calls(), remote_preflights);
    assert_eq!(remote_spy.prepared().len(), 1);
    remote
        .prepare_fenced_transition(delete_request(74))
        .await
        .expect("delete remains payload-free");
    remote
        .prepare_fenced_transition(refresh_request(75))
        .await
        .expect("refresh remains payload-free");
    assert_eq!(remote_provider.calls(), 1);
}

#[tokio::test]
async fn protected_fenced_transition_rejects_non_envelope_observations_before_provider_work() {
    let local_spy = Arc::new(AtomicSpy::new());
    let local_provider = CountingKeyProvider::with_key("local-observation-encoding", 0x68);
    let local_journal = JournalFixture::new(0xa5);
    let local = EncryptingSessionBackend::new(
        Arc::clone(&local_spy),
        Arc::clone(&local_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(local_journal.open());
    local
        .prepare_fenced_transition(create_request(80))
        .await
        .expect("prepare local observation fixture");
    let local_physical = local_spy.prepared()[0]
        .mutation()
        .record()
        .expect("physical record")
        .clone();
    local_spy.set_observed(Some(local_physical.clone()));
    assert_eq!(
        local
            .observe_fenced_transition(&key())
            .await
            .expect("envelope observation")
            .record()
            .expect("caller record")
            .payload
            .encoding(),
        SessionPayloadEncoding::Plaintext
    );
    let local_calls = local_provider.calls();
    for payload in [
        EncryptedSessionPayload::new([0x81]),
        EncryptedSessionPayload::legacy_plaintext([0x82]),
        EncryptedSessionPayload::unclassified([0x83]),
    ] {
        let mut record = local_physical.clone();
        record.payload = payload;
        local_spy.set_observed(Some(record));
        assert!(matches!(
            local.observe_fenced_transition(&key()).await,
            Err(StoreError::CapabilityNotSupported(_))
        ));
        assert_eq!(local_provider.calls(), local_calls);
    }

    let remote_spy = Arc::new(AtomicSpy::new());
    let remote_provider = CountingRemoteProvider::with_key("remote-observation-encoding", 0x69);
    let remote_journal = JournalFixture::new(0xa6);
    let remote = RemoteSealingSessionBackend::new(
        Arc::clone(&remote_spy),
        Arc::clone(&remote_provider),
        NAMESPACE,
    )
    .with_fenced_transition_journal(remote_journal.open());
    remote
        .prepare_fenced_transition(create_request(90))
        .await
        .expect("prepare remote observation fixture");
    let remote_physical = remote_spy.prepared()[0]
        .mutation()
        .record()
        .expect("physical record")
        .clone();
    remote_spy.set_observed(Some(remote_physical.clone()));
    assert_eq!(
        remote
            .observe_fenced_transition(&key())
            .await
            .expect("envelope observation")
            .record()
            .expect("caller record")
            .payload
            .encoding(),
        SessionPayloadEncoding::Plaintext
    );
    let remote_calls = remote_provider.calls();
    for payload in [
        EncryptedSessionPayload::new([0x91]),
        EncryptedSessionPayload::legacy_plaintext([0x92]),
        EncryptedSessionPayload::unclassified([0x93]),
    ] {
        let mut record = remote_physical.clone();
        record.payload = payload;
        remote_spy.set_observed(Some(record));
        assert!(matches!(
            remote.observe_fenced_transition(&key()).await,
            Err(StoreError::CapabilityNotSupported(_))
        ));
        assert_eq!(remote_provider.calls(), remote_calls);
    }
}

#[tokio::test]
async fn protected_fenced_transition_capability_withdrawal_blocks_atomic_actions_but_not_recovery()
{
    let local_spy = Arc::new(AtomicSpy::new());
    let local_provider = CountingKeyProvider::with_key("local-withdrawal", 0x6a);
    let local_journal = JournalFixture::new(0xa7);
    let local_backend: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(Arc::new(
        EncryptingSessionBackend::new(
            Arc::clone(&local_spy),
            Arc::clone(&local_provider),
            NAMESPACE,
        )
        .with_fenced_transition_journal(local_journal.open()),
    )));
    let local_token = local_backend
        .prepare_fenced_transition(create_request(100))
        .await
        .expect("prepare local token");
    let local_provider_calls = local_provider.calls();
    let local_observations = local_spy.observation_calls();
    local_spy.disable_capability();
    assert!(matches!(
        local_backend.observe_fenced_transition(&key()).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        local_backend.fenced_transition(&local_token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        local_backend.fenced_transition_status(&local_token).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    let recovered_local = match local_backend
        .recover_prepared_fenced_transition(local_token.request_id())
        .await
        .expect("recover local token while capability is withdrawn")
    {
        PreparedFencedTransitionLookup::Found(prepared) => prepared,
        PreparedFencedTransitionLookup::Absent => panic!("retained local token was lost"),
    };
    assert!(recovered_local.as_bytes() == local_token.as_bytes());
    assert_eq!(local_provider.calls(), local_provider_calls);
    assert_eq!(local_spy.observation_calls(), local_observations);
    assert_eq!(local_spy.dispatches(), 0);
    assert!(local_spy.statuses().is_empty());

    let remote_spy = Arc::new(AtomicSpy::new());
    let remote_provider = CountingRemoteProvider::with_key("remote-withdrawal", 0x6b);
    let remote_journal = JournalFixture::new(0xa8);
    let remote_backend: Arc<dyn SessionBackend> = Arc::new(SessionStore::from_arc(Arc::new(
        RemoteSealingSessionBackend::new(
            Arc::clone(&remote_spy),
            Arc::clone(&remote_provider),
            NAMESPACE,
        )
        .with_fenced_transition_journal(remote_journal.open()),
    )));
    let remote_token = remote_backend
        .prepare_fenced_transition(create_request(101))
        .await
        .expect("prepare remote token");
    let remote_provider_calls = remote_provider.calls();
    let remote_observations = remote_spy.observation_calls();
    remote_spy.disable_capability();
    assert!(matches!(
        remote_backend.observe_fenced_transition(&key()).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    assert!(matches!(
        remote_backend.fenced_transition(&remote_token).await,
        Err(FencedTransitionExecuteError::NotTransmitted)
    ));
    assert!(matches!(
        remote_backend.fenced_transition_status(&remote_token).await,
        Err(StoreError::CapabilityNotSupported(_))
    ));
    let recovered_remote = match remote_backend
        .recover_prepared_fenced_transition(remote_token.request_id())
        .await
        .expect("recover remote token while capability is withdrawn")
    {
        PreparedFencedTransitionLookup::Found(prepared) => prepared,
        PreparedFencedTransitionLookup::Absent => panic!("retained remote token was lost"),
    };
    assert!(recovered_remote.as_bytes() == remote_token.as_bytes());
    assert_eq!(remote_provider.calls(), remote_provider_calls);
    assert_eq!(remote_spy.observation_calls(), remote_observations);
    assert_eq!(remote_spy.dispatches(), 0);
    assert!(remote_spy.statuses().is_empty());
}

#[tokio::test]
async fn protected_fenced_transition_full_surface_forwards_through_session_store_without_readback()
{
    let spy = Arc::new(AtomicSpy::new());
    let provider = CountingKeyProvider::with_key("session-store-before-rotation", 0x53);
    let journal_fixture = JournalFixture::new(0x95);
    let journal = journal_fixture.open();
    let wrapper = Arc::new(
        EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
            .with_fenced_transition_journal(Arc::clone(&journal)),
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
            .with_fenced_transition_journal(Arc::clone(&journal)),
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
    let local_journal_fixture = JournalFixture::new(0xa0);
    let local_journal = local_journal_fixture.open();
    let backend = EncryptingSessionBackend::new(Arc::clone(&spy), Arc::clone(&provider), NAMESPACE)
        .with_fenced_transition_journal(Arc::clone(&local_journal));
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
    .with_fenced_transition_journal(Arc::clone(&local_journal));
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
    .with_fenced_transition_journal(Arc::clone(&local_journal));
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
