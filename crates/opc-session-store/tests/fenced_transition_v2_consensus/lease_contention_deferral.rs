//! Lease-contention acceptance cases for issue #1334.
//!
//! These cases use the existing public protected request boundary against a
//! real consensus store. Advancing the injected store clock never changes a
//! caller deadline. No contention retry prepares another request or journal row.

use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use opc_session_store::{
    fenced_transition::FencedTransitionV2Effect, BackendCapabilities, Clock, CompareAndSet,
    CompareAndSetResult, EncryptingSessionBackend, FencedTransitionOutcome,
    FencedTransitionRequest, FencedTransitionRequestId, FencedTransitionV2JournalScope,
    FencedTransitionV2Profile, FencedTransitionV2RecoveryJournal,
    FencedTransitionV2RecoveryJournalKey, LeaseGuard, PreparedFencedTransitionV2,
    PreparedFencedTransitionV2Lookup, ProtectedFencedTransitionV2Backend, SessionLeaseManager,
    SessionOp, SessionOpResult,
};
use opc_types::Timestamp;
use tokio::sync::Notify;

const NAMESPACE: &str = "lease-contention-acceptance";
const LEASE_TTL: Duration = Duration::from_secs(60);
const REFUSALS: usize = 16;

#[derive(Debug)]
struct StoreClock {
    origin: Timestamp,
    seconds: AtomicU64,
}

impl StoreClock {
    fn advance(&self, seconds: u64) {
        self.seconds.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for StoreClock {
    fn now_utc(&self) -> Timestamp {
        Timestamp::from_offset_datetime(
            *self.origin.as_offset_datetime()
                + Duration::from_secs(self.seconds.load(Ordering::SeqCst)),
        )
    }
}

/// Faults occur only after an actual consensus result, or on a receipt read.
/// The wrapper and request journal remain the production implementations.
struct PhysicalBoundary {
    store: Arc<ConsensusSessionStore>,
    calls: AtomicUsize,
    pause_after_commit: AtomicBool,
    committed: Notify,
    status_fault: AtomicU8,
}

#[async_trait]
impl SessionBackend for PhysicalBoundary {
    fn fenced_transition_preserves_protected_payloads(&self) -> bool {
        true
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.store.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.store.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.store.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.store.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        self.store.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        self.store.batch(ops).await
    }

    async fn observe_fenced_transition(
        &self,
        key: &SessionKey,
    ) -> Result<opc_session_store::FencedTransitionObservation, StoreError> {
        self.store.observe_fenced_transition(key).await
    }

    async fn fenced_transition_v2_capability(
        &self,
    ) -> Result<Option<FencedTransitionV2Capability>, StoreError> {
        self.store.fenced_transition_v2_capability().await
    }

    async fn fenced_transition_v2_history_state(
        &self,
    ) -> Result<opc_session_store::FencedTransitionV2HistoryState, StoreError> {
        self.store.fenced_transition_v2_history_state().await
    }

    async fn fenced_transition_v2_effect(
        &self,
        request: FencedTransitionV2Request,
    ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self.store.fenced_transition_v2_effect(request).await;
        if matches!(&result, FencedTransitionV2Effect::Resolved(Ok(_)))
            && self.pause_after_commit.swap(false, Ordering::SeqCst)
        {
            self.committed.notify_one();
            std::future::pending::<()>().await;
        }
        result
    }

    async fn fenced_transition_v2_status(
        &self,
        request: &FencedTransitionV2Request,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        match self.status_fault.load(Ordering::SeqCst) {
            1 => Err(StoreError::BackendUnavailable(
                "synthetic receipt unavailable".into(),
            )),
            2 => Ok(FencedTransitionV2Status::NotFound),
            _ => self.store.fenced_transition_v2_status(request).await,
        }
    }
}

type Protected = EncryptingSessionBackend<PhysicalBoundary, MemoryKeyProvider>;

struct Fixture {
    directory: tempfile::TempDir,
    clock: Arc<StoreClock>,
    physical: Arc<PhysicalBoundary>,
    provider: Arc<MemoryKeyProvider>,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().expect("private fixture directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private recovery journal directory");
        }
        let clock = Arc::new(StoreClock {
            origin: Timestamp::now_utc(),
            seconds: AtomicU64::new(0),
        });
        let source: Arc<dyn Clock> = clock.clone();
        let store = Arc::new(
            ConsensusSessionStore::open_with_clock(
                topology(),
                SqliteSessionBackend::open_with_fenced_transition_v2_profile(
                    directory.path().join("store.sqlite"),
                    FencedTransitionV2Profile::V2WithLeaseDeferral,
                )
                .expect("durable consensus backend")
                .with_clock(Arc::clone(&source)),
                directory.path().join("snapshots"),
                BTreeMap::new(),
                source,
                OPERATION_TIMEOUT,
            )
            .await
            .expect("open consensus store"),
        );
        store.initialize_cluster().await.expect("initialize voter");
        Self {
            directory,
            clock,
            physical: Arc::new(PhysicalBoundary {
                store,
                calls: AtomicUsize::new(0),
                pause_after_commit: AtomicBool::new(false),
                committed: Notify::new(),
                status_fault: AtomicU8::new(0),
            }),
            provider: Arc::new(sealing_provider()),
        }
    }

    fn caller(&self, reopen: bool) -> Protected {
        let path = self.directory.path().join("caller-recovery.sqlite");
        let key = FencedTransitionV2RecoveryJournalKey::from_bytes([0x94; 32]);
        let journal = if reopen {
            FencedTransitionV2RecoveryJournal::open_existing(path, key)
        } else {
            FencedTransitionV2RecoveryJournal::create_new(path, key)
        }
        .expect("open exact caller journal");
        EncryptingSessionBackend::new(
            Arc::clone(&self.physical),
            Arc::clone(&self.provider),
            NAMESPACE,
        )
        .with_fenced_transition_v2_recovery_journal(Arc::new(journal))
        .with_fenced_transition_v2_journal_scope(
            FencedTransitionV2JournalScope::from_bytes([0x95; 32]),
        )
    }

    async fn predecessor(&self, ordinal: u64) -> FencedTransitionOutcome {
        let key = key(&ordinal.to_be_bytes());
        let owner = OwnerId::new("synthetic-owner-a").unwrap();
        let mut record = record(key.clone(), owner.clone(), FenceToken::new(1), b"original");
        record.payload = EncryptedSessionPayload::encrypt(&*self.provider, &record, NAMESPACE)
            .await
            .expect("protect predecessor");
        let request = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).unwrap(),
            FencedTransitionV2CallerNonce::from_bytes((ordinal as u128).to_be_bytes()),
            FencedTransitionLease::acquire(key, owner, FenceToken::new(0), LEASE_TTL).unwrap(),
            FencedTransitionMutation::create(record),
        )
        .unwrap();
        self.physical
            .store
            .fenced_transition_v2(request)
            .await
            .expect("commit predecessor")
    }

    fn successor(
        predecessor: &FencedTransitionOutcome,
        id: FencedTransitionRequestId,
    ) -> FencedTransitionRequest {
        let owner = OwnerId::new("synthetic-owner-b").unwrap();
        let lease = predecessor.lease();
        let mut record = record(
            lease.key().clone(),
            owner.clone(),
            FenceToken::new(lease.fence().get() + 1),
            b"successor",
        );
        record.generation = predecessor.committed_generation().next().unwrap();
        FencedTransitionRequest::new(
            id,
            FencedTransitionLease::acquire(lease.key().clone(), owner, lease.fence(), LEASE_TTL)
                .unwrap(),
            FencedTransitionMutation::update(predecessor.committed_generation(), record),
        )
        .unwrap()
    }

    async fn unchanged(&self, predecessor: &FencedTransitionOutcome) {
        let observation = self
            .physical
            .store
            .observe_fenced_transition(predecessor.lease().key())
            .await
            .expect("authoritative predecessor observation");
        assert_eq!(observation.current_fence(), predecessor.lease().fence());
        let record = observation.record().expect("predecessor remains present");
        assert_eq!(record.generation, predecessor.committed_generation());
        assert!(record.owner == *predecessor.lease().owner());
        assert_eq!(record.fence, predecessor.lease().fence());
    }
}

fn caller_id(value: u128) -> FencedTransitionRequestId {
    FencedTransitionRequestId::from_bytes(value.to_be_bytes())
}

async fn contend(caller: &Protected, prepared: &PreparedFencedTransitionV2) {
    let FencedTransitionV2Effect::Resolved(Err(error)) =
        caller.protected_fenced_transition_v2_effect(prepared).await
    else {
        panic!("the fixture must reach a conclusive live-lease refusal");
    };
    assert_eq!(
        error,
        StoreError::FencedTransitionLeaseDeferred,
        "only actual lease contention sets up the regression"
    );
    assert!(matches!(
        caller.protected_fenced_transition_v2_status(prepared).await.unwrap(),
        FencedTransitionV2Status::LeaseDeferred { request_id }
            if request_id.epoch() == prepared.history_epoch()
    ));
    assert_eq!(
        caller
            .retained_protected_fenced_transitions_v2()
            .await
            .unwrap(),
        1
    );
}

async fn complete(
    caller: &Protected,
    prepared: &PreparedFencedTransitionV2,
) -> FencedTransitionOutcome {
    let FencedTransitionV2Effect::Resolved(Ok(outcome)) =
        caller.protected_fenced_transition_v2_effect(prepared).await
    else {
        panic!("the same deferred identity must commit once the store lease is available");
    };
    assert_eq!(outcome.mutation(), FencedTransitionMutationResult::Updated);
    assert_eq!(outcome.committed_generation(), Generation::new(2));
    outcome
}

#[tokio::test]
async fn repeated_live_lease_contention_is_nonterminal_without_history_growth() {
    let fixture = Fixture::new().await;
    let predecessor = fixture.predecessor(1).await;
    let caller = fixture.caller(false);
    let prepared = caller
        .prepare_protected_fenced_transition_v2(Fixture::successor(&predecessor, caller_id(1)))
        .await
        .unwrap();
    let epoch = prepared.history_epoch();
    let mut bound = None;
    for _ in 0..REFUSALS {
        contend(&caller, &prepared).await;
        fixture.unchanged(&predecessor).await;
        let history = caller
            .protected_fenced_transition_v2_history_state()
            .await
            .unwrap();
        assert_eq!(history.active_epoch(), Some(epoch));
        assert_eq!(
            *bound.get_or_insert(history.bound_entries()),
            history.bound_entries()
        );
        assert!(
            !matches!(
                caller
                    .protected_fenced_transition_v2_status(&prepared)
                    .await
                    .unwrap(),
                FencedTransitionV2Status::Recorded(_)
            ),
            "a conclusive live-lease refusal must not bind a terminal receipt",
        );
    }
    fixture.physical.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn store_clock_expiry_allows_one_commit_of_the_same_deferred_request() {
    let fixture = Fixture::new().await;
    let predecessor = fixture.predecessor(2).await;
    let caller = fixture.caller(false);
    let prepared = caller
        .prepare_protected_fenced_transition_v2(Fixture::successor(&predecessor, caller_id(2)))
        .await
        .unwrap();
    for _ in 0..REFUSALS {
        contend(&caller, &prepared).await;
    }
    fixture.unchanged(&predecessor).await;
    fixture.clock.advance(61);
    let first = complete(&caller, &prepared).await;
    let second = complete(&caller, &prepared).await;
    assert!(
        first == second,
        "an exact repeat returns the original committed result"
    );
    let current = fixture
        .physical
        .store
        .get(predecessor.lease().key())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.generation, Generation::new(2));
    assert_eq!(current.fence, first.lease().fence());
    fixture.physical.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn caller_restart_preserves_deferral_identity_through_contention_and_expiry() {
    let fixture = Fixture::new().await;
    let predecessor = fixture.predecessor(3).await;
    let caller = fixture.caller(false);
    let id = caller_id(3);
    let prepared = caller
        .prepare_protected_fenced_transition_v2(Fixture::successor(&predecessor, id))
        .await
        .unwrap();
    contend(&caller, &prepared).await;
    drop(caller);
    let restarted = fixture.caller(true);
    let PreparedFencedTransitionV2Lookup::Found(recovered) = restarted
        .recover_protected_fenced_transition_v2(id)
        .await
        .unwrap()
    else {
        panic!("the durable caller identity survives restart");
    };
    assert!(
        recovered == prepared,
        "restart retains the complete sealed request"
    );
    for _ in 0..REFUSALS {
        contend(&restarted, &recovered).await;
    }
    drop(restarted);
    fixture.clock.advance(61);
    let restarted = fixture.caller(true);
    let PreparedFencedTransitionV2Lookup::Found(recovered) = restarted
        .recover_protected_fenced_transition_v2(id)
        .await
        .unwrap()
    else {
        panic!("expiry does not discard the deferred request");
    };
    assert!(recovered == prepared);
    complete(&restarted, &recovered).await;
    fixture.physical.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn predecessor_renewal_after_observation_keeps_the_same_request_deferred() {
    let fixture = Fixture::new().await;
    let predecessor = fixture.predecessor(4).await;
    let caller = fixture.caller(false);
    let prepared = caller
        .prepare_protected_fenced_transition_v2(Fixture::successor(&predecessor, caller_id(4)))
        .await
        .unwrap();
    fixture.clock.advance(50);
    caller
        .observe_protected_fenced_transition_v2(predecessor.lease().key())
        .await
        .unwrap();
    let renewed = fixture
        .physical
        .store
        .renew(predecessor.lease(), LEASE_TTL)
        .await
        .unwrap();
    assert_eq!(renewed.fence(), predecessor.lease().fence());
    assert_eq!(renewed.credential_id(), predecessor.lease().credential_id());
    fixture.clock.advance(11);
    for _ in 0..REFUSALS {
        contend(&caller, &prepared).await;
        fixture.unchanged(&predecessor).await;
    }
    fixture.clock.advance(50);
    complete(&caller, &prepared).await;
    fixture.physical.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn new_owner_after_observation_rejects_the_original_fence_without_a_mutation() {
    let fixture = Fixture::new().await;
    let predecessor = fixture.predecessor(5).await;
    let caller = fixture.caller(false);
    let prepared = caller
        .prepare_protected_fenced_transition_v2(Fixture::successor(&predecessor, caller_id(5)))
        .await
        .unwrap();
    fixture
        .physical
        .store
        .release(predecessor.lease().clone())
        .await
        .unwrap();
    caller
        .observe_protected_fenced_transition_v2(predecessor.lease().key())
        .await
        .unwrap();
    let successor = fixture
        .physical
        .store
        .acquire(
            predecessor.lease().key(),
            OwnerId::new("synthetic-owner-c").unwrap(),
            LEASE_TTL,
        )
        .await
        .unwrap();
    assert_eq!(
        caller
            .protected_fenced_transition_v2_effect(&prepared)
            .await,
        FencedTransitionV2Effect::Resolved(Err(StoreError::StaleFence)),
    );
    let current = fixture
        .physical
        .store
        .get(predecessor.lease().key())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.generation, predecessor.committed_generation());
    assert!(current.owner == *predecessor.lease().owner());
    let observed = fixture
        .physical
        .store
        .observe_fenced_transition(predecessor.lease().key())
        .await
        .unwrap();
    assert_eq!(observed.current_fence(), successor.fence());
    fixture.physical.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn interrupted_deferred_execution_retains_status_recovery_through_unknown_reads() {
    let fixture = Fixture::new().await;
    let predecessor = fixture.predecessor(6).await;
    let caller = fixture.caller(false);
    let request = Fixture::successor(&predecessor, caller_id(6));
    let prepared = caller
        .prepare_protected_fenced_transition_v2(request.clone())
        .await
        .unwrap();
    contend(&caller, &prepared).await;
    assert!(
        !matches!(
            caller
                .protected_fenced_transition_v2_status(&prepared)
                .await
                .unwrap(),
            FencedTransitionV2Status::Recorded(_)
        ),
        "deferral must remain distinct from a terminal execution result",
    );
    fixture.clock.advance(61);
    fixture
        .physical
        .pause_after_commit
        .store(true, Ordering::SeqCst);
    {
        let execution = caller.protected_fenced_transition_v2_effect(&prepared);
        tokio::pin!(execution);
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            tokio::select! {
                _ = fixture.physical.committed.notified() => {},
                _ = &mut execution => panic!("execution must reach its actual committed boundary"),
            }
        })
        .await
        .expect("bounded post-commit interruption");
    }
    let calls = fixture.physical.calls.load(Ordering::SeqCst);
    drop(caller);
    let restarted = fixture.caller(true);
    let PreparedFencedTransitionV2Lookup::Found(recovered) = restarted
        .recover_protected_fenced_transition_v2(request.request_id())
        .await
        .unwrap()
    else {
        panic!("an unknown result retains its exact request");
    };
    assert!(recovered == prepared);
    fixture.physical.status_fault.store(1, Ordering::SeqCst);
    assert!(restarted
        .protected_fenced_transition_v2_status(&recovered)
        .await
        .is_err());
    fixture.physical.status_fault.store(2, Ordering::SeqCst);
    assert_eq!(
        restarted
            .protected_fenced_transition_v2_status(&recovered)
            .await
            .unwrap(),
        FencedTransitionV2Status::NotFound,
    );
    assert_eq!(
        restarted
            .retained_protected_fenced_transitions_v2()
            .await
            .unwrap(),
        1
    );
    assert!(matches!(
        restarted
            .prepare_protected_fenced_transition_v2(request)
            .await,
        Err(StoreError::FencedTransitionRequestConflict),
    ));
    assert_eq!(fixture.physical.calls.load(Ordering::SeqCst), calls);
    fixture.physical.status_fault.store(0, Ordering::SeqCst);
    assert!(matches!(
        restarted.protected_fenced_transition_v2_status(&recovered).await.unwrap(),
        FencedTransitionV2Status::Recorded(result) if result.is_ok(),
    ));
    assert_eq!(fixture.physical.calls.load(Ordering::SeqCst), calls);
    let current = fixture
        .physical
        .store
        .get(predecessor.lease().key())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.generation, Generation::new(2));
    fixture.physical.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn releasing_completed_work_reuses_capacity_after_many_contention_refusals() {
    let fixture = Fixture::new().await;
    let caller = fixture.caller(false);
    for ordinal in 10..22 {
        let predecessor = fixture.predecessor(ordinal).await;
        let prepared = caller
            .prepare_protected_fenced_transition_v2(Fixture::successor(
                &predecessor,
                caller_id(ordinal as u128),
            ))
            .await
            .unwrap();
        for _ in 0..REFUSALS {
            contend(&caller, &prepared).await;
        }
        fixture.clock.advance(61);
        complete(&caller, &prepared).await;
        assert!(matches!(
            caller.protected_fenced_transition_v2_status(&prepared).await.unwrap(),
            FencedTransitionV2Status::Recorded(result) if result.is_ok(),
        ));
        assert!(caller
            .discard_protected_fenced_transition_v2(&prepared)
            .await
            .unwrap());
        assert_eq!(
            caller
                .retained_protected_fenced_transitions_v2()
                .await
                .unwrap(),
            0
        );
    }
    fixture.physical.store.shutdown().await.unwrap();
}
