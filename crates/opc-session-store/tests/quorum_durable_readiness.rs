use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use opc_session_store::{
    BackendCapabilities, BackendInstanceIdentity, CompareAndSet, CompareAndSetResult,
    DurableReadinessOptions, DurableReadinessState, FakeSessionBackend, FencedSessionReplica,
    LeaseError, LeaseGuard, OwnerId, QuorumSessionStore, ReplicaReadinessFailure,
    ReplicaReadinessOutcome, ReplicationEntry, ReplicationOp, SessionBackend, SessionKey,
    SessionKeyType, SessionLeaseManager, SessionOp, SessionOpResult, StoreError,
    StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use tokio::sync::Mutex;

mod support;

#[derive(Debug, Clone, Copy)]
enum HeadBehavior {
    Normal,
    Fail(ReplicaReadinessFailure),
    Delay(Duration),
}

struct ControlledBackend {
    inner: FakeSessionBackend,
    head_behavior: Mutex<HeadBehavior>,
    head_probe_calls: AtomicUsize,
    reject_repairs: AtomicBool,
    replicate_calls: AtomicUsize,
    rebuild_calls: AtomicUsize,
}

impl ControlledBackend {
    fn new() -> Self {
        Self {
            inner: FakeSessionBackend::new(),
            head_behavior: Mutex::new(HeadBehavior::Normal),
            head_probe_calls: AtomicUsize::new(0),
            reject_repairs: AtomicBool::new(false),
            replicate_calls: AtomicUsize::new(0),
            rebuild_calls: AtomicUsize::new(0),
        }
    }

    async fn set_head_behavior(&self, behavior: HeadBehavior) {
        *self.head_behavior.lock().await = behavior;
    }

    fn reject_repairs(&self, reject: bool) {
        self.reject_repairs.store(reject, Ordering::SeqCst);
    }

    async fn seed(&self, entries: &[ReplicationEntry]) {
        for entry in entries {
            self.inner
                .replicate_entry(entry.clone())
                .await
                .expect("seed replication entry");
        }
    }

    async fn replication_log(&self) -> Vec<ReplicationEntry> {
        let head = self
            .inner
            .max_replication_sequence()
            .await
            .expect("read replication head");
        let limit = usize::try_from(head).expect("test replication head fits usize");
        self.inner
            .get_replication_log(1, limit)
            .await
            .expect("read replication log")
    }
}

#[async_trait]
impl SessionBackend for ControlledBackend {
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        self.inner.backend_instance_identity()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.inner.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.inner.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        self.inner.batch(ops).await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.inner.max_replication_sequence().await
    }

    async fn probe_replication_head(&self) -> Result<u64, ReplicaReadinessFailure> {
        self.head_probe_calls.fetch_add(1, Ordering::SeqCst);
        match *self.head_behavior.lock().await {
            HeadBehavior::Normal => self
                .inner
                .max_replication_sequence()
                .await
                .map_err(|_| ReplicaReadinessFailure::Backend),
            HeadBehavior::Fail(failure) => Err(failure),
            HeadBehavior::Delay(delay) => {
                tokio::time::sleep(delay).await;
                self.inner
                    .max_replication_sequence()
                    .await
                    .map_err(|_| ReplicaReadinessFailure::Backend)
            }
        }
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.inner.get_replication_log(start, limit).await
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        self.replicate_calls.fetch_add(1, Ordering::SeqCst);
        if self.reject_repairs.load(Ordering::SeqCst) {
            return Err(StoreError::BackendUnavailable(
                "injected append failure".into(),
            ));
        }
        self.inner.replicate_entry(entry).await
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        self.rebuild_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.rebuild_replication_state(entries).await
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.inner.next_lease_info().await
    }
}

#[async_trait]
impl SessionLeaseManager for ControlledBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        self.inner.renew(lease, ttl).await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        self.inner.release(lease).await
    }
}

fn backends() -> Vec<Arc<ControlledBackend>> {
    controlled_backends(3)
}

fn controlled_backends(count: usize) -> Vec<Arc<ControlledBackend>> {
    (0..count)
        .map(|_| Arc::new(ControlledBackend::new()))
        .collect()
}

fn quorum(backends: &[Arc<ControlledBackend>], order: &[usize]) -> QuorumSessionStore {
    support::validated_ha(
        order
            .iter()
            .map(|index| {
                let backend: Arc<dyn opc_session_store::SessionStoreBackend> =
                    backends[*index].clone();
                support::member(*index, backend)
            })
            .collect(),
    )
}

fn options(timeout: Duration, max_log_entries: usize) -> DurableReadinessOptions {
    DurableReadinessOptions::new(timeout, max_log_entries)
}

fn entry(sequence: u64, tx_id: &str) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: tx_id.to_owned(),
        op: ReplicationOp::Batch { ops: Vec::new() },
        timestamp: Timestamp::now_utc(),
    }
}

fn test_key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("readiness-test").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"durable-readiness"),
    }
}

#[tokio::test]
async fn quorum_rejects_zero_before_readiness_or_replica_dispatch() {
    let backends = backends();
    let store = quorum(&backends, &[0, 1, 2]);
    let malformed = entry(0, "untrusted-transaction-canary");

    let error = store
        .replicate_entry(malformed)
        .await
        .expect_err("sequence zero must be rejected");

    assert_eq!(error, StoreError::InvalidReplicationSequence);
    assert_eq!(error.to_string(), "invalid replication sequence");
    assert!(!format!("{error:?}").contains("untrusted-transaction-canary"));
    assert!(backends.iter().all(|backend| {
        backend.head_probe_calls.load(Ordering::SeqCst) == 0
            && backend.replicate_calls.load(Ordering::SeqCst) == 0
            && backend.rebuild_calls.load(Ordering::SeqCst) == 0
    }));
    for backend in &backends {
        assert!(backend.replication_log().await.is_empty());
    }
}

#[tokio::test]
async fn quorum_sequence_one_duplicate_gap_and_max_remain_bounded() {
    let backends = backends();
    let store = quorum(&backends, &[0, 1, 2]);
    let first = entry(1, "tx-1");

    store
        .replicate_entry(first.clone())
        .await
        .expect("sequence one must append");
    store
        .replicate_entry(first.clone())
        .await
        .expect("an exact duplicate must be idempotent");

    for rejected in [
        entry(1, "divergent-tx"),
        entry(3, "gap"),
        entry(u64::MAX, "maximum"),
    ] {
        assert!(matches!(
            store.replicate_entry(rejected).await,
            Err(StoreError::BackendUnavailable(_))
        ));
    }

    for backend in &backends {
        assert_eq!(backend.replication_log().await, vec![first.clone()]);
        assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.rebuild_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn empty_three_replica_quorum_is_freshly_ready() {
    let backends = backends();
    let report = quorum(&backends, &[0, 1, 2])
        .probe_durable_readiness()
        .await;

    assert_eq!(report.state(), DurableReadinessState::Ready);
    assert!(report.is_ready());
    assert_eq!(report.reason_code(), "ready");
    assert_eq!(report.configured_voters(), 3);
    assert_eq!(report.fresh_reachable_voters(), 3);
    assert_eq!(report.agreeing_voters(), 3);
    assert_eq!(report.required_quorum(), 2);
    assert_eq!(report.majority_visible_prefix_index(), Some(0));
    assert!(report
        .replica_observations()
        .iter()
        .all(|observation| observation.outcome() == ReplicaReadinessOutcome::Ready));
}

#[tokio::test]
async fn fresh_two_of_three_majority_is_ready_with_typed_minority_failure() {
    let backends = backends();
    backends[2]
        .set_head_behavior(HeadBehavior::Fail(ReplicaReadinessFailure::Transport))
        .await;

    let report = quorum(&backends, &[0, 1, 2])
        .probe_durable_readiness()
        .await;

    assert_eq!(report.state(), DurableReadinessState::Ready);
    assert_eq!(report.fresh_reachable_voters(), 2);
    assert_eq!(report.agreeing_voters(), 2);
    assert_eq!(
        report.replica_observations()[2].outcome(),
        ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::Transport)
    );
}

#[tokio::test]
async fn one_of_three_probe_and_real_operation_both_fail_without_quorum() {
    let backends = backends();
    let store = quorum(&backends, &[0, 1, 2]);
    let admitted_capabilities = store.capabilities().await;
    assert!(admitted_capabilities.ordered_replication_log);
    for backend in &backends[1..] {
        backend
            .set_head_behavior(HeadBehavior::Fail(ReplicaReadinessFailure::Transport))
            .await;
    }

    assert_eq!(
        store.capabilities().await,
        admitted_capabilities,
        "descriptive capabilities must not be mistaken for live quorum evidence"
    );

    let report = store.probe_durable_readiness().await;
    assert_eq!(report.state(), DurableReadinessState::NoQuorum);
    assert_eq!(report.fresh_reachable_voters(), 1);
    assert_eq!(report.agreeing_voters(), 0);

    let error = store
        .get(&test_key())
        .await
        .expect_err("real operation must use the same fresh quorum assessment");
    assert!(matches!(error, StoreError::BackendUnavailable(_)));

    let lease_error = store
        .acquire(
            &test_key(),
            OwnerId::new("blocked-owner").expect("test owner"),
            Duration::from_secs(30),
        )
        .await
        .expect_err("ownership lease publication must fail without quorum");
    assert!(matches!(lease_error, LeaseError::Backend(_)));
}

#[allow(deprecated)]
#[tokio::test]
async fn raw_legacy_topology_is_reported_as_invalid() {
    let store = QuorumSessionStore::new(vec![FencedSessionReplica::new(
        0,
        Arc::new(FakeSessionBackend::new()),
    )]);

    let report = store.probe_durable_readiness().await;

    assert_eq!(report.state(), DurableReadinessState::TopologyInvalid);
    assert_eq!(report.reason_code(), "topology_invalid");
    assert!(!report.is_ready());
    assert!(report.replica_observations().is_empty());
}

#[tokio::test]
async fn strict_shorter_prefix_is_caught_up_with_append_only_repair() {
    let backends = backends();
    let entries = [entry(1, "tx-1"), entry(2, "tx-2")];
    backends[0].seed(&entries).await;
    backends[1].seed(&entries).await;
    backends[2].seed(&entries[..1]).await;

    let report = quorum(&backends, &[0, 1, 2])
        .probe_durable_readiness()
        .await;

    assert_eq!(report.state(), DurableReadinessState::Ready);
    assert_eq!(report.majority_visible_prefix_index(), Some(2));
    assert_eq!(report.agreeing_voters(), 3);
    assert_eq!(
        report.replica_observations()[2].outcome(),
        ReplicaReadinessOutcome::Repaired
    );
    assert_eq!(backends[2].replication_log().await, entries);
    assert_eq!(backends[2].replicate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backends[2].rebuild_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_strict_prefix_repair_is_typed_without_blocking_an_agreeing_majority() {
    let backends = backends();
    let committed = [entry(1, "tx-1")];
    backends[0].seed(&committed).await;
    backends[1].seed(&committed).await;
    backends[2].reject_repairs(true);

    let report = quorum(&backends, &[0, 1, 2])
        .probe_durable_readiness()
        .await;

    assert_eq!(report.state(), DurableReadinessState::Ready);
    assert_eq!(report.agreeing_voters(), 2);
    assert_eq!(
        report.replica_observations()[2].outcome(),
        ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::RepairFailed)
    );
    assert!(backends[2].replication_log().await.is_empty());
    assert_eq!(backends[2].rebuild_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn conflicting_log_requires_recovery_without_mutating_any_replica() {
    let backends = backends();
    let majority = entry(1, "majority-tx");
    let conflict = entry(1, "minority-conflict");
    backends[0].seed(std::slice::from_ref(&majority)).await;
    backends[1].seed(std::slice::from_ref(&majority)).await;
    backends[2].seed(std::slice::from_ref(&conflict)).await;
    let before =
        futures_util::future::join_all(backends.iter().map(|backend| backend.replication_log()))
            .await;

    let report = quorum(&backends, &[0, 1, 2])
        .probe_durable_readiness()
        .await;

    assert_eq!(report.state(), DurableReadinessState::RecoveryRequired);
    assert_eq!(report.reason_code(), "recovery_required");
    assert_eq!(
        report.replica_observations()[2].outcome(),
        ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::Divergent)
    );
    let after =
        futures_util::future::join_all(backends.iter().map(|backend| backend.replication_log()))
            .await;
    assert_eq!(after, before);
    assert!(backends.iter().all(|backend| {
        backend.replicate_calls.load(Ordering::SeqCst) == 0
            && backend.rebuild_calls.load(Ordering::SeqCst) == 0
    }));
}

#[tokio::test]
async fn minority_longer_tail_requires_recovery_without_truncation() {
    let backends = backends();
    let majority = [entry(1, "tx-1")];
    let longer = [majority[0].clone(), entry(2, "minority-tail")];
    backends[0].seed(&majority).await;
    backends[1].seed(&majority).await;
    backends[2].seed(&longer).await;

    let report = quorum(&backends, &[0, 1, 2])
        .probe_durable_readiness()
        .await;

    assert_eq!(report.state(), DurableReadinessState::RecoveryRequired);
    assert_eq!(backends[0].replication_log().await, majority);
    assert_eq!(backends[1].replication_log().await, majority);
    assert_eq!(backends[2].replication_log().await, longer);
    assert!(backends.iter().all(|backend| {
        backend.replicate_calls.load(Ordering::SeqCst) == 0
            && backend.rebuild_calls.load(Ordering::SeqCst) == 0
    }));
}

#[tokio::test]
async fn recovery_evidence_suppresses_repairs_of_other_shorter_replicas() {
    let backends = controlled_backends(5);
    let majority = [entry(1, "tx-1"), entry(2, "tx-2")];
    for backend in &backends[..3] {
        backend.seed(&majority).await;
    }
    backends[3].seed(&majority[..1]).await;
    let longer = [
        majority[0].clone(),
        majority[1].clone(),
        entry(3, "minority-tail"),
    ];
    backends[4].seed(&longer).await;
    let shorter_before = backends[3].replication_log().await;

    let report = quorum(&backends, &[0, 1, 2, 3, 4])
        .probe_durable_readiness()
        .await;

    assert_eq!(report.state(), DurableReadinessState::RecoveryRequired);
    assert_eq!(report.majority_visible_prefix_index(), Some(2));
    assert_eq!(backends[3].replication_log().await, shorter_before);
    assert_eq!(backends[3].replicate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backends[3].rebuild_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn readiness_timeout_is_bounded_and_a_later_probe_can_recover() {
    let backends = backends();
    for backend in &backends[1..] {
        backend
            .set_head_behavior(HeadBehavior::Delay(Duration::from_secs(10)))
            .await;
    }
    let probe_options = options(Duration::from_millis(25), 16);
    let store = quorum(&backends, &[0, 1, 2]).with_durable_readiness_options(probe_options);

    let report = tokio::time::timeout(Duration::from_millis(50), store.probe_durable_readiness())
        .await
        .expect("probe must finish inside its end-to-end budget");
    assert_eq!(report.state(), DurableReadinessState::NoQuorum);
    assert_eq!(
        report
            .replica_observations()
            .iter()
            .filter(|observation| {
                observation.outcome()
                    == ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::Timeout)
            })
            .count(),
        2
    );

    for backend in &backends[1..] {
        backend.set_head_behavior(HeadBehavior::Normal).await;
    }
    let recovered = store.probe_durable_readiness().await;
    assert_eq!(recovered.state(), DurableReadinessState::Ready);
    assert_eq!(recovered.agreeing_voters(), 3);
}

#[tokio::test]
async fn oversized_replication_heads_fail_closed_at_the_probe_budget() {
    let backends = backends();
    let entries = [entry(1, "tx-1"), entry(2, "tx-2")];
    for backend in &backends {
        backend.seed(&entries).await;
    }

    let report = quorum(&backends, &[0, 1, 2])
        .with_durable_readiness_options(options(Duration::from_secs(1), 1))
        .probe_durable_readiness()
        .await;

    assert_eq!(report.state(), DurableReadinessState::NoQuorum);
    assert_eq!(report.fresh_reachable_voters(), 3);
    assert_eq!(report.agreeing_voters(), 0);
    assert!(report.replica_observations().iter().all(|observation| {
        observation.observed_sequence() == Some(2)
            && observation.outcome()
                == ReplicaReadinessOutcome::Failed(ReplicaReadinessFailure::ProbeBudgetExceeded)
    }));
}

#[tokio::test(start_paused = true)]
async fn explicit_probe_and_real_operation_share_one_store_policy() {
    let backends = backends();
    for backend in &backends {
        backend
            .set_head_behavior(HeadBehavior::Delay(Duration::from_secs(3)))
            .await;
    }
    let store = quorum(&backends, &[0, 1, 2])
        .with_durable_readiness_options(options(Duration::from_secs(5), 16));

    assert_eq!(
        store.probe_durable_readiness().await.state(),
        DurableReadinessState::Ready
    );
    assert_eq!(
        store.get(&test_key()).await.expect("same policy read"),
        None
    );
}

#[tokio::test]
async fn readiness_debug_output_redacts_replica_identity_and_raw_failures() {
    let backends = backends();
    backends[2]
        .set_head_behavior(HeadBehavior::Fail(ReplicaReadinessFailure::Authentication))
        .await;
    let report = quorum(&backends, &[0, 1, 2])
        .probe_durable_readiness()
        .await;

    let debug = format!("{report:?}");
    assert!(!debug.contains("test-replica-0"));
    assert!(!debug.contains("test-replica-1"));
    assert!(!debug.contains("test-replica-2"));
    assert!(!debug.contains(".invalid"));
    assert!(debug.contains("ReplicaId(<redacted>)"));
    assert!(debug.contains("Authentication"));
}

#[tokio::test]
async fn readiness_result_is_invariant_to_configured_member_order() {
    let backends = backends();
    let entries = [entry(1, "tx-1")];
    for backend in &backends {
        backend.seed(&entries).await;
    }

    let first = quorum(&backends, &[0, 1, 2])
        .probe_durable_readiness()
        .await;
    let reordered = quorum(&backends, &[2, 0, 1])
        .probe_durable_readiness()
        .await;

    assert_eq!(reordered.state(), first.state());
    assert_eq!(reordered.configured_voters(), first.configured_voters());
    assert_eq!(reordered.agreeing_voters(), first.agreeing_voters());
    assert_eq!(reordered.required_quorum(), first.required_quorum());
    assert_eq!(
        reordered.majority_visible_prefix_index(),
        first.majority_visible_prefix_index()
    );
    let mut first_outcomes = first
        .replica_observations()
        .iter()
        .map(|observation| {
            (
                observation.replica_id().as_str().to_owned(),
                observation.outcome(),
            )
        })
        .collect::<Vec<_>>();
    let mut reordered_outcomes = reordered
        .replica_observations()
        .iter()
        .map(|observation| {
            (
                observation.replica_id().as_str().to_owned(),
                observation.outcome(),
            )
        })
        .collect::<Vec<_>>();
    first_outcomes.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    reordered_outcomes.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(reordered_outcomes, first_outcomes);
}
