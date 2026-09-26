use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use opc_session_store::{
    BackendCapabilities, LeaseError, LeaseGuard, SessionOp, SessionOpResult, StoreError,
};

use super::*;

/// Gate the acknowledgement after SQLite has actually renewed the lease.
/// This exercises cancellation/late replies without replacing the credential
/// checks with a mock result or holding an SQLite transaction open.
pub(in crate::selector_namespace) struct RenewalBackend {
    inner: SqliteSessionBackend,
    acquisition_entered: Mutex<Option<Instant>>,
    pub(in crate::selector_namespace) renewals: AtomicUsize,
    pub(in crate::selector_namespace) acquisitions: AtomicUsize,
    pub(in crate::selector_namespace) releases: AtomicUsize,
    pub(in crate::selector_namespace) reject_renewal: AtomicBool,
    pub(in crate::selector_namespace) reject_release: AtomicBool,
    pub(in crate::selector_namespace) panic_release: AtomicBool,
    pub(in crate::selector_namespace) hold_acquire: AtomicBool,
    pub(in crate::selector_namespace) acquire_entered: tokio::sync::Notify,
    pub(in crate::selector_namespace) acquire_release: tokio::sync::Notify,
    pub(super) reads: AtomicUsize,
    pub(super) writes: AtomicUsize,
    pub(super) reject_read: AtomicUsize,
    hold_ack: AtomicBool,
    applied: tokio::sync::Notify,
    acknowledge: tokio::sync::Notify,
    pub(in crate::selector_namespace) hold_cas: AtomicBool,
    pub(in crate::selector_namespace) cas_entered: tokio::sync::Notify,
    pub(in crate::selector_namespace) cas_release: tokio::sync::Notify,
}

impl RenewalBackend {
    pub(in crate::selector_namespace) fn new() -> Self {
        Self {
            inner: SqliteSessionBackend::in_memory().unwrap(),
            acquisition_entered: Mutex::new(None),
            renewals: AtomicUsize::new(0),
            acquisitions: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            reject_renewal: AtomicBool::new(false),
            reject_release: AtomicBool::new(false),
            panic_release: AtomicBool::new(false),
            hold_acquire: AtomicBool::new(false),
            acquire_entered: tokio::sync::Notify::new(),
            acquire_release: tokio::sync::Notify::new(),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            reject_read: AtomicUsize::new(usize::MAX),
            hold_ack: AtomicBool::new(false),
            applied: tokio::sync::Notify::new(),
            acknowledge: tokio::sync::Notify::new(),
            hold_cas: AtomicBool::new(false),
            cas_entered: tokio::sync::Notify::new(),
            cas_release: tokio::sync::Notify::new(),
        }
    }
}

#[async_trait::async_trait]
impl SessionBackend for RenewalBackend {
    fn restore_scan_cursor_profile(&self) -> Option<RestoreScanCursorProfile> {
        self.inner.restore_scan_cursor_profile()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let count = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        if count == self.reject_read.load(Ordering::SeqCst) {
            return Err(StoreError::BackendUnavailable("fixed read fault".into()));
        }
        self.inner.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.hold_cas.swap(false, Ordering::SeqCst) {
            self.cas_entered.notify_one();
            self.cas_release.notified().await;
        }
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
}

#[async_trait::async_trait]
impl SessionLeaseManager for RenewalBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        *self.acquisition_entered.lock().unwrap() = Some(Instant::now());
        let result = self.inner.acquire(key, owner, ttl).await;
        if self.hold_acquire.load(Ordering::SeqCst) {
            self.acquire_entered.notify_one();
            self.acquire_release.notified().await;
        }
        result
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        self.renewals.fetch_add(1, Ordering::SeqCst);
        if self.reject_renewal.load(Ordering::SeqCst) {
            return Err(LeaseError::StaleFence);
        }
        let renewed = self.inner.renew(lease, ttl).await?;
        if self.hold_ack.load(Ordering::SeqCst) {
            self.applied.notify_one();
            self.acknowledge.notified().await;
        }
        Ok(renewed)
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.panic_release.load(Ordering::SeqCst),
            "fixed release panic"
        );
        if self.reject_release.load(Ordering::SeqCst) {
            return Err(LeaseError::StaleFence);
        }
        self.inner.release(lease).await
    }
}

pub(in crate::selector_namespace) async fn authority(
    ttl: Duration,
) -> (
    GtpuSessionSelectorNamespaceAuthority<RenewalBackend>,
    Arc<RenewalBackend>,
) {
    let backend = Arc::new(RenewalBackend::new());
    let authority = GtpuSessionSelectorNamespaceAuthority::open(
        SessionStore::from_arc(Arc::clone(&backend)),
        production_namespace_key(GtpuSessionDeviceId::new([1; 16]).unwrap()),
        OwnerId::new("selector-worker-lease-test").unwrap(),
        ttl,
        32,
    )
    .await
    .unwrap();
    (authority, backend)
}

pub(in crate::selector_namespace) async fn provisioned_authority(
    ttl: Duration,
) -> (
    GtpuSessionSelectorNamespaceAuthority<RenewalBackend>,
    Arc<RenewalBackend>,
) {
    let (authority, backend) = authority(ttl).await;
    authority
        .provision(&FaultingSelectorBackend::default())
        .await
        .unwrap();
    (authority, backend)
}

/// Move only the worker's conservative observations into the past. The actual
/// SQLite lease is still current, so renewal must exercise the real credential.
fn make_renewal_due(lease: &mut SelectorWorkerLease) {
    let timing = lease.timing.as_mut().unwrap();
    timing.requested_at -= timing.renew_after;
    timing.requested_wall -= timing.renew_after;
    timing.monotonic_deadline -= timing.renew_after;
    timing.wall_deadline -= timing.renew_after;
}

#[test]
fn cadence_reserves_backend_time_and_rejects_expiry_or_clock_rollback() {
    for ttl in [Duration::from_secs(30), Duration::from_millis(20)] {
        let timing = SelectorLeaseTiming::start(ttl).unwrap();
        let due = timing.renew_after;
        let check = |monotonic_age, wall_age, reserve| {
            timing.renewal_due_at(
                timing.requested_at + monotonic_age,
                timing.requested_wall + wall_age,
                reserve,
            )
        };
        assert_eq!(
            check(Duration::ZERO, Duration::ZERO, Duration::ZERO),
            Ok(false)
        );
        assert_eq!(check(due, Duration::ZERO, Duration::ZERO), Ok(true));
        assert_eq!(check(Duration::ZERO, due, Duration::ZERO), Ok(true));
        assert_eq!(check(due / 2, due / 2, due / 2), Ok(true));
        assert!(check(ttl, Duration::ZERO, Duration::ZERO).is_err());
        assert!(check(Duration::ZERO, ttl, Duration::ZERO).is_err());
        assert!(timing
            .renewal_due_at(
                timing.requested_at - Duration::from_nanos(1),
                timing.requested_wall,
                Duration::ZERO,
            )
            .is_err());
        assert!(timing
            .renewal_due_at(
                timing.requested_at,
                timing.requested_wall - Duration::from_nanos(1),
                Duration::ZERO,
            )
            .is_err());
    }
}

#[tokio::test]
async fn rapid_steps_share_one_durable_lease_and_each_receive_a_fresh_window() {
    let (authority, backend) = authority(Duration::from_secs(30)).await;
    authority
        .provision(&FaultingSelectorBackend::default())
        .await
        .unwrap();
    backend.renewals.store(0, Ordering::SeqCst);
    let mut lease = authority.acquire_worker_lease().await.unwrap();
    let original_start = lease.timing.as_ref().unwrap().requested_at;
    assert!(original_start <= backend.acquisition_entered.lock().unwrap().unwrap());
    let original_credential = lease.guard.clone();
    let mut coordinates = std::collections::BTreeSet::new();
    for _ in 0..3 {
        let window = authority
            .mint_backend_mutation_window(&mut lease)
            .await
            .unwrap();
        assert!(coordinates.insert(window.coordinate()));
        assert!(window.is_current());
        let timing = lease.timing.as_ref().unwrap();
        assert!(window.monotonic_deadline <= timing.monotonic_deadline);
        assert!(window.wall_deadline <= timing.wall_deadline);
        assert!(window.monotonic_deadline <= timing.requested_at + timing.renew_after);
        assert!(window.wall_deadline <= timing.requested_wall + timing.renew_after);
        assert_eq!(timing.requested_at, original_start);
        let (record, state) = authority.read_state().await.unwrap();
        assert!(authority
            .replace_with_lease(record.as_ref(), state, &mut lease)
            .await
            .unwrap());
    }
    assert_eq!(backend.renewals.load(Ordering::SeqCst), 0);
    assert_eq!(lease.guard, original_credential);

    make_renewal_due(&mut lease);
    let window = authority
        .mint_backend_mutation_window(&mut lease)
        .await
        .unwrap();
    assert!(coordinates.insert(window.coordinate()));
    assert_eq!(backend.renewals.load(Ordering::SeqCst), 1);
    assert_eq!(lease.guard.fence(), original_credential.fence());
    assert_eq!(
        lease.guard.credential_id(),
        original_credential.credential_id()
    );
    authority.release_worker_lease(lease).await.unwrap();
}

#[tokio::test]
async fn cancelled_renewal_cannot_reuse_or_retry_the_worker_credential() {
    let (authority, backend) = authority(Duration::from_secs(30)).await;
    let mut lease = authority.acquire_worker_lease().await.unwrap();
    make_renewal_due(&mut lease);
    backend.hold_ack.store(true, Ordering::SeqCst);
    let mut renewal = Box::pin(authority.mint_backend_mutation_window(&mut lease));
    tokio::select! {
        result = &mut renewal => panic!("renewal escaped its acknowledgement gate: {result:?}"),
        () = backend.applied.notified() => {}
    }
    drop(renewal);
    assert!(lease.timing.is_none());
    assert!(authority
        .mint_backend_mutation_window(&mut lease)
        .await
        .is_err());
    assert_eq!(backend.renewals.load(Ordering::SeqCst), 1);
    // The old expiry is no longer the exact durable guard either. Cancellation
    // must not synthesize a successful release from the missing renewal reply.
    assert!(authority.release_worker_lease(lease).await.is_err());
}

#[tokio::test]
async fn failed_renewal_permanently_fences_the_worker() {
    let (authority, backend) = authority(Duration::from_secs(30)).await;
    let mut lease = authority.acquire_worker_lease().await.unwrap();
    backend.inner.release(lease.guard.clone()).await.unwrap();
    make_renewal_due(&mut lease);
    assert!(authority
        .mint_backend_mutation_window(&mut lease)
        .await
        .is_err());
    assert!(lease.timing.is_none());
    assert!(authority
        .mint_backend_mutation_window(&mut lease)
        .await
        .is_err());
    assert_eq!(backend.renewals.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn late_renewal_acknowledgement_does_not_restart_the_lease_budget() {
    let (authority, backend) = authority(Duration::from_secs(1)).await;
    let mut lease = authority.acquire_worker_lease().await.unwrap();
    make_renewal_due(&mut lease);
    backend.hold_ack.store(true, Ordering::SeqCst);
    let mut renewal = Box::pin(authority.mint_backend_mutation_window(&mut lease));
    tokio::select! {
        result = &mut renewal => panic!("renewal escaped its acknowledgement gate: {result:?}"),
        () = backend.applied.notified() => {}
    }
    // The result is already durable. Only acknowledgement delivery is delayed
    // past the half-TTL cadence; a longer scheduler pause also fails closed.
    tokio::time::sleep(Duration::from_millis(550)).await;
    backend.acknowledge.notify_one();
    assert!(renewal.await.is_err());
    assert!(lease.timing.is_none());
    assert!(authority
        .mint_backend_mutation_window(&mut lease)
        .await
        .is_err());
    assert_eq!(backend.renewals.load(Ordering::SeqCst), 1);
    let _ = authority.release_worker_lease(lease).await;
}
