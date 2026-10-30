//! Transport deadlines must not manufacture terminal scan-work exhaustion.

use super::*;
use crate::protocol::RestoreScanWireRequest;
use opc_session_store::{
    BackendCapabilities, FakeSessionBackend, LeaseGuard, SessionBackend, SessionLeaseManager,
    SessionOp,
};
use std::sync::atomic::AtomicUsize;
use tokio::io::DuplexStream;
use tokio::task::JoinHandle;

#[derive(Clone, Copy)]
enum ScanMode {
    Ready,
    Stall,
    WorkBudget,
}

struct ControlledRestoreBackend {
    inner: FakeSessionBackend,
    mode: StdMutex<ScanMode>,
    started: AtomicUsize,
    active: AtomicUsize,
    retired: AtomicUsize,
    succeeded: AtomicUsize,
}

impl ControlledRestoreBackend {
    fn new(mode: ScanMode) -> Self {
        Self {
            inner: FakeSessionBackend::new(),
            mode: StdMutex::new(mode),
            started: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            retired: AtomicUsize::new(0),
            succeeded: AtomicUsize::new(0),
        }
    }

    fn ready(&self) {
        *self.mode.lock().unwrap() = ScanMode::Ready;
    }

    fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.started.load(Ordering::SeqCst),
            self.active.load(Ordering::SeqCst),
            self.retired.load(Ordering::SeqCst),
            self.succeeded.load(Ordering::SeqCst),
        )
    }
}

struct ActiveRestoreCall<'a>(&'a ControlledRestoreBackend);

impl Drop for ActiveRestoreCall<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.retired.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl SessionBackend for ControlledRestoreBackend {
    fn restore_scan_cursor_profile(&self) -> Option<RestoreScanCursorProfile> {
        Some(RestoreScanCursorProfile::DurableOpaqueV1)
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

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        assert_eq!(request, RestoreScanRequest::all(1));
        self.started.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveRestoreCall(self);
        let mode = *self.mode.lock().unwrap();
        match mode {
            ScanMode::Stall => std::future::pending().await,
            ScanMode::WorkBudget => Err(StoreError::RestoreScanWorkBudgetExceeded),
            ScanMode::Ready => {
                self.succeeded.fetch_add(1, Ordering::SeqCst);
                let mut page = RestoreScanPage::new(Vec::new(), 0, None);
                page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
                Ok(page)
            }
        }
    }
}

#[async_trait::async_trait]
impl SessionLeaseManager for ControlledRestoreBackend {
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

async fn connect_restore_rpc(
    backend: Arc<ControlledRestoreBackend>,
    config: DispatchConfig,
) -> (DuplexStream, JoinHandle<Result<(), ProtocolError>>) {
    let pending = PendingServerLifecycle::insecure(config.reauthentication.generation());
    let (mut peer, server) = tokio::io::duplex(DEFAULT_MAX_FRAME_SIZE);
    let task = tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(server);
        dispatch(
            backend,
            Arc::new(StdMutex::new(CasIdempotencyCache::default())),
            &mut reader,
            &mut writer,
            ConnectionPeerIdentity::InsecureTest,
            pending,
            config,
        )
        .await
    });
    peer.write_all(&valid_bootstrap_hello_bytes().await)
        .await
        .expect("send actual bootstrap Hello");
    assert!(matches!(
        read_frame::<_, BootstrapResponse>(&mut peer, MAX_HANDSHAKE_FRAME_SIZE)
            .await
            .expect("read actual bootstrap acknowledgement"),
        BootstrapResponse::HelloAck(_)
    ));
    (peer, task)
}

async fn restore_rpc(peer: &mut DuplexStream) -> Result<RestoreScanPage, StoreError> {
    write_frame(
        peer,
        &Request::ScanRestoreRecords {
            request: RestoreScanWireRequest::try_from(&RestoreScanRequest::all(1))
                .expect("bounded restore request"),
            max_response_frame_size: DEFAULT_MAX_FRAME_SIZE as u32,
        },
    )
    .await
    .expect("send framed restore request");
    match read_frame::<_, Response>(peer, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read framed restore reply")
    {
        Response::ScanRestoreRecords(result) => result,
        other => panic!("unexpected response family: {other:?}"),
    }
}

fn assert_empty_complete_page(page: &RestoreScanPage) {
    assert!(page.records.is_empty());
    assert_eq!(page.loaded_count, 0);
    assert_eq!(page.excluded_count, 0);
    assert!(page.complete);
    assert!(page.next_cursor.is_none());
    assert_eq!(
        page.cursor_profile,
        RestoreScanCursorProfile::DurableOpaqueV1
    );
}

async fn prove_restore_rpc_deadline(queue: bool) {
    let backend = Arc::new(ControlledRestoreBackend::new(ScanMode::Stall));
    let config = test_dispatch_config(SessionReauthenticationControl::new());
    let timeout = config
        .restore_scan_timeout
        .min(config.backend_operation_timeout);
    let slots = Arc::clone(&config.restore_scan_slots);
    let held = if queue {
        Some(Arc::clone(&slots).acquire_owned().await.unwrap())
    } else {
        None
    };
    let (mut peer, server) = connect_restore_rpc(Arc::clone(&backend), config).await;
    let started = tokio::time::Instant::now();
    let error = restore_rpc(&mut peer)
        .await
        .expect_err("transport deadline");
    assert_eq!(started.elapsed(), timeout);
    assert!(
        matches!(error, StoreError::BackendUnavailable(_)),
        "transport slowness must remain retryable availability: {error:?}"
    );
    if queue {
        assert_eq!(backend.counts(), (0, 0, 0, 0), "queue ran no backend work");
        assert_eq!(slots.available_permits(), 0, "fixture still owns admission");
    } else {
        assert_eq!(backend.counts(), (1, 0, 1, 0), "timed-out scan was retired");
        assert_eq!(slots.available_permits(), 1, "execution released admission");
    }
    drop(held);
    backend.ready();
    assert_empty_complete_page(&restore_rpc(&mut peer).await.expect("later scan succeeds"));
    assert_eq!(
        backend.counts(),
        if queue { (1, 0, 1, 1) } else { (2, 0, 2, 1) }
    );
    assert_eq!(slots.available_permits(), 1);
    drop(peer);
    server.await.expect("join server").expect("clean peer EOF");
}

#[tokio::test(start_paused = true)]
async fn queued_restore_scan_rpc_deadline_is_retryable_without_backend_work() {
    prove_restore_rpc_deadline(true).await;
}

#[tokio::test(start_paused = true)]
async fn executing_restore_scan_rpc_deadline_is_retryable_and_retires_work() {
    prove_restore_rpc_deadline(false).await;
}

#[tokio::test(start_paused = true)]
async fn restore_scan_rpc_preserves_terminal_backend_work_budget() {
    let backend = Arc::new(ControlledRestoreBackend::new(ScanMode::WorkBudget));
    let config = test_dispatch_config(SessionReauthenticationControl::new());
    let slots = Arc::clone(&config.restore_scan_slots);
    let (mut peer, server) = connect_restore_rpc(Arc::clone(&backend), config).await;
    let started = tokio::time::Instant::now();
    assert_eq!(
        restore_rpc(&mut peer)
            .await
            .expect_err("real work exhaustion"),
        StoreError::RestoreScanWorkBudgetExceeded
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(backend.counts(), (1, 0, 1, 0));
    assert_eq!(slots.available_permits(), 1);
    backend.ready();
    assert_empty_complete_page(&restore_rpc(&mut peer).await.expect("new scan succeeds"));
    assert_eq!(backend.counts(), (2, 0, 2, 1));
    assert_eq!(slots.available_permits(), 1);
    drop(peer);
    server.await.expect("join server").expect("clean peer EOF");
}
