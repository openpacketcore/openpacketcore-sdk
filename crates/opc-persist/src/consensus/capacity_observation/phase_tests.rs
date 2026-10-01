//! Component controls for the metadata guard, independent of native timing.

use super::*;

#[derive(Default)]
struct Observer {
    samples: Mutex<[Option<NativePhaseSample>; 4]>,
    count: AtomicUsize,
}

impl NativeOwnerObserver for Observer {
    fn observe(&self, _: NativeOwnerSample) {}

    fn observe_phase(&self, sample: NativePhaseSample) {
        let index = self.count.fetch_add(1, Ordering::SeqCst);
        lock(&self.samples)[index] = Some(sample);
    }
}

struct TestScope;

impl TestScope {
    fn start(observer: Arc<Observer>) -> (Self, Arc<Shared>) {
        let shared = Arc::new(Shared {
            identity: ConsensusIdentity::new(
                opc_consensus::ConsensusClusterId::from_bytes([0xD1; 32]),
                opc_consensus::ConsensusConfigurationId::from_bytes([0xD2; 32]),
                opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
            ),
            source: ConsensusNodeId::new(1).unwrap(),
            request: ConsensusRequestId::from_bytes([0xD3; 16]),
            selected_root: 0,
            preparations: Arc::new(PreparationCensus::default()),
            observer,
            native_scopes: AtomicUsize::new(0),
            transport_scopes: AtomicUsize::new(0),
            callbacks: AtomicUsize::new(0),
            next_transport: AtomicU64::new(0),
            append_scopes: AtomicUsize::new(0),
            append_callbacks: AtomicUsize::new(0),
            next_append: AtomicU64::new(0),
        });
        NATIVE.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(ActiveNative {
                shared: shared.clone(),
                entered_at: Instant::now(),
                command: Allocations::new(),
                #[cfg(target_os = "linux")]
                command_oracle_bytes: 0,
            });
        });
        (Self, shared)
    }
}

impl Drop for TestScope {
    fn drop(&mut self) {
        NATIVE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[test]
fn config_capacity_native_phase_guard_records_success_error_and_saturation() {
    let observer = Arc::new(Observer::default());
    let (_scope, shared) = TestScope::start(observer.clone());
    let strong_count = Arc::strong_count(&shared);
    let mut success = NativePhaseGuard::start(NativePhase::DecodeCollections);
    assert_eq!(
        Arc::strong_count(&shared),
        strong_count,
        "guard retains no owner"
    );
    success.rows(1, 37);
    success.finish();
    let mut incomplete = NativePhaseGuard::start(NativePhase::RetainedOutcomeValidation);
    incomplete.rows(2, 71);
    drop(incomplete);
    let mut saturated = NativePhaseGuard::start(NativePhase::LedgerValidation);
    saturated.rows(usize::MAX, usize::MAX);
    saturated.rows(1, 1);
    saturated.finish();
    assert_eq!(
        observer.count.load(Ordering::SeqCst),
        3,
        "exactly one receipt per guard"
    );
    let samples = lock(&observer.samples);
    let success = samples[0].unwrap();
    let incomplete = samples[1].unwrap();
    let saturated = samples[2].unwrap();
    assert_eq!((success.rows, success.bytes), (1, 37));
    assert!(success.completed && !success.saturated);
    assert_eq!((incomplete.rows, incomplete.bytes), (2, 71));
    assert!(!incomplete.completed && !incomplete.saturated);
    assert_eq!((saturated.rows, saturated.bytes), (usize::MAX, usize::MAX));
    assert!(saturated.completed && saturated.saturated);
    for sample in samples.iter().flatten() {
        assert!(sample.native_scope_entered_at <= sample.started_at);
        assert!(sample.started_at <= sample.finished_at);
    }
}

#[test]
fn config_capacity_native_phase_guard_ignores_inactive_and_expired_scopes() {
    let mut inactive = NativePhaseGuard::start(NativePhase::LedgerRowRead);
    assert!(inactive.active.is_none());
    inactive.rows(usize::MAX, usize::MAX);
    assert_eq!((inactive.rows, inactive.bytes), (0, 0));
    inactive.finish();
    let observer = Arc::new(Observer::default());
    let (scope, shared) = TestScope::start(observer.clone());
    let expired = NativePhaseGuard::start(NativePhase::ReadCanonicalCount);
    // A scope's diagnostic receipt cannot migrate to another generation,
    // including a later apply of the very same selected request.
    NATIVE.with(|slot| {
        slot.borrow_mut().as_mut().unwrap().entered_at += std::time::Duration::from_secs(1);
    });
    expired.finish();
    let detached = NativePhaseGuard::start(NativePhase::ReadCanonicalMac);
    let weak = Arc::downgrade(&shared);
    drop(shared);
    drop(scope);
    assert!(
        weak.upgrade().is_none(),
        "phase cannot retain native shared state"
    );
    detached.finish();
    assert_eq!(observer.count.load(Ordering::SeqCst), 0);
}
