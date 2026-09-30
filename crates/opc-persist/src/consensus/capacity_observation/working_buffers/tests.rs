use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn identity(value: u8) -> ConsensusIdentity {
    ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([value; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0xDA; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn node() -> ConsensusNodeId {
    ConsensusNodeId::new(1).unwrap()
}

struct DropValue {
    bytes: Vec<u8>,
    dropped: Option<Arc<AtomicBool>>,
}
impl Vacate for DropValue {
    fn vacate(&mut self) -> Self {
        Self {
            bytes: std::mem::take(&mut self.bytes),
            dropped: self.dropped.take(),
        }
    }
}
impl Drop for DropValue {
    fn drop(&mut self) {
        if let Some(dropped) = &self.dropped {
            dropped.store(true, Ordering::SeqCst);
        }
    }
}

#[test]
fn capacity_working_buffers_drop_barrier_protects_actual_owner() {
    let census = Arc::new(WorkingBufferCensus::default());
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let observer = Arc::new(Blocked {
        retirement: Mutex::new(Some(started_tx)),
        allocation: Mutex::new(None),
    });
    let registration = census
        .observe_source(identity(0xDB), node(), Some(observer))
        .unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let bytes = Vec::<u8>::with_capacity(137);
    let capacity = bytes.capacity();
    let mut inventory = Inventory {
        values: Allocations::new(),
        limit: 4,
        issues: WorkingBufferIssues::default(),
    };
    inventory.vector(&bytes);
    let observation = Observation::start(
        registration.shared.clone(),
        None,
        WorkingBufferKind::RecoveryOutput,
        None,
        inventory,
    );
    let owner = Observed::new(
        DropValue {
            bytes,
            dropped: Some(dropped.clone()),
        },
        observation,
    );
    let (worker, protected) = census.with_current_capture(|capture| {
        let worker = std::thread::spawn(move || drop(owner));
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let sample = capture.sample();
        assert_eq!(sample.bytes, capacity);
        assert_eq!(sample.owners.len(), 1);
        let protected = !dropped.load(Ordering::SeqCst);
        (worker, protected)
    });
    worker.join().unwrap();
    let after = census.with_current_capture(|capture| capture.sample());
    assert!(dropped.load(Ordering::SeqCst));
    assert!(after.owners.is_empty());
    assert_eq!(after.bytes, 0);
    assert!(after.issues.complete());
    drop(registration);
    eprintln!(
        "CAPACITY_WORKING_CLEANUP drop owners={} bytes={}",
        after.owners.len(),
        after.bytes
    );
    assert!(
        protected,
        "CAPACITY_WORKING_DROP_RED: capture bars actual last-owner destructor"
    );
}

#[test]
fn capacity_working_buffers_union_uses_authority_and_detects_inconsistent_extents() {
    let census = Arc::new(WorkingBufferCensus::default());
    let first = census.observe_source(identity(0xDC), node(), None).unwrap();
    let other = census.observe_source(identity(0xDD), node(), None).unwrap();
    let encoded = vec![1_u8; 91];
    let mut inventory = Inventory {
        values: Allocations::new(),
        limit: 4,
        issues: WorkingBufferIssues::default(),
    };
    inventory.vector(&encoded);
    let original = inventory.values.clone();
    let observation = Observation::start(
        first.shared.clone(),
        None,
        WorkingBufferKind::RecoveryOutput,
        None,
        inventory,
    );
    let owner = Observed::new(encoded, observation);
    let (same, foreign, inconsistent) = census.with_current_capture(|capture| {
        let same = capture.join(&AllocationView::new(identity(0xDC), node(), &original));
        let foreign = capture.join(&AllocationView::new(
            identity(0xDD),
            node(),
            &Allocations::new(),
        ));
        let wrong = original
            .iter()
            .map(|(&address, &bytes)| (address, bytes + 1))
            .collect();
        let inconsistent = capture.join(&AllocationView::new(identity(0xDC), node(), &wrong));
        (same, foreign, inconsistent)
    });
    drop(owner);
    assert!(census
        .with_current_capture(|capture| capture.sample())
        .owners
        .is_empty());
    eprintln!("CAPACITY_WORKING_CLEANUP authority owners=0 bytes=0");
    assert_eq!(same.working_bytes, 91);
    assert_eq!(same.shared_bytes, 91);
    assert_eq!(same.union_bytes, 91);
    assert!(same.issues.complete());
    assert_eq!(foreign.working_bytes, 0, "CAPACITY_WORKING_AUTHORITY_RED");
    assert!(foreign.issues.complete());
    assert!(inconsistent.issues.inconsistent_extents);
    drop((first, other));
}

#[test]
fn capacity_working_buffers_metadata_limits_and_arithmetic_fail_closed() {
    let census = Arc::new(WorkingBufferCensus::new(WorkingBufferLimits {
        owners: 0,
        allocations_per_owner: 0,
    }));
    assert!(census
        .observe_source(identity(0xDE), node(), None)
        .is_none());
    assert!(
        census
            .with_current_capture(|capture| capture.sample())
            .issues
            .metadata_saturated
    );
    let mut inventory = Inventory {
        values: Allocations::new(),
        limit: 0,
        issues: WorkingBufferIssues::default(),
    };
    inventory.vector(&vec![1_u8; 32]);
    assert!(inventory.issues.metadata_saturated);
    assert!(!inventory.issues.complete());
    let mut issues = WorkingBufferIssues::default();
    assert_eq!(
        sum(&BTreeMap::from([(1, usize::MAX), (2, 1)]), &mut issues),
        usize::MAX
    );
    assert!(issues.arithmetic_overflow);
}

struct Blocked {
    retirement: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    allocation: Mutex<Option<std::sync::mpsc::Sender<usize>>>,
}
impl WorkingBufferObserver for Blocked {
    fn observe(&self, _: WorkingBufferStage, _: WorkingBufferOwner) {}
    fn retirement_blocked(&self) {
        if let Some(sender) = lock(&self.retirement).take() {
            sender.send(()).unwrap();
        }
    }
    fn allocation_blocked(&self, bytes: usize) {
        if let Some(sender) = lock(&self.allocation).take() {
            sender.send(bytes).unwrap();
        }
    }
}

#[test]
fn capacity_working_buffers_clone_birth_is_inside_capture_barrier() {
    let census = Arc::new(WorkingBufferCensus::default());
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let observer = Arc::new(Blocked {
        retirement: Mutex::new(None),
        allocation: Mutex::new(Some(blocked_tx)),
    });
    let registration = census
        .observe_source(identity(0xDF), node(), Some(observer))
        .unwrap();
    let original = ConfigMutationIntent::CreateRollbackPoint {
        tx_id: opc_types::TxId::new(),
        label: Some(
            crate::consensus::types::ValidatedRollbackLabel::try_new("synthetic".to_owned())
                .unwrap(),
        ),
    };
    let created = Arc::new(AtomicBool::new(false));
    let observed = created.clone();
    let (worker, protected) = census.with_current_capture(|capture| {
        let worker = std::thread::spawn(move || {
            Observed::create_intent(
                identity(0xDF),
                node(),
                ConsensusRequestId::new(),
                WorkingBufferKind::LocalAttempt,
                || {
                    let actual_clone = original.clone();
                    observed.store(true, Ordering::SeqCst);
                    actual_clone
                },
                |value| value,
            )
        });
        assert_eq!(blocked_rx.recv_timeout(Duration::from_secs(10)).unwrap(), 0);
        let protected = !created.load(Ordering::SeqCst);
        let sample = capture.sample();
        assert!(sample.owners.is_empty() && sample.issues.complete());
        (worker, protected)
    });
    let owner = worker.join().unwrap();
    let sample = census.with_current_capture(|capture| capture.sample());
    drop(owner);
    let clean = census.with_current_capture(|capture| capture.sample());
    drop(registration);
    assert_eq!(sample.bytes, "synthetic".len());
    assert!(clean.owners.is_empty());
    eprintln!(
        "CAPACITY_WORKING_CLEANUP birth owners={} bytes={}",
        clean.owners.len(),
        clean.bytes
    );
    assert!(
        protected,
        "CAPACITY_WORKING_BIRTH_RED: actual clone waits for capture barrier"
    );
}

#[test]
fn capacity_working_buffers_historical_sources_saturate_metadata() {
    let census = Arc::new(WorkingBufferCensus::new(WorkingBufferLimits {
        owners: 1,
        allocations_per_owner: 1,
    }));
    for value in [0xE0, 0xE1] {
        let registration = census
            .observe_source(identity(value), node(), None)
            .unwrap();
        let intent = ConfigMutationIntent::MarkConfirmed {
            tx_id: opc_types::TxId::new(),
        };
        let observation = Observation::intent(
            identity(value),
            node(),
            ConsensusRequestId::new(),
            WorkingBufferKind::FinalizedCommand,
            &intent,
        );
        let command = Observed::new(intent, observation).into_engine();
        drop(command);
        drop(registration);
    }
    let clean = census.with_current_capture(|capture| capture.sample());
    assert!(clean.owners.is_empty() && clean.registrations == 0);
    assert!(lock(&census.state).engine_transfers.len() <= 1);
    assert!(
        clean.issues.metadata_saturated,
        "CAPACITY_WORKING_HISTORY_RED"
    );
}
