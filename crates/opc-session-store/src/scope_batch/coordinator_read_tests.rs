//! Borrowed predicate contexts cannot allocate a second entitlement or outlive their builder.
use super::*;
use crate::scope_scheduler::{ClassBudget, ScopeSchedulerBudgets, ScopeSchedulerKey};
use std::time::Duration;
use tokio::time::{advance, Instant as Deadline};

struct ReadPort {
    model: Arc<Model>,
    reads: Mutex<Vec<(ScopeWorkClass, Deadline, Vec<ScopeChildKey>)>>,
    active: AtomicUsize,
    hold: AtomicBool,
    refuse_first: AtomicBool,
}

impl ReadPort {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            model: Model::new(),
            reads: Mutex::new(vec![]),
            active: AtomicUsize::new(0),
            hold: AtomicBool::new(false),
            refuse_first: AtomicBool::new(false),
        })
    }
}

struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl ScopeBatchPort for ReadPort {
    async fn reopen(&self, class: ScopeWorkClass) -> Result<ScopeBatchReopen, ScopeBatchError> {
        self.model.reopen(class).await
    }
    async fn apply(
        &self,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        self.model.apply(request, class).await
    }
    async fn cancel(
        &self,
        attempt: &ScopeBatchAttempt,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        self.model.cancel(attempt, class).await
    }
    async fn read_current(
        &self,
        request: &ScopeChildReadRequest,
        class: ScopeWorkClass,
        deadline: Deadline,
    ) -> Result<Vec<Option<ScopeChildRecord>>, ScopeChildReadError> {
        assert_eq!(request.stamp(), &self.model.stamp());
        self.reads
            .lock()
            .unwrap()
            .push((class, deadline, request.keys().to_vec()));
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = Active(&self.active);
        if self.hold.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.refuse_first.swap(false, Ordering::SeqCst) {
            return Err(ScopeChildReadError::ObservationTooLarge);
        }
        Ok(vec![None; request.keys().len()])
    }
}

#[tokio::test(start_paused = true)]
async fn child_read_builder_debits_refusals_and_inherits_class_at_running_grant() {
    let port = ReadPort::new();
    port.refuse_first.store(true, Ordering::SeqCst);
    let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
        ScopeWorkClass::Normal,
        ClassBudget {
            queued: 8,
            running: 1,
        },
    ))
    .unwrap();
    let scheduler = owner.scheduler();
    let batches = ScopeBatchCoordinator::open_with_backend(
        port.model.stamp(),
        scheduler.clone(),
        port.clone(),
        ScopeWorkClass::Normal,
    )
    .await
    .unwrap();
    let normal = scheduler
        .reserve(
            ScopeSchedulerKey::from_bytes([83; 32]),
            ScopeWorkClass::Normal,
        )
        .await
        .unwrap()
        .start()
        .await
        .unwrap();
    let reservation = batches
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap();
    let waiting = batches.reserve_lane(0, ScopeWorkClass::Emergency);
    tokio::pin!(waiting);
    assert!(poll!(&mut waiting).is_pending());
    let deadline = Deadline::now() + Duration::from_secs(20);
    let sooner = Deadline::now() + Duration::from_secs(10);
    let handle = reservation
        .submit_with_reads(
            ScopeBatchReadBudget::new(deadline, 2).unwrap(),
            move |mut read| {
                Box::pin(async move {
                    assert_eq!(
                        read.class(),
                        ScopeWorkClass::Emergency,
                        "inheritance fixes the effective class at running grant"
                    );
                    assert_eq!(
                        read.read_children(&[key(1), key(2)], deadline + Duration::from_secs(30))
                            .await,
                        Err(ScopeChildReadError::ObservationTooLarge)
                    );
                    assert_eq!(
                        read.read_children(&[key(1)], sooner).await.unwrap(),
                        vec![None]
                    );
                    assert_eq!(
                        read.read_children(&[key(2)], deadline).await,
                        Err(ScopeChildReadError::ReadBudgetExceeded),
                        "a refusal consumes one exchange and no automatic split occurs"
                    );
                    let n = scheduler.snapshot().class(ScopeWorkClass::Normal);
                    let e = scheduler.snapshot().class(ScopeWorkClass::Emergency);
                    assert_eq!((n.resident, n.running, e.resident, e.running), (2, 1, 1, 1));
                    read.build()
                        .request(
                            [93; 16],
                            vec![],
                            vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
                        )
                        .map_err(Into::into)
                })
            },
        )
        .await
        .unwrap();
    let done = handle.completion().await;
    assert!(matches!(
        done.outcome(),
        ScopeBatchCompletionOutcome::Applied(_)
    ));
    assert!(batches.ack(done.attempt()));
    assert_eq!(
        *port.reads.lock().unwrap(),
        vec![
            (ScopeWorkClass::Emergency, deadline, vec![key(1), key(2)]),
            (ScopeWorkClass::Emergency, sooner, vec![key(1)]),
        ]
    );
    assert_eq!(port.model.calls.lock().unwrap().len(), 1);
    assert_eq!(
        port.model.calls.lock().unwrap()[0].1,
        ScopeWorkClass::Emergency
    );
    drop(waiting.await.unwrap());
    drop(normal);
}

#[tokio::test(start_paused = true)]
async fn child_read_builder_deadline_and_cancellation_release_without_apply_or_cancel() {
    for mode in 0..3 {
        let port = ReadPort::new();
        port.hold.store(mode != 2, Ordering::SeqCst);
        let owner = ScopeSchedulerOwner::default();
        let scheduler = owner.scheduler();
        let batches = ScopeBatchCoordinator::open_with_backend(
            port.model.stamp(),
            scheduler.clone(),
            port.clone(),
            ScopeWorkClass::Normal,
        )
        .await
        .unwrap();
        let deadline = Deadline::now() + Duration::from_secs(1);
        let reservation = batches
            .reserve_lane(0, ScopeWorkClass::Normal)
            .await
            .unwrap();
        let mut building = Box::pin(reservation.submit_with_reads(
            ScopeBatchReadBudget::new(deadline, 2).unwrap(),
            move |mut read| {
                Box::pin(async move {
                    read.read_children(&[key(1)], deadline + Duration::from_secs(10))
                        .await?;
                    std::future::pending::<Result<ScopeBatchRequest, ScopeChildReadError>>().await
                })
            },
        ));
        assert!(poll!(&mut building).is_pending());
        assert_eq!(port.reads.lock().unwrap().len(), 1);
        assert_eq!(
            scheduler.snapshot().class(ScopeWorkClass::Normal).running,
            1
        );
        if mode != 1 {
            advance(Duration::from_secs(1)).await;
            assert_eq!(
                building.await.err(),
                Some(ScopeChildReadError::Batch(ScopeBatchError::Unavailable))
            );
        } else {
            drop(building);
        }
        assert_eq!(port.active.load(Ordering::SeqCst), 0);
        let snapshot = scheduler.snapshot().class(ScopeWorkClass::Normal);
        assert_eq!((snapshot.resident, snapshot.running), (0, 0));
        assert!(port.model.calls.lock().unwrap().is_empty());
        assert_eq!(port.model.cancels.load(Ordering::SeqCst), 0);
        assert!(!batches.lane_status()[0].occupied);
        drop(
            tokio::time::timeout(HANG_GUARD, batches.reserve_lane(0, ScopeWorkClass::Normal))
                .await
                .unwrap()
                .unwrap(),
        );
    }
}

#[tokio::test(start_paused = true)]
async fn child_read_builder_requires_an_explicit_bounded_exchange_budget() {
    let deadline = Deadline::now() + Duration::from_secs(1);
    for exchanges in [0, 65, usize::MAX] {
        assert_eq!(
            ScopeBatchReadBudget::new(deadline, exchanges).err(),
            Some(ScopeChildReadError::Batch(ScopeBatchError::InvalidRequest))
        );
    }
    for exchanges in [1, 32, 64] {
        assert!(ScopeBatchReadBudget::new(deadline, exchanges).is_ok());
    }
}
