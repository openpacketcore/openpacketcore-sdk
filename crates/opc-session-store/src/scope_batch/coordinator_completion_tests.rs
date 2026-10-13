//! Completion metadata retains the original class and pins reconciliation before ack.
use super::*;

struct ContextPort(Arc<Model>);

#[async_trait]
impl ScopeBatchPort for ContextPort {
    async fn reopen(&self, class: ScopeWorkClass) -> Result<ScopeBatchReopen, ScopeBatchError> {
        self.0.reopen(class).await
    }
    async fn apply(
        &self,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        self.0.apply(request, class).await
    }
    async fn cancel(
        &self,
        attempt: &ScopeBatchAttempt,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        self.0.cancel(attempt, class).await
    }
    fn completion_context(
        &self,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
        outcome: &ScopeBatchCompletionOutcome,
        retention: ScopeBatchCompletionRetention,
    ) -> Option<ScopeBatchCompletionContext> {
        Some(ScopeBatchCompletionContext::new((
            request.clone(),
            class,
            outcome.clone(),
            retention,
        )))
    }
}

type Facts = (
    ScopeBatchRequest,
    ScopeWorkClass,
    ScopeBatchCompletionOutcome,
    ScopeBatchCompletionRetention,
);

#[tokio::test(start_paused = true)]
async fn completion_context_keeps_original_class_and_ack_waits_for_readback() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    let batches = ScopeBatchCoordinator::open_with_backend(
        model.stamp(),
        owner.scheduler(),
        Arc::new(ContextPort(model.clone())),
        ScopeWorkClass::Normal,
    )
    .await
    .unwrap();
    let reservation = batches
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap();
    let waiting = batches.reserve_lane(0, ScopeWorkClass::Emergency);
    tokio::pin!(waiting);
    assert!(poll!(&mut waiting).is_pending());
    let handle = reservation
        .submit(|context| async move { context.request([102; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    let done = handle.completion().await;
    let (request, class, outcome, retention) =
        done.context().unwrap().downcast_ref::<Facts>().unwrap();
    assert_eq!(
        *class,
        ScopeWorkClass::Normal,
        "inheritance never retags the effect"
    );
    assert_eq!(model.calls.lock().unwrap()[0].1, ScopeWorkClass::Emergency);
    assert_eq!(request.attempt().unwrap(), *done.attempt());
    assert_eq!(outcome, done.outcome());
    assert!(retention.is_same(done.retention().unwrap()));
    let pin = retention
        .acquire()
        .expect("unacknowledged completion must pin");
    let another = retention.acquire().unwrap();
    assert!(
        !batches.ack(done.attempt()),
        "readback still owns its receipt"
    );
    drop(pin);
    assert!(
        !batches.ack(done.attempt()),
        "every active readback must finish"
    );
    assert!(poll!(&mut waiting).is_pending());
    drop(another);
    assert!(batches.ack(done.attempt()));
    assert!(
        retention.acquire().is_none(),
        "saved completion cannot revive early ack"
    );
    assert!(done.retention().unwrap().acquire().is_none());
    assert!(handle
        .completion()
        .await
        .retention()
        .unwrap()
        .acquire()
        .is_none());
    drop(waiting.await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn completion_context_is_absent_for_legacy_ports_and_bare_receipts() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    let batches = coordinator(&model, &owner).await;
    let handle = batches
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([103; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    let done = handle.completion().await;
    assert!(done.context().is_none());
    let receipt = model
        .state
        .lock()
        .unwrap()
        .checkpoint
        .receipt(0)
        .unwrap()
        .clone();
    let recovered = ScopeBatchCompletion::from_receipt(receipt).unwrap();
    assert_eq!(
        recovered, done,
        "observed facts remain comparable without capability metadata"
    );
    assert!(recovered.context().is_none());
    assert!(recovered.retention().is_none());
    assert!(batches.ack(done.attempt()));
}
