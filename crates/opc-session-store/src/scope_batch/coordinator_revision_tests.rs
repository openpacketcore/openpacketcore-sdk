//! Revision diagnostics never decide a pending attempt or create a hot probe loop.
use super::*;
use std::time::Duration;
use tokio::time::{advance, Instant};

struct RevisionPort {
    model: Arc<Model>,
    committed_first: bool,
    begun: AtomicBool,
    recovered: AtomicBool,
    faults: Mutex<Vec<Instant>>,
    fault_count: watch::Sender<usize>,
    requests: Mutex<Vec<Vec<u8>>>,
}

impl RevisionPort {
    fn fault(&self) -> ScopeBatchError {
        let count = {
            let mut faults = self.faults.lock().unwrap();
            faults.push(Instant::now());
            faults.len()
        };
        self.fault_count.send_replace(count);
        ScopeBatchError::TransportRevisionMismatch
    }
}

#[async_trait]
impl ScopeBatchPort for RevisionPort {
    async fn reopen(&self, class: ScopeWorkClass) -> Result<ScopeBatchReopen, ScopeBatchError> {
        if self.begun.load(Ordering::SeqCst) && !self.recovered.load(Ordering::SeqCst) {
            return Err(self.fault());
        }
        self.model.reopen(class).await
    }

    async fn apply(
        &self,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        self.requests
            .lock()
            .unwrap()
            .push(request.encode_canonical()?);
        let first = !self.begun.swap(true, Ordering::SeqCst);
        if first && self.committed_first {
            self.model.apply(request, class).await?;
            return Err(ScopeBatchError::OutcomeUnknown);
        }
        if !self.recovered.load(Ordering::SeqCst) {
            return Err(self.fault());
        }
        self.model.apply(request, class).await
    }

    async fn cancel(
        &self,
        attempt: &ScopeBatchAttempt,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        self.model.cancel(attempt, class).await
    }
}

#[tokio::test(start_paused = true)]
async fn coordinator_revision_mismatch_retains_exact_attempt_and_probes_at_most_every_thirty_seconds(
) {
    // An initial typed failure, a mismatch resolving a lost committed reply,
    // and an explicit cancellation wake all obey the same probe minimum.
    for (committed_first, request_cancel) in [(false, false), (true, false), (false, true)] {
        let port = Arc::new(RevisionPort {
            model: Model::new(),
            committed_first,
            begun: AtomicBool::new(false),
            recovered: AtomicBool::new(false),
            faults: Mutex::new(vec![]),
            fault_count: watch::channel(0).0,
            requests: Mutex::new(vec![]),
        });
        let owner = ScopeSchedulerOwner::default();
        let batches = ScopeBatchCoordinator::open_with_backend(
            port.model.stamp(),
            owner.scheduler(),
            port.clone(),
            ScopeWorkClass::Normal,
        )
        .await
        .unwrap();
        let mut fault_count = port.fault_count.subscribe();
        let handle = batches
            .reserve_lane(0, ScopeWorkClass::Normal)
            .await
            .unwrap()
            .submit(|build| async move {
                build.request(
                    [111; 16],
                    vec![],
                    vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
                )
            })
            .await
            .unwrap();
        tokio::time::timeout(HANG_GUARD, async {
            while *fault_count.borrow_and_update() < 1 {
                fault_count.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let exact = handle.attempt().clone();
        for second in 1..30 {
            if request_cancel && second == 1 {
                assert!(
                    handle.cancel(),
                    "explicit user cancellation is retained without bypassing the probe minimum"
                );
            }
            advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            assert_eq!(
                port.faults.lock().unwrap().len(),
                1,
                "no immediate reconnect or background retry before thirty seconds"
            );
            let lane = &batches.lane_status()[0];
            assert!(lane.occupied);
            assert!(
                lane.oldest_unacknowledged.is_none(),
                "mismatch never infers a terminal outcome"
            );
            assert_eq!(
                lane.last_error,
                Some(ScopeBatchError::TransportRevisionMismatch)
            );
            assert!(
                !batches.ack(&exact),
                "an unresolved exact attempt cannot be acknowledged"
            );
            assert_eq!(
                port.model.cancels.load(Ordering::SeqCst),
                0,
                "mismatch never authorizes cancellation"
            );
            let credits = owner.scheduler().snapshot().class(ScopeWorkClass::Normal);
            assert_eq!(
                (credits.resident, credits.running),
                (1, 0),
                "retain original payload credit while the probe sleeps"
            );
        }
        advance(Duration::from_secs(1)).await;
        tokio::time::timeout(HANG_GUARD, async {
            while *fault_count.borrow_and_update() < 2 {
                fault_count.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        {
            let faults = port.faults.lock().unwrap();
            assert_eq!(faults.len(), 2);
            assert!(faults[1].duration_since(faults[0]) >= Duration::from_secs(30));
        }
        port.recovered.store(true, Ordering::SeqCst);
        advance(Duration::from_secs(30)).await;
        let done = tokio::time::timeout(HANG_GUARD, handle.completion())
            .await
            .unwrap();
        assert_eq!(done.attempt(), &exact);
        assert_eq!(
            done.refusal(),
            None,
            "a transport revision problem is never a committed refusal"
        );
        if request_cancel {
            assert!(matches!(
                done.outcome(),
                ScopeBatchCompletionOutcome::Cancelled
            ));
            assert_eq!(port.model.cancels.load(Ordering::SeqCst), 1);
        } else {
            assert!(matches!(
                done.outcome(),
                ScopeBatchCompletionOutcome::Applied(_)
            ));
            assert_eq!(port.model.cancels.load(Ordering::SeqCst), 0);
            assert_eq!(
                port.model.calls.lock().unwrap().len(),
                1,
                "exact readback resolves a lost committed reply without applying twice"
            );
        }
        let requests = port.requests.lock().unwrap();
        assert!(!requests.is_empty());
        assert!(
            requests.iter().all(|request| request == &requests[0]),
            "recovery retains exact original bytes"
        );
        assert!(
            batches.lane_status()[0].occupied,
            "completion still requires explicit reconciliation and acknowledgement"
        );
        assert!(batches.ack(&exact));
        assert!(!batches.lane_status()[0].occupied);
        assert_eq!(
            owner
                .scheduler()
                .snapshot()
                .class(ScopeWorkClass::Normal)
                .resident,
            0
        );
    }
}
