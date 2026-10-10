use super::*;
use crate::scope_scheduler::{ScopeSchedulerOwner, ScopeWorkClass};
use async_trait::async_trait;
use futures_util::poll;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::{watch, Notify};

// These tests use paused time. This only catches a hung event path; it is not
// an elapsed-time bound on admission, retries or backend progress.
const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(60);

struct Model {
    state: Mutex<State>,
    calls: Mutex<Vec<(ScopeBatchAttempt, ScopeWorkClass)>>,
    cancels: AtomicUsize,
    cuts: Mutex<Vec<ScopeWorkClass>>,
    reopened: watch::Sender<usize>,
    cancel_classes: Mutex<Vec<ScopeWorkClass>>,
    hold_first: AtomicBool,
    hold_all: AtomicBool,
    outage: AtomicBool,
    all_entered: watch::Sender<usize>,
    unknown_returns: watch::Sender<usize>,
    release_all: Notify,
    unknown_first: AtomicBool,
    conflicts: AtomicBool,
    entered: Notify,
    release: Notify,
}

impl Model {
    fn new() -> Arc<Self> {
        static NEXT_SCOPE: AtomicUsize = AtomicUsize::new(1);
        let mut wire = serde_json::to_value(scope()).unwrap();
        let mut slot = [0; 32];
        slot[..8]
            .copy_from_slice(&(NEXT_SCOPE.fetch_add(1, Ordering::SeqCst) as u64).to_be_bytes());
        wire["slot"] = serde_json::to_value(slot).unwrap();
        let scope: ScopeId = serde_json::from_value(wire).unwrap();
        let authority = ScopeState::empty(scope.clone())
            .transition(
                &crate::scope_authority::ScopeAuthorityRequest::new(
                    scope.clone(),
                    [1; 16],
                    0,
                    crate::scope_authority::ScopeAuthorityOperation::AdmitInitial {
                        execution: crate::scope_authority::tests::execution(1),
                    },
                )
                .unwrap(),
            )
            .unwrap();
        Arc::new(Self {
            state: Mutex::new(State {
                authority,
                checkpoint: ScopeBatchCheckpoint::empty(scope),
                rows: HashMap::new(),
            }),
            calls: Mutex::new(Vec::new()),
            cancels: AtomicUsize::new(0),
            cuts: Mutex::new(Vec::new()),
            reopened: watch::channel(0).0,
            cancel_classes: Mutex::new(Vec::new()),
            hold_first: AtomicBool::new(false),
            hold_all: AtomicBool::new(false),
            outage: AtomicBool::new(false),
            all_entered: watch::channel(0).0,
            unknown_returns: watch::channel(0).0,
            release_all: Notify::new(),
            unknown_first: AtomicBool::new(false),
            conflicts: AtomicBool::new(false),
            entered: Notify::new(),
            release: Notify::new(),
        })
    }
    fn stamp(&self) -> ScopeAuthorityStamp {
        self.state
            .lock()
            .unwrap()
            .authority
            .view
            .stamp()
            .unwrap()
            .clone()
    }
}

#[async_trait]
impl ScopeBatchPort for Model {
    async fn reopen(&self, class: ScopeWorkClass) -> Result<ScopeBatchReopen, ScopeBatchError> {
        self.cuts.lock().unwrap().push(class);
        self.reopened.send_modify(|count| *count += 1);
        if self.outage.load(Ordering::SeqCst) {
            return Err(ScopeBatchError::Unavailable);
        }
        let state = self.state.lock().unwrap();
        ScopeBatchReadCut::new(
            state.authority.view.scope(),
            Some(state.authority.clone()),
            Some(state.checkpoint.clone()),
        )
        .map(|cut| cut.reopen())
    }
    async fn apply(
        &self,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        let first = {
            let mut calls = self.calls.lock().unwrap();
            calls.push((request.attempt()?, class));
            calls.len() == 1
        };
        if self.hold_all.load(Ordering::SeqCst) {
            let released = self.release_all.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            self.all_entered.send_modify(|count| *count += 1);
            released.await;
        }
        if self.outage.load(Ordering::SeqCst) {
            self.unknown_returns.send_modify(|count| *count += 1);
            return Err(ScopeBatchError::OutcomeUnknown);
        }
        if first && self.hold_first.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if first && self.unknown_first.load(Ordering::SeqCst) {
            self.unknown_returns.send_modify(|count| *count += 1);
            return Err(ScopeBatchError::OutcomeUnknown);
        }
        if self.conflicts.load(Ordering::SeqCst) {
            return Err(ScopeBatchError::RevisionConflict);
        }
        self.state.lock().unwrap().apply(&ScopeBatchCommand {
            request: request.clone(),
        })
    }
    async fn cancel(
        &self,
        attempt: &ScopeBatchAttempt,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        self.cancel_classes.lock().unwrap().push(class);
        self.cancels.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap();
        let plan = ScopeBatchCancelCommand {
            attempt: attempt.clone(),
        }
        .plan(&state.authority, &state.checkpoint)?;
        state.rows.extend(plan.rows);
        state.checkpoint = plan.checkpoint;
        Ok(state.checkpoint.receipt(attempt.lane()).unwrap().clone())
    }
}

async fn coordinator(model: &Arc<Model>, owner: &ScopeSchedulerOwner) -> ScopeBatchCoordinator {
    ScopeBatchCoordinator::open_with_backend(
        model.stamp(),
        owner.scheduler(),
        model.clone(),
        ScopeWorkClass::Normal,
    )
    .await
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn coordinator_factories_share_lanes_and_reserve_seven_for_established_emergency() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    let first = coordinator(&model, &owner).await;
    let second = coordinator(&model, &owner).await;
    assert!(first.reserve(ScopeWorkClass::SafetyControl).await.is_err());
    assert!(first
        .reserve_lane(7, ScopeWorkClass::EmergencyClassification)
        .await
        .is_err());
    let mut held = Vec::new();
    for lane in 0..7 {
        held.push(
            first
                .reserve_lane(lane, ScopeWorkClass::Normal)
                .await
                .unwrap(),
        );
    }
    let waiting = second.reserve(ScopeWorkClass::Normal);
    tokio::pin!(waiting);
    assert!(poll!(&mut waiting).is_pending());
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Normal)
            .resident,
        8
    );
    let emergency = tokio::time::timeout(HANG_GUARD, second.reserve(ScopeWorkClass::Emergency))
        .await
        .expect("reserved Emergency lane must progress with shared lanes full")
        .unwrap();
    assert_eq!(emergency.lane(), 7);
    assert!(
        model.calls.lock().unwrap().is_empty(),
        "lane waiters have built no request"
    );
    drop(held.remove(2));
    assert_eq!(waiting.await.unwrap().lane(), 2);
}

#[tokio::test(start_paused = true)]
async fn coordinator_dropped_observer_keeps_request_lane_and_terminal_until_exact_ack() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.hold_first.store(true, Ordering::SeqCst);
    let coordinator = coordinator(&model, &owner).await;
    let handle = coordinator
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([2; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    model.entered.notified().await;
    let attempt = handle.attempt().clone();
    drop(handle);
    let waiting = coordinator.reserve_lane(0, ScopeWorkClass::Normal);
    tokio::pin!(waiting);
    assert!(poll!(&mut waiting).is_pending());
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Normal)
            .resident,
        2
    );
    model.release.notify_one();
    let mut stream = coordinator.completions();
    let terminal = stream.next().await;
    assert_eq!(terminal.attempt(), &attempt);
    assert!(matches!(
        terminal.outcome(),
        ScopeBatchCompletionOutcome::Applied(_)
    ));
    assert_eq!(stream.next().await, terminal, "delivery is at least once");
    assert!(
        poll!(&mut waiting).is_pending(),
        "terminal observation does not acknowledge"
    );
    assert!(coordinator.lane_status()[0].oldest_unacknowledged.is_some());
    let mut wrong = attempt.clone();
    wrong.request_id[0] ^= 1;
    assert!(!coordinator.ack(&wrong));
    assert!(poll!(&mut waiting).is_pending());
    assert!(coordinator.ack(&attempt));
    assert!(coordinator.lane_status()[0].oldest_unacknowledged.is_none());
    assert_eq!(waiting.await.unwrap().lane(), 0);
    assert!(!coordinator.ack(&attempt));
}

#[tokio::test(start_paused = true)]
async fn coordinator_cancellation_after_unknown_consumes_original_attempt_only() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.hold_first.store(true, Ordering::SeqCst);
    model.unknown_first.store(true, Ordering::SeqCst);
    let coordinator = coordinator(&model, &owner).await;
    let handle = coordinator
        .reserve_lane(7, ScopeWorkClass::Emergency)
        .await
        .unwrap()
        .submit(|context| async move { context.request([3; 16], vec![create(1, &[1])], vec![]) })
        .await
        .unwrap();
    model.entered.notified().await;
    assert!(handle.cancel());
    model.release.notify_one();
    let completion = handle.completion().await;
    assert_eq!(
        completion.outcome(),
        &ScopeBatchCompletionOutcome::Cancelled
    );
    assert_eq!(model.cancels.load(Ordering::SeqCst), 1);
    assert_eq!(model.calls.lock().unwrap().len(), 1);
    let state = model.state.lock().unwrap();
    assert!(state.child(1).is_none());
    assert_eq!(state.checkpoint.revision, 1);
    drop(state);
    assert!(coordinator.ack(handle.attempt()));
}

#[tokio::test(start_paused = true)]
async fn coordinator_guard_stalls_after_sixteen_resolved_and_acknowledged_conflicts() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.conflicts.store(true, Ordering::SeqCst);
    let coordinator = coordinator(&model, &owner).await;
    let reconciling = coordinator.clone();
    let reconcile = tokio::spawn(async move {
        let mut stream = reconciling.completions();
        for _ in 0..16 {
            let result = stream.next().await;
            assert_eq!(result.outcome(), &ScopeBatchCompletionOutcome::Cancelled);
            assert!(reconciling.ack(result.attempt()));
        }
    });
    let mut id = 1u8;
    let result = tokio::time::timeout(
        HANG_GUARD,
        coordinator.execute_guarded(ScopeWorkClass::Normal, move |context| {
            id += 1;
            async move { context.request([id; 16], vec![create(1, &[])], vec![]) }
        }),
    )
    .await
    .expect("sixteen conflicts must resolve within the bounded retry schedule");
    assert_eq!(result, Err(ScopeBatchError::ScopeGuardStalled));
    reconcile.await.unwrap();
    assert_eq!(model.calls.lock().unwrap().len(), 16);
    assert_eq!(model.cancels.load(Ordering::SeqCst), 16);
    assert_eq!(model.state.lock().unwrap().checkpoint.revision, 16);
    assert!(coordinator.lane_status().iter().all(|lane| !lane.occupied));
}
#[tokio::test(start_paused = true)]
async fn coordinator_retry_inherits_a_later_emergency_waiter_without_reserving_again() {
    use crate::scope_scheduler::{ClassBudget, ScopeSchedulerBudgets, ScopeSchedulerKey};
    let model = Model::new();
    let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default().with_budget(
        ScopeWorkClass::Normal,
        ClassBudget {
            queued: 8,
            running: 1,
        },
    ))
    .unwrap();
    model.hold_first.store(true, Ordering::SeqCst);
    model.unknown_first.store(true, Ordering::SeqCst);
    let coordinator = coordinator(&model, &owner).await;
    let handle = coordinator
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([2; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    model.entered.notified().await;
    let resident = owner
        .scheduler()
        .reserve(
            ScopeSchedulerKey::from_bytes([99; 32]),
            ScopeWorkClass::Normal,
        )
        .await
        .unwrap();
    let running = resident.start();
    tokio::pin!(running);
    assert!(poll!(&mut running).is_pending());
    model.release.notify_one();
    let occupied = running.await.unwrap();
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Normal)
            .resident,
        2
    );
    let emergency = coordinator.reserve_lane(0, ScopeWorkClass::Emergency);
    tokio::pin!(emergency);
    assert!(poll!(&mut emergency).is_pending());
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Emergency)
            .resident,
        1,
        "the waiter owns one resident credit; the holder retains only its original credit"
    );
    let completed = tokio::time::timeout(HANG_GUARD, handle.completion())
        .await
        .unwrap();
    assert!(matches!(
        completed.outcome(),
        ScopeBatchCompletionOutcome::Applied(_)
    ));
    {
        let calls = model.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], (handle.attempt().clone(), ScopeWorkClass::Normal));
        assert_eq!(
            calls[1],
            (handle.attempt().clone(), ScopeWorkClass::Emergency)
        );
    }
    assert!(coordinator.ack(handle.attempt()));
    assert_eq!(emergency.await.unwrap().lane(), 0);
    drop(occupied);
}

#[tokio::test(start_paused = true)]
async fn coordinator_reopen_redelivers_receipts_and_reconnect_preserves_observation_age() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    let request =
        ScopeBatchRequest::in_lane(&model.stamp(), [2; 16], 3, 1, vec![create(1, &[])], vec![])
            .unwrap();
    model
        .state
        .lock()
        .unwrap()
        .apply(&ScopeBatchCommand {
            request: request.clone(),
        })
        .unwrap();
    let first = coordinator(&model, &owner).await;
    let mut stream = first.completions();
    let recovered = tokio::time::timeout(HANG_GUARD, stream.next())
        .await
        .expect("the stored receipt must be redelivered");
    assert_eq!(recovered.attempt(), &request.attempt().unwrap());
    let age = first.lane_status()[3].oldest_unacknowledged.unwrap();
    drop(stream);
    drop(first);
    let second = coordinator(&model, &owner).await;
    assert!(second.lane_status()[3].oldest_unacknowledged.unwrap() >= age);
    assert_eq!(
        tokio::time::timeout(HANG_GUARD, second.completions().next())
            .await
            .expect("reconnecting must preserve the pending receipt"),
        recovered
    );
    let waiting = second.reserve_lane(3, ScopeWorkClass::Normal);
    tokio::pin!(waiting);
    assert!(poll!(&mut waiting).is_pending());
    assert!(second.ack(recovered.attempt()));
    let handle = waiting
        .await
        .unwrap()
        .submit(|context| async move {
            assert_eq!(context.sequence(), 2);
            context.request([3; 16], vec![create(2, &[])], vec![])
        })
        .await
        .unwrap();
    let next = handle.completion().await;
    assert_ne!(next.attempt(), recovered.attempt());
    assert!(!second.ack(recovered.attempt()));
    assert!(second.ack(next.attempt()));
}

#[tokio::test(start_paused = true)]
async fn coordinator_unknown_attempt_requires_a_same_cut_no_apply_proof_after_close() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.hold_first.store(true, Ordering::SeqCst);
    model.unknown_first.store(true, Ordering::SeqCst);
    let coordinator = coordinator(&model, &owner).await;
    let handle = coordinator
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([2; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    model.entered.notified().await;
    {
        use crate::scope_authority::{
            ScopeAuthorityOperation, ScopeAuthorityRequest, ScopeClosureKind,
        };
        let mut state = model.state.lock().unwrap();
        let close = ScopeAuthorityRequest::new(
            state.authority.view.scope().clone(),
            [9; 16],
            state.authority.view.revision(),
            ScopeAuthorityOperation::Close {
                current: state.authority.view.stamp().unwrap().clone(),
                evidence: crate::scope_authority::tests::evidence(
                    ScopeClosureKind::LocalQuiescence,
                    9,
                ),
            },
        )
        .unwrap();
        state.authority = state.authority.transition(&close).unwrap();
    }
    assert!(
        !coordinator.ack(handle.attempt()),
        "neither closure intent nor elapsed time acknowledges an unknown result"
    );
    model.release.notify_one();
    let completed = handle.completion().await;
    let ScopeBatchCompletionOutcome::NotApplied(proof) = completed.outcome() else {
        panic!("positive same-cut no-apply proof required");
    };
    assert!(proof.matches(handle.attempt()));
    assert!(!proof.authority().is_active());
    assert_eq!(proof.revision(), 0);
    assert_eq!(model.calls.lock().unwrap().len(), 1);
    assert_eq!(model.cancels.load(Ordering::SeqCst), 0);
    assert!(coordinator.ack(handle.attempt()));
}

#[tokio::test(start_paused = true)]
async fn coordinator_port_receives_emergency_for_reopen_apply_and_cancel() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.unknown_first.store(true, Ordering::SeqCst);
    model.hold_first.store(true, Ordering::SeqCst);
    let shared = coordinator(&model, &owner).await;
    let handle = shared
        .reserve(ScopeWorkClass::Emergency)
        .await
        .unwrap()
        .submit(|context| async move { context.request([40; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    model.entered.notified().await;
    handle.cancel();
    model.release.notify_one();
    let completion = tokio::time::timeout(HANG_GUARD, handle.completion())
        .await
        .unwrap();
    assert!(matches!(
        completion.outcome(),
        ScopeBatchCompletionOutcome::Cancelled
    ));
    assert!(model
        .cuts
        .lock()
        .unwrap()
        .contains(&ScopeWorkClass::Emergency));
    assert!(model
        .cancel_classes
        .lock()
        .unwrap()
        .iter()
        .all(|class| *class == ScopeWorkClass::Emergency));
    assert_eq!(
        *model.calls.lock().unwrap(),
        [(handle.attempt().clone(), ScopeWorkClass::Emergency)]
    );
    assert_eq!(model.cancel_classes.lock().unwrap().len(), 1);
    assert!(shared.ack(completion.attempt()));
}

#[tokio::test(start_paused = true)]
async fn coordinator_all_lanes_recover_with_full_resident_budgets_and_waiting_producers() {
    use crate::scope_scheduler::{ClassBudget, ScopeSchedulerBudgets};
    let model = Model::new();
    model.hold_all.store(true, Ordering::SeqCst);
    let owner = ScopeSchedulerOwner::new(
        ScopeSchedulerBudgets::default()
            .with_budget(
                ScopeWorkClass::Normal,
                ClassBudget {
                    queued: 14,
                    running: 14,
                },
            )
            .with_budget(
                ScopeWorkClass::Emergency,
                ClassBudget {
                    queued: 2,
                    running: 2,
                },
            ),
    )
    .unwrap();
    let shared = coordinator(&model, &owner).await;
    let mut attempts = Vec::new();
    for lane in 0..8 {
        let class = if lane == 7 {
            ScopeWorkClass::Emergency
        } else {
            ScopeWorkClass::Normal
        };
        let handle = shared
            .reserve_lane(lane, class)
            .await
            .unwrap()
            .submit(|context| async move {
                context.request([100 + lane; 16], vec![create(100 + lane, &[])], vec![])
            })
            .await
            .unwrap();
        attempts.push(handle.attempt().clone());
        drop(handle);
    }
    let mut all_entered = model.all_entered.subscribe();
    tokio::time::timeout(HANG_GUARD, all_entered.wait_for(|count| *count == 8))
        .await
        .unwrap()
        .unwrap();
    model.outage.store(true, Ordering::SeqCst);
    model.hold_all.store(false, Ordering::SeqCst);
    model.release_all.notify_waiters();
    let mut unknown_returns = model.unknown_returns.subscribe();
    tokio::time::timeout(HANG_GUARD, unknown_returns.wait_for(|count| *count == 8))
        .await
        .unwrap()
        .unwrap();
    assert!(shared
        .lane_status()
        .iter()
        .all(|lane| lane.last_error == Some(ScopeBatchError::OutcomeUnknown)));
    let normal_waiter = shared.reserve_lane(0, ScopeWorkClass::Normal);
    let emergency_waiter = shared.reserve(ScopeWorkClass::Emergency);
    tokio::pin!(normal_waiter, emergency_waiter);
    assert!(poll!(&mut normal_waiter).is_pending());
    assert!(poll!(&mut emergency_waiter).is_pending());
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Normal)
            .resident,
        7
    );
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Emergency)
            .resident,
        1
    );
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Normal)
            .running,
        0
    );
    assert_eq!(model.calls.lock().unwrap().len(), 8);
    model.outage.store(false, Ordering::SeqCst);
    let reconnected = coordinator(&model, &owner).await;
    let mut stream = reconnected.completions();
    let mut seen = std::collections::HashSet::new();
    tokio::time::timeout(HANG_GUARD, async {
        for _ in 0..8 {
            let result = stream.next().await;
            assert!(matches!(
                result.outcome(),
                ScopeBatchCompletionOutcome::Applied(_)
            ));
            assert_eq!(
                result.attempt(),
                &attempts[usize::from(result.attempt().lane())]
            );
            assert!(seen.insert(result.attempt().lane()));
            assert!(reconnected.ack(result.attempt()));
        }
    })
    .await
    .expect("holders must resolve without reserving a second resident entitlement");
    assert_eq!(normal_waiter.await.unwrap().lane(), 0);
    assert_eq!(emergency_waiter.await.unwrap().lane(), 7);
    let state = model.state.lock().unwrap();
    assert_eq!(state.checkpoint.revision, 8);
    assert_eq!(
        state
            .rows
            .values()
            .filter(|row| matches!(row, crate::scope_storage::ScopeRow::Child(_)))
            .count(),
        8
    );
    drop(state);
    assert!(model
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|(attempt, _)| attempts[usize::from(attempt.lane())] == *attempt));
}

#[tokio::test(start_paused = true)]
async fn coordinator_final_close_cannot_discard_an_unknown_entitlement() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.hold_first.store(true, Ordering::SeqCst);
    model.unknown_first.store(true, Ordering::SeqCst);
    let shared = coordinator(&model, &owner).await;
    let handle = shared
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([2; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    model.entered.notified().await;
    owner.close();
    model.release.notify_one();
    tokio::time::timeout(HANG_GUARD, async {
        while shared.lane_status()[0].last_error != Some(ScopeBatchError::Unavailable) {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Normal)
            .resident,
        1,
        "an accepted unknown request retains its original resident entitlement on a failed start"
    );
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Normal)
            .running,
        0
    );
    assert!(shared.lane_status()[0].occupied);
    assert!(shared.lane_status()[0].oldest_unacknowledged.is_none());
    assert!(!shared.ack(handle.attempt()));
    let terminal = handle.completion();
    tokio::pin!(terminal);
    assert!(poll!(&mut terminal).is_pending());
    assert_eq!(model.state.lock().unwrap().checkpoint.revision, 0);
}

async fn reused_id_is_refused(lane_first: u8, lane_second: u8, class: ScopeWorkClass) {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    let shared = coordinator(&model, &owner).await;
    let first = shared
        .reserve_lane(lane_first, class)
        .await
        .unwrap()
        .submit(|context| async move { context.request([7; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    let done = first.completion().await;
    assert!(matches!(
        done.outcome(),
        ScopeBatchCompletionOutcome::Applied(_)
    ));
    assert!(shared.ack(done.attempt()));
    // A caller bug reuses the previous request ID for a different batch.
    let submitted = shared
        .reserve_lane(lane_second, class)
        .await
        .unwrap()
        .submit(|context| async move { context.request([7; 16], vec![create(2, &[])], vec![]) })
        .await;
    assert_eq!(submitted.unwrap_err(), ScopeBatchError::IdempotencyConflict);
    assert_eq!(
        model.calls.lock().unwrap().len(),
        1,
        "reused ID was never sent"
    );
    assert_eq!(model.cancels.load(Ordering::SeqCst), 0);
    let next = tokio::time::timeout(HANG_GUARD, shared.reserve_lane(lane_second, class)).await;
    assert!(next.is_ok(), "lane {lane_second} stays wedged");
}

#[tokio::test(start_paused = true)]
async fn reused_request_id_on_reserved_emergency_lane_is_refused_before_dispatch() {
    reused_id_is_refused(7, 7, ScopeWorkClass::Emergency).await;
}

#[tokio::test(start_paused = true)]
async fn reused_request_id_across_shared_lanes_is_refused_before_dispatch() {
    reused_id_is_refused(0, 1, ScopeWorkClass::Normal).await;
}

#[tokio::test(start_paused = true)]
async fn guarded_rebuild_with_a_stable_operation_id_terminates() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.conflicts.store(true, Ordering::SeqCst);
    let shared = coordinator(&model, &owner).await;
    let reconciling = shared.clone();
    let flip = model.clone();
    let reconciler = tokio::spawn(async move {
        let mut stream = reconciling.completions();
        loop {
            let result = stream.next().await;
            // Only the first guarded attempt conflicts.
            flip.conflicts.store(false, Ordering::SeqCst);
            reconciling.ack(result.attempt());
        }
    });
    // The builder keeps one idempotency ID per logical operation, as an
    // exact-retry caller naturally would.
    let result = tokio::time::timeout(
        HANG_GUARD,
        shared.execute_guarded(ScopeWorkClass::Normal, |context| async move {
            context.request([42; 16], vec![create(1, &[])], vec![])
        }),
    )
    .await;
    reconciler.abort();
    assert!(
        result.is_ok(),
        "execute_guarded never returned; lanes occupied={:?} idempotency_conflict={:?}",
        shared
            .lane_status()
            .iter()
            .map(|lane| lane.occupied)
            .collect::<Vec<_>>(),
        shared
            .lane_status()
            .iter()
            .map(|lane| lane.last_error == Some(ScopeBatchError::IdempotencyConflict))
            .collect::<Vec<_>>(),
    );
    assert_eq!(result.unwrap(), Err(ScopeBatchError::IdempotencyConflict));
    assert_eq!(model.calls.lock().unwrap().len(), 1);
    assert!(shared.lane_status().iter().all(|lane| !lane.occupied));
}

#[tokio::test(start_paused = true)]
async fn reused_request_id_in_an_unresolved_slot_is_refused_before_dispatch() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.hold_first.store(true, Ordering::SeqCst);
    let shared = coordinator(&model, &owner).await;
    let first = shared
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([7; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    model.entered.notified().await;
    let second = shared
        .reserve_lane(1, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([7; 16], vec![create(2, &[])], vec![]) })
        .await;
    assert_eq!(second.unwrap_err(), ScopeBatchError::IdempotencyConflict);
    assert_eq!(model.calls.lock().unwrap().len(), 1);
    assert!(!shared.lane_status()[1].occupied);
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Normal)
            .resident,
        1
    );
    model.release.notify_one();
    assert!(matches!(
        first.completion().await.outcome(),
        ScopeBatchCompletionOutcome::Applied(_)
    ));
    assert!(shared.ack(first.attempt()));
}

#[tokio::test(start_paused = true)]
async fn caller_built_stamp_lane_and_sequence_must_match_before_dispatch() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    let shared = coordinator(&model, &owner).await;
    for field in 0..3 {
        let result = shared
            .reserve_lane(0, ScopeWorkClass::Normal)
            .await
            .unwrap()
            .submit(|context| async move {
                let mut request = context.request([9; 16], vec![create(1, &[])], vec![])?;
                match field {
                    0 => request.stamp = State::new().authority.view.stamp().unwrap().clone(),
                    1 => request.lane = 1,
                    _ => request.sequence += 1,
                }
                Ok(request)
            })
            .await;
        assert_eq!(
            result.unwrap_err(),
            ScopeBatchError::InvalidRequest,
            "field {field}"
        );
        assert!(model.calls.lock().unwrap().is_empty());
        assert!(shared.lane_status().iter().all(|lane| !lane.occupied));
        assert_eq!(
            owner
                .scheduler()
                .snapshot()
                .class(ScopeWorkClass::Normal)
                .resident,
            0
        );
    }
    let next = shared
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move {
            assert_eq!(context.sequence(), 1, "refusal consumes no sequence");
            context.request([10; 16], vec![create(1, &[])], vec![])
        })
        .await
        .unwrap();
    next.completion().await;
    assert!(shared.ack(next.attempt()));
}

#[tokio::test(start_paused = true)]
async fn resident_budget_waiters_cannot_hold_lanes_against_admitted_classes() {
    use futures_util::FutureExt;
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    let shared = coordinator(&model, &owner).await;
    let mut held = Vec::new();
    for lane in 0..4 {
        held.push(
            shared
                .reserve_lane(lane, ScopeWorkClass::Maintenance)
                .await
                .unwrap(),
        );
    }
    let mut waiting = (0..3)
        .map(|index| {
            let shared = shared.clone();
            Box::pin(async move {
                if index == 1 {
                    shared.reserve_lane(5, ScopeWorkClass::Maintenance).await
                } else {
                    shared.reserve(ScopeWorkClass::Maintenance).await
                }
            })
        })
        .collect::<Vec<_>>();
    for reservation in &mut waiting {
        assert!(poll!(reservation).is_pending());
    }
    assert_eq!(
        owner
            .scheduler()
            .snapshot()
            .class(ScopeWorkClass::Maintenance)
            .resident,
        4
    );
    let normal = shared
        .reserve(ScopeWorkClass::Normal)
        .now_or_never()
        .expect("a Maintenance budget waiter cannot hold an available lane")
        .unwrap();
    assert_eq!(normal.lane(), 4);
    let emergency = shared
        .reserve_lane(5, ScopeWorkClass::Emergency)
        .now_or_never()
        .expect("an Emergency dependency cannot wait behind unadmitted Maintenance")
        .unwrap();
    assert_eq!(emergency.lane(), 5);
    assert!(model.calls.lock().unwrap().is_empty());
    drop(held.remove(0));
    assert_eq!(waiting.remove(0).await.unwrap().lane(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_same_lane_id_collision_after_the_build_cut_has_a_terminal_proof() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.hold_first.store(true, Ordering::SeqCst);
    let shared = coordinator(&model, &owner).await;
    let handle = shared
        .reserve_lane(7, ScopeWorkClass::Emergency)
        .await
        .unwrap()
        .submit(|context| async move { context.request([7; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    model.entered.notified().await;
    // An independent writer wins the same sequence after the builder's cut.
    let competing =
        ScopeBatchRequest::in_lane(&model.stamp(), [7; 16], 7, 1, vec![create(2, &[])], vec![])
            .unwrap();
    model
        .state
        .lock()
        .unwrap()
        .apply(&ScopeBatchCommand { request: competing })
        .unwrap();
    model.release.notify_one();
    let terminal = tokio::time::timeout(HANG_GUARD, handle.completion())
        .await
        .expect("a permanent collision must resolve without a restart");
    let ScopeBatchCompletionOutcome::NotApplied(proof) = terminal.outcome() else {
        panic!("a colliding request never acquired the winning receipt");
    };
    assert!(proof.matches(handle.attempt()));
    assert_eq!(
        terminal.refusal(),
        Some(&ScopeBatchError::IdempotencyConflict)
    );
    assert!(shared.ack(handle.attempt()));
    let next = shared
        .reserve(ScopeWorkClass::Emergency)
        .await
        .unwrap()
        .submit(|context| async move {
            assert_eq!(context.sequence(), 2);
            context.request([8; 16], vec![create(3, &[])], vec![])
        })
        .await
        .unwrap();
    assert!(matches!(
        next.completion().await.outcome(),
        ScopeBatchCompletionOutcome::Applied(_)
    ));
    assert!(shared.ack(next.attempt()));
}

#[tokio::test(start_paused = true)]
async fn a_cross_lane_collision_stays_observably_unresolved_until_its_receipt_moves() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.hold_first.store(true, Ordering::SeqCst);
    let shared = coordinator(&model, &owner).await;
    let handle = shared
        .reserve_lane(7, ScopeWorkClass::Emergency)
        .await
        .unwrap()
        .submit(|context| async move { context.request([7; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    model.entered.notified().await;
    let competing =
        ScopeBatchRequest::in_lane(&model.stamp(), [7; 16], 0, 1, vec![create(2, &[])], vec![])
            .unwrap();
    model
        .state
        .lock()
        .unwrap()
        .apply(&ScopeBatchCommand { request: competing })
        .unwrap();
    let mut reopened = model.reopened.subscribe();
    let cuts_before_release = *reopened.borrow();
    model.release.notify_one();
    tokio::time::timeout(
        HANG_GUARD,
        reopened.wait_for(|count| *count > cuts_before_release),
    )
    .await
    .unwrap()
    .unwrap();
    let status = &shared.lane_status()[7];
    assert!(status.occupied);
    assert_eq!(
        status.last_error,
        Some(ScopeBatchError::IdempotencyConflict)
    );
    assert!(status.oldest_unacknowledged.is_none());
    let unresolved_age = status
        .unresolved_for
        .expect("pending work has an observable age");
    let reconnected = coordinator(&model, &owner).await;
    assert!(reconnected.lane_status()[7].unresolved_for.unwrap() >= unresolved_age);
    assert!(!shared.ack(handle.attempt()));
    let terminal = handle.completion();
    tokio::pin!(terminal);
    assert!(poll!(&mut terminal).is_pending());
    let next =
        ScopeBatchRequest::in_lane(&model.stamp(), [8; 16], 0, 2, vec![create(3, &[])], vec![])
            .unwrap();
    model
        .state
        .lock()
        .unwrap()
        .apply(&ScopeBatchCommand { request: next })
        .unwrap();
    let completed = tokio::time::timeout(HANG_GUARD, terminal).await.unwrap();
    assert!(matches!(
        completed.outcome(),
        ScopeBatchCompletionOutcome::Cancelled
    ));
    assert!(shared.lane_status()[7].unresolved_for.is_none());
    assert!(shared.lane_status()[7].oldest_unacknowledged.is_some());
    assert!(shared.ack(handle.attempt()));
    assert_eq!(model.calls.lock().unwrap().len(), 1);
    assert!(model.state.lock().unwrap().child(1).is_none());
}

async fn acknowledged_id_during_build_is_refused(lane: u8, class: ScopeWorkClass) {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    let shared = coordinator(&model, &owner).await;
    let (entered, building) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let second_coordinator = shared.clone();
    let second = tokio::spawn(async move {
        second_coordinator
            .reserve_lane(lane, class)
            .await
            .unwrap()
            .submit(|context| async move {
                assert!(context
                    .view()
                    .lanes()
                    .iter()
                    .all(|lane| lane.receipt().is_none()));
                entered.send(()).unwrap();
                released.await.unwrap();
                context.request([7; 16], vec![create(2, &[])], vec![])
            })
            .await
    });
    tokio::time::timeout(HANG_GUARD, building)
        .await
        .expect("the second builder must observe the empty cut")
        .unwrap();
    let first = shared
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([7; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(HANG_GUARD, first.completion())
            .await
            .unwrap()
            .outcome(),
        ScopeBatchCompletionOutcome::Applied(_)
    ));
    assert!(shared.ack(first.attempt()));
    assert!(!shared.lane_status()[0].occupied);
    release.send(()).unwrap();
    assert!(matches!(
        tokio::time::timeout(HANG_GUARD, second)
            .await
            .expect("the resumed builder must finish")
            .unwrap(),
        Err(ScopeBatchError::IdempotencyConflict)
    ));
    assert_eq!(
        model.calls.lock().unwrap().len(),
        1,
        "the duplicate must never be sent"
    );
    assert_eq!(model.cancels.load(Ordering::SeqCst), 0);
    assert!(!shared.lane_status()[usize::from(lane)].occupied);
    let next = tokio::time::timeout(HANG_GUARD, shared.reserve_lane(lane, class))
        .await
        .expect("the refused builder must release its lane and resident credit")
        .unwrap()
        .submit(|context| async move {
            assert_eq!(
                context.sequence(),
                1,
                "pre-dispatch refusal consumes no sequence"
            );
            context.request([8; 16], vec![create(2, &[])], vec![])
        })
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(HANG_GUARD, next.completion())
            .await
            .unwrap()
            .outcome(),
        ScopeBatchCompletionOutcome::Applied(_)
    ));
    assert!(shared.ack(next.attempt()));
}

#[tokio::test(start_paused = true)]
async fn acknowledged_id_during_build_is_refused_on_emergency_lane() {
    acknowledged_id_during_build_is_refused(7, ScopeWorkClass::Emergency).await;
}

#[tokio::test(start_paused = true)]
async fn acknowledged_id_during_build_is_refused_on_shared_lane() {
    acknowledged_id_during_build_is_refused(1, ScopeWorkClass::Normal).await;
}

#[tokio::test(start_paused = true)]
async fn stalled_emergency_lane_waiters_leave_other_scopes_resident_capacity() {
    let owner = ScopeSchedulerOwner::default();
    let mut keep = Vec::new();
    let mut queued = Vec::new();
    for _ in 0..2 {
        let model = Model::new();
        let shared = coordinator(&model, &owner).await;
        let handle = shared
            .reserve(ScopeWorkClass::Emergency)
            .await
            .unwrap()
            .submit(|context| async move { context.request([1; 16], vec![create(1, &[])], vec![]) })
            .await
            .unwrap();
        model.outage.store(true, Ordering::SeqCst);
        let mut unknown = model.unknown_returns.subscribe();
        tokio::time::timeout(HANG_GUARD, unknown.wait_for(|count| *count == 1))
            .await
            .expect("the accepted attempt must remain unresolved")
            .unwrap();
        for index in 0..7 {
            let shared = shared.clone();
            let mut waiter = Box::pin(async move {
                if index % 2 == 0 {
                    shared.reserve(ScopeWorkClass::Emergency).await
                } else {
                    shared.reserve_lane(7, ScopeWorkClass::Emergency).await
                }
            });
            assert!(poll!(&mut waiter).is_pending());
            queued.push(waiter);
        }
        keep.push((model, shared, handle));
    }
    let emergency = owner
        .scheduler()
        .snapshot()
        .class(ScopeWorkClass::Emergency);
    let healthy = Model::new();
    let shared = coordinator(&healthy, &owner).await;
    let reserved = tokio::time::timeout(HANG_GUARD, shared.reserve(ScopeWorkClass::Emergency))
        .await
        .expect("queued lane-7 producers must leave Emergency capacity for a healthy scope")
        .unwrap();
    assert_eq!(reserved.lane(), 7);
    assert_eq!(
        emergency.resident, 2,
        "only the two unresolved requests hold credits"
    );
    assert_eq!(
        emergency.reserve_waiting, 0,
        "lane waiters do not enter the resident queue"
    );
    drop(queued);
    drop(keep);
}

// A cross-lane collision must stay unresolved even when the attempt's own lane
// already retains an unrelated receipt at the preceding sequence. Treating that
// receipt as a permanent collision would publish NotApplied for an attempt that
// can still apply once the other lane moves.
#[tokio::test(start_paused = true)]
async fn cross_lane_collision_with_an_unrelated_own_receipt_stays_unresolved() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.hold_first.store(true, Ordering::SeqCst);
    let shared = coordinator(&model, &owner).await;
    let earlier =
        ScopeBatchRequest::in_lane(&model.stamp(), [6; 16], 7, 1, vec![create(9, &[])], vec![])
            .unwrap();
    model
        .state
        .lock()
        .unwrap()
        .apply(&ScopeBatchCommand { request: earlier })
        .unwrap();
    let handle = shared
        .reserve(ScopeWorkClass::Emergency)
        .await
        .unwrap()
        .submit(|context| async move {
            assert_eq!(context.sequence(), 2);
            context.request([7; 16], vec![create(1, &[])], vec![])
        })
        .await
        .unwrap();
    tokio::time::timeout(HANG_GUARD, model.entered.notified())
        .await
        .unwrap();
    let competing =
        ScopeBatchRequest::in_lane(&model.stamp(), [7; 16], 0, 1, vec![create(2, &[])], vec![])
            .unwrap();
    model
        .state
        .lock()
        .unwrap()
        .apply(&ScopeBatchCommand { request: competing })
        .unwrap();
    let mut reopened = model.reopened.subscribe();
    let cuts_before_release = *reopened.borrow();
    model.release.notify_one();
    tokio::time::timeout(
        HANG_GUARD,
        reopened.wait_for(|count| *count > cuts_before_release),
    )
    .await
    .unwrap()
    .unwrap();
    let terminal = handle.completion();
    tokio::pin!(terminal);
    assert!(
        poll!(&mut terminal).is_pending(),
        "a cross-lane collision was published as a terminal result"
    );
    assert_eq!(
        shared.lane_status()[7].last_error,
        Some(ScopeBatchError::IdempotencyConflict)
    );
    let next =
        ScopeBatchRequest::in_lane(&model.stamp(), [8; 16], 0, 2, vec![create(3, &[])], vec![])
            .unwrap();
    model
        .state
        .lock()
        .unwrap()
        .apply(&ScopeBatchCommand { request: next })
        .unwrap();
    let completed = tokio::time::timeout(HANG_GUARD, terminal).await.unwrap();
    assert!(matches!(
        completed.outcome(),
        ScopeBatchCompletionOutcome::Cancelled
    ));
    assert!(shared.ack(handle.attempt()));
}

// A lost reply followed by a same-lane, same-sequence collision is a permanent
// no-application; the completion must still name the refusal.
#[tokio::test(start_paused = true)]
async fn same_lane_collision_after_lost_reply_preserves_the_refusal() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.unknown_first.store(true, Ordering::SeqCst);
    let shared = coordinator(&model, &owner).await;
    let handle = shared
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([7; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    let mut unknown = model.unknown_returns.subscribe();
    tokio::time::timeout(HANG_GUARD, unknown.wait_for(|count| *count == 1))
        .await
        .unwrap()
        .unwrap();
    let competing =
        ScopeBatchRequest::in_lane(&model.stamp(), [7; 16], 0, 1, vec![create(2, &[])], vec![])
            .unwrap();
    model
        .state
        .lock()
        .unwrap()
        .apply(&ScopeBatchCommand { request: competing })
        .unwrap();
    let terminal = tokio::time::timeout(HANG_GUARD, handle.completion())
        .await
        .unwrap();
    assert!(matches!(
        terminal.outcome(),
        ScopeBatchCompletionOutcome::NotApplied(_)
    ));
    assert_eq!(
        terminal.refusal(),
        Some(&ScopeBatchError::IdempotencyConflict)
    );
    assert!(shared.ack(handle.attempt()));
}

// A lost reply whose sequence is later discarded is Pruned: the attempt may
// have applied, so the supervisor must keep it unresolved, never Cancelled.
#[tokio::test(start_paused = true)]
async fn pruned_attempt_after_lost_reply_stays_unresolved() {
    let model = Model::new();
    let owner = ScopeSchedulerOwner::default();
    model.unknown_first.store(true, Ordering::SeqCst);
    let shared = coordinator(&model, &owner).await;
    let handle = shared
        .reserve_lane(0, ScopeWorkClass::Normal)
        .await
        .unwrap()
        .submit(|context| async move { context.request([7; 16], vec![create(1, &[])], vec![]) })
        .await
        .unwrap();
    let mut unknown = model.unknown_returns.subscribe();
    tokio::time::timeout(HANG_GUARD, unknown.wait_for(|count| *count == 1))
        .await
        .unwrap()
        .unwrap();
    for (sequence, id) in [(1, 8), (2, 9)] {
        let other = ScopeBatchRequest::in_lane(
            &model.stamp(),
            [id; 16],
            0,
            sequence,
            vec![create(u8::try_from(sequence).unwrap() + 1, &[])],
            vec![],
        )
        .unwrap();
        model
            .state
            .lock()
            .unwrap()
            .apply(&ScopeBatchCommand { request: other })
            .unwrap();
    }
    let mut reopened = model.reopened.subscribe();
    let cuts = *reopened.borrow();
    tokio::time::timeout(HANG_GUARD, reopened.wait_for(|count| *count > cuts + 2))
        .await
        .unwrap()
        .unwrap();
    let terminal = handle.completion();
    tokio::pin!(terminal);
    assert!(
        poll!(&mut terminal).is_pending(),
        "a pruned attempt was published as a terminal result"
    );
    assert_eq!(
        shared.lane_status()[0].last_error,
        Some(ScopeBatchError::OutcomeUnknown)
    );
}
