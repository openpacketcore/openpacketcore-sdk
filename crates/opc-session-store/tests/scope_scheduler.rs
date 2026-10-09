//! Deterministic public contract tests: timeouts are only outer hang guards.
use futures_util::{poll, FutureExt};
use opc_session_store::scope_scheduler::{
    ClassBudget, ScopeLane, ScopeScheduler, ScopeSchedulerBudgets, ScopeSchedulerError,
    ScopeSchedulerKey, ScopeSchedulerOwner, ScopeWorkClass, ScopeWorkPermit,
};
use std::task::Poll;

const CLASSES: [ScopeWorkClass; 5] = [
    ScopeWorkClass::SafetyControl,
    ScopeWorkClass::Emergency,
    ScopeWorkClass::EmergencyClassification,
    ScopeWorkClass::Normal,
    ScopeWorkClass::Maintenance,
];

fn key(value: u8) -> ScopeSchedulerKey {
    ScopeSchedulerKey::from_bytes([value; 32])
}

fn owner() -> ScopeSchedulerOwner {
    let budget = ClassBudget {
        queued: 2,
        running: 1,
    };
    let budgets = CLASSES
        .into_iter()
        .fold(ScopeSchedulerBudgets::default(), |budgets, class| {
            budgets.with_budget(class, budget)
        });
    ScopeSchedulerOwner::new(budgets).unwrap()
}

async fn run(scheduler: &ScopeScheduler, class: ScopeWorkClass, scope: u8) -> ScopeWorkPermit {
    scheduler
        .reserve(key(scope), class)
        .await
        .unwrap()
        .start()
        .await
        .unwrap()
}

#[tokio::test]
async fn every_class_is_isolated_in_both_directions() {
    for protected in CLASSES {
        let owner = owner();
        let scheduler = owner.scheduler();
        let mut held = Vec::new();
        let mut queued = Vec::new();
        for class in CLASSES.into_iter().filter(|class| *class != protected) {
            held.push(run(&scheduler, class, 1).await);
            queued.push(scheduler.reserve(key(2), class).await.unwrap());
            let wait = scheduler.reserve(key(3), class);
            tokio::pin!(wait);
            assert!(
                poll!(&mut wait).is_pending(),
                "{class:?} capacity must wait"
            );
        }
        let permit = run(&scheduler.clone(), protected, 4)
            .now_or_never()
            .expect("other classes cannot delay protected work");
        assert_eq!(scheduler.snapshot().class(protected).running, 1);
        drop(permit);
        drop(queued);
        drop(held);
        for class in CLASSES {
            assert_eq!(scheduler.snapshot().class(class).resident, 0);
        }
    }
}

#[tokio::test]
async fn unresolved_retry_retains_entitlement_when_resident_queue_is_full() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let permit = run(&scheduler, ScopeWorkClass::Normal, 1).await;
    let queued = scheduler
        .reserve(key(2), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let reserve = scheduler.reserve(key(3), ScopeWorkClass::Normal);
    tokio::pin!(reserve);
    assert!(poll!(&mut reserve).is_pending());
    let retry = permit.finish_unknown();
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
        2
    );
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).running,
        0
    );
    let permit = retry
        .start()
        .now_or_never()
        .expect("retry must not reserve again")
        .unwrap();
    assert!(poll!(&mut reserve).is_pending());
    drop(permit);
    assert!(poll!(&mut reserve).is_ready());
    drop(queued);
}

#[tokio::test]
async fn reserve_and_start_are_fifo_and_cancellation_leaves_no_holes() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let held = run(&scheduler, ScopeWorkClass::Normal, 1).await;
    let queued = scheduler
        .reserve(key(2), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let mut first = Box::pin(scheduler.reserve(key(3), ScopeWorkClass::Normal));
    let mut second = Box::pin(scheduler.reserve(key(4), ScopeWorkClass::Normal));
    assert!(poll!(&mut first).is_pending());
    assert!(poll!(&mut second).is_pending());
    drop(queued);
    assert!(poll!(&mut second).is_pending(), "no barging on reserve");
    let first = match poll!(&mut first) {
        Poll::Ready(Ok(value)) => value,
        _ => panic!("first reserve"),
    };
    let mut waiting_start = Box::pin(first.start());
    assert!(poll!(&mut waiting_start).is_pending());
    assert_eq!(
        scheduler
            .snapshot()
            .class(ScopeWorkClass::Normal)
            .start_waiting,
        1
    );
    drop(waiting_start);
    let second = match poll!(&mut second) {
        Poll::Ready(Ok(value)) => value,
        _ => panic!("cancel releases resident"),
    };
    let mut second_start = Box::pin(second.start());
    assert!(poll!(&mut second_start).is_pending());
    drop(held);
    assert!(poll!(&mut second_start).is_ready());
    let stats = scheduler.snapshot().class(ScopeWorkClass::Normal);
    assert_eq!(
        (
            stats.resident,
            stats.running,
            stats.reserve_waiting,
            stats.start_waiting
        ),
        (0, 0, 0, 0)
    );
}

#[tokio::test]
async fn hot_scope_cannot_hold_every_emergency_credit() {
    let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default()).unwrap();
    let scheduler = owner.scheduler();
    let held = run(&scheduler, ScopeWorkClass::Emergency, 1).await;
    let queued = scheduler
        .reserve(key(1), ScopeWorkClass::Emergency)
        .await
        .unwrap();
    let mut hot = Box::pin(queued.start());
    assert!(poll!(&mut hot).is_pending());
    let cold = run(&scheduler, ScopeWorkClass::Emergency, 2)
        .now_or_never()
        .expect("another scope has an independent share");
    assert_eq!(
        scheduler
            .snapshot()
            .class(ScopeWorkClass::Emergency)
            .running,
        2
    );
    drop(cold);
    assert!(poll!(&mut hot).is_pending());
    drop(held);
    assert!(poll!(&mut hot).is_ready());
}

#[tokio::test]
async fn quiesce_preserves_retry_and_final_control_then_close_wakes_waiters() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let permit = run(&scheduler, ScopeWorkClass::Normal, 1).await;
    let retry = permit.finish_unknown();
    owner.quiesce();
    assert!(scheduler
        .reserve(key(2), ScopeWorkClass::Normal)
        .await
        .is_err());
    drop(retry.start().await.unwrap());
    let final_close = run(&scheduler, ScopeWorkClass::SafetyControl, 1).await;
    let pending = scheduler
        .reserve(key(2), ScopeWorkClass::SafetyControl)
        .await
        .unwrap();
    let mut pending = Box::pin(pending.start());
    assert!(poll!(&mut pending).is_pending());
    owner.close();
    assert!(matches!(poll!(&mut pending), Poll::Ready(Err(_))));
    assert!(scheduler
        .reserve(key(3), ScopeWorkClass::SafetyControl)
        .await
        .is_err());
    assert_eq!(
        scheduler
            .snapshot()
            .class(ScopeWorkClass::SafetyControl)
            .running,
        1
    );
    drop(final_close);
    assert_eq!(
        scheduler
            .snapshot()
            .class(ScopeWorkClass::SafetyControl)
            .resident,
        0
    );
}

#[tokio::test]
async fn lane_waiter_boosts_holder_even_after_start_is_waiting() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let normal = run(&scheduler, ScopeWorkClass::Normal, 2).await;
    let lane = ScopeLane::new(key(1));
    let holder = lane.acquire(ScopeWorkClass::Normal).await.unwrap();
    let reservation = scheduler
        .reserve(key(1), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let mut attempt = Box::pin(reservation.start_in_lane(&holder));
    assert!(poll!(&mut attempt).is_pending());
    let mut emergency = Box::pin(lane.acquire(ScopeWorkClass::Emergency));
    assert!(poll!(&mut emergency).is_pending());
    assert_eq!(
        holder.effective_class(ScopeWorkClass::Normal),
        ScopeWorkClass::Emergency
    );
    let permit = match poll!(&mut attempt) {
        Poll::Ready(Ok(permit)) => permit,
        _ => panic!("boosted resolution cannot wait for the Normal queue"),
    };
    assert_eq!(
        scheduler
            .snapshot()
            .class(ScopeWorkClass::Emergency)
            .running,
        1
    );
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
        2
    );
    let retry = permit.finish_unknown();
    drop(emergency);
    assert_eq!(
        holder.effective_class(ScopeWorkClass::Normal),
        ScopeWorkClass::Normal
    );
    drop(attempt);
    drop(holder);
    drop(retry);
    drop(normal);
}

#[tokio::test]
async fn lane_grants_by_class_with_at_most_eight_bypasses_of_oldest() {
    let lane = ScopeLane::new(key(1));
    let mut holder = Some(lane.acquire(ScopeWorkClass::Maintenance).await.unwrap());
    let mut normal = Box::pin(lane.acquire(ScopeWorkClass::Normal));
    assert!(poll!(&mut normal).is_pending());
    let mut emergency: Vec<_> = (0..10)
        .map(|_| Box::pin(lane.acquire(ScopeWorkClass::Emergency)))
        .collect();
    for future in &mut emergency {
        assert!(poll!(future).is_pending());
    }
    for future in emergency.iter_mut().take(8) {
        drop(holder.take());
        assert!(poll!(&mut normal).is_pending());
        holder = Some(match poll!(future) {
            Poll::Ready(Ok(guard)) => guard,
            _ => panic!("class priority"),
        });
    }
    drop(holder);
    assert!(poll!(&mut emergency[8]).is_pending());
    let normal = match poll!(&mut normal) {
        Poll::Ready(Ok(guard)) => guard,
        _ => panic!("bypass bound"),
    };
    drop(normal);
    assert!(poll!(&mut emergency[8]).is_ready());
}

#[tokio::test]
async fn cancelling_selected_lane_waiter_wakes_its_successor() {
    let lane = ScopeLane::new(key(1));
    let held = lane.acquire(ScopeWorkClass::Normal).await.unwrap();
    let mut first = Box::pin(lane.acquire(ScopeWorkClass::Emergency));
    let mut second = Box::pin(lane.acquire(ScopeWorkClass::Normal));
    assert!(poll!(&mut first).is_pending());
    assert!(poll!(&mut second).is_pending());
    drop(held);
    drop(first);
    assert!(poll!(&mut second).is_ready());
}

#[tokio::test]
async fn concurrent_producers_exceed_budgets_without_a_lifetime_quota() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let mut tasks = tokio::task::JoinSet::new();
    for scope in 1..=80 {
        let scheduler = scheduler.clone();
        tasks.spawn(async move {
            for _ in 0..3 {
                let permit = run(&scheduler, ScopeWorkClass::Normal, scope).await;
                tokio::task::yield_now().await;
                drop(permit);
            }
        });
    }
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("bounded producers all progress");
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
        0
    );
}

#[test]
fn invalid_resource_configurations_are_rejected() {
    for budget in [
        ClassBudget {
            queued: 0,
            running: 1,
        },
        ClassBudget {
            queued: 1,
            running: 0,
        },
        ClassBudget {
            queued: 1,
            running: 2,
        },
        ClassBudget {
            queued: usize::MAX,
            running: 1,
        },
    ] {
        let budgets = ScopeSchedulerBudgets::default().with_budget(ScopeWorkClass::Normal, budget);
        assert!(ScopeSchedulerOwner::new(budgets).is_err());
    }
}

#[test]
fn debug_never_discloses_a_scope_key() {
    let key = ScopeSchedulerKey::from_bytes(*b"private-scope-key-do-not-display");
    let lane = ScopeLane::new(key);
    let owner = owner();
    let rendered = format!("{key:?} {lane:?} {owner:?} {:?}", owner.scheduler());
    assert!(!rendered.contains("private-scope"));
    assert!(!rendered.contains("112, 114, 105"));
    assert!(rendered.contains("redacted"));
}

#[tokio::test]
async fn unchanged_lane_priority_does_not_lose_running_fifo_position() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let blocked = run(&scheduler, ScopeWorkClass::Emergency, 2).await;
    let lane = ScopeLane::new(key(1));
    let holder = lane.acquire(ScopeWorkClass::Normal).await.unwrap();
    let mut emergency = Box::pin(lane.acquire(ScopeWorkClass::Emergency));
    assert!(poll!(&mut emergency).is_pending());
    let reservation = scheduler
        .reserve(key(1), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let mut holder_start = Box::pin(reservation.start_in_lane(&holder));
    assert!(poll!(&mut holder_start).is_pending());
    let other = scheduler
        .reserve(key(3), ScopeWorkClass::Emergency)
        .await
        .unwrap();
    let mut other_start = Box::pin(other.start());
    assert!(poll!(&mut other_start).is_pending());
    let mut lower_waiter = Box::pin(lane.acquire(ScopeWorkClass::Normal));
    assert!(poll!(&mut lower_waiter).is_pending());
    assert!(poll!(&mut holder_start).is_pending());
    drop(blocked);
    assert!(
        poll!(&mut other_start).is_pending(),
        "unchanged priority must retain its FIFO place"
    );
    assert!(poll!(&mut holder_start).is_ready());
}

#[tokio::test]
async fn close_wakes_scope_global_and_start_waiters_without_cancelling_a_permit() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let held = run(&scheduler, ScopeWorkClass::Normal, 1).await;
    let queued = scheduler
        .reserve(key(2), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let mut start = Box::pin(queued.start());
    let mut scope_wait = Box::pin(scheduler.reserve(key(1), ScopeWorkClass::Normal));
    let mut global_wait = Box::pin(scheduler.reserve(key(3), ScopeWorkClass::Normal));
    assert!(poll!(&mut start).is_pending());
    assert!(poll!(&mut scope_wait).is_pending());
    assert!(poll!(&mut global_wait).is_pending());
    owner.close();
    assert!(matches!(poll!(&mut scope_wait), Poll::Ready(Err(_))));
    assert!(matches!(poll!(&mut global_wait), Poll::Ready(Err(_))));
    assert!(matches!(poll!(&mut start), Poll::Ready(Err(_))));
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).running,
        1
    );
    drop(held);
    let counts = scheduler.snapshot().class(ScopeWorkClass::Normal);
    assert_eq!(
        (
            counts.resident,
            counts.running,
            counts.reserve_waiting,
            counts.start_waiting
        ),
        (0, 0, 0, 0)
    );
}

#[tokio::test]
async fn ready_start_fifo_ignores_a_reservation_still_preparing() {
    let budgets = ScopeSchedulerBudgets::default().with_budget(
        ScopeWorkClass::Normal,
        ClassBudget {
            queued: 4,
            running: 1,
        },
    );
    let owner = ScopeSchedulerOwner::new(budgets).unwrap();
    let scheduler = owner.scheduler();
    let held = run(&scheduler, ScopeWorkClass::Normal, 1).await;
    let preparing = scheduler
        .reserve(key(2), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let first = scheduler
        .reserve(key(3), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let second = scheduler
        .reserve(key(4), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let mut first = Box::pin(first.start());
    let mut second = Box::pin(second.start());
    assert!(poll!(&mut first).is_pending());
    assert!(poll!(&mut second).is_pending());
    drop(held);
    assert!(poll!(&mut second).is_pending());
    // The ready first waiter owns the grant even before it is polled again.
    // Cancelling it returns that grant to the second, without a queue hole.
    drop(first);
    assert!(poll!(&mut second).is_ready());
    drop(preparing);
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
        0
    );
}

#[tokio::test]
async fn lane_inheritance_cannot_cross_another_scope() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let lane = ScopeLane::new(key(2));
    let holder = lane.acquire(ScopeWorkClass::Emergency).await.unwrap();
    let reservation = scheduler
        .reserve(key(1), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let failed = reservation.start_in_lane(&holder).await.unwrap_err();
    assert_eq!(failed.error(), ScopeSchedulerError::ScopeMismatch);
    let retry = failed.into_reservation();
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
        1
    );
    drop(retry.start().await.unwrap());
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
        0
    );
}

#[tokio::test]
async fn classification_flood_cannot_consume_established_emergency_credits() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let unverified = run(&scheduler, ScopeWorkClass::EmergencyClassification, 1).await;
    let unverified_queue = scheduler
        .reserve(key(2), ScopeWorkClass::EmergencyClassification)
        .await
        .unwrap();
    let normal = run(&scheduler, ScopeWorkClass::Normal, 1).await;
    let maintenance = run(&scheduler, ScopeWorkClass::Maintenance, 1).await;
    let emergency = run(&scheduler, ScopeWorkClass::Emergency, 3)
        .now_or_never()
        .expect("classification and unverified claims cannot delay established emergency work");
    drop((emergency, maintenance, normal, unverified_queue, unverified));
}

// A data-lane waiter must never consume the authority-control pool.
#[tokio::test]
async fn data_lane_holder_cannot_consume_the_control_running_credit() {
    let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default()).unwrap();
    let scheduler = owner.scheduler();
    let lane = ScopeLane::new(key(1));
    // Refusal is immediate for both an idle and an occupied data lane.
    for occupied in [false, true] {
        let holder = if occupied {
            Some(lane.acquire(ScopeWorkClass::Normal).await.unwrap())
        } else {
            None
        };
        let refused = lane
            .acquire(ScopeWorkClass::SafetyControl)
            .now_or_never()
            .expect("control never queues on a data lane")
            .unwrap_err();
        assert_eq!(refused, ScopeSchedulerError::SafetyControlOnDataLane);
        if let Some(holder) = holder {
            let permit = scheduler
                .reserve(key(1), ScopeWorkClass::Normal)
                .await
                .unwrap()
                .start_in_lane(&holder)
                .await
                .unwrap();
            assert_eq!(permit.class(), ScopeWorkClass::Normal);
            let control = run(&scheduler, ScopeWorkClass::SafetyControl, 9)
                .now_or_never()
                .expect("data work cannot borrow authority control capacity");
            drop((permit, control));
        }
    }
}

// The reservation and real waiters determine the running class.
#[tokio::test]
async fn guard_class_cannot_raise_an_unrelated_reservation() {
    let owner = ScopeSchedulerOwner::new(ScopeSchedulerBudgets::default()).unwrap();
    let scheduler = owner.scheduler();
    let lane = ScopeLane::new(key(1));
    let holder = lane.acquire(ScopeWorkClass::Emergency).await.unwrap();
    let permit = scheduler
        .reserve(key(1), ScopeWorkClass::Normal)
        .await
        .unwrap()
        .start_in_lane(&holder)
        .await
        .unwrap();
    assert_eq!(
        permit.class(),
        ScopeWorkClass::Normal,
        "no waiter exists, yet a Normal reservation runs on Emergency credit"
    );
}

// Excess work from one scope must not occupy the global resident FIFO.
#[tokio::test]
async fn scope_over_cap_does_not_take_global_resident_credit() {
    let budgets = ScopeSchedulerBudgets::default().with_budget(
        ScopeWorkClass::Normal,
        ClassBudget {
            queued: 4,
            running: 1,
        },
    );
    let owner = ScopeSchedulerOwner::new(budgets).unwrap();
    let scheduler = owner.scheduler();
    // Scope 1 holds its cap of two resident credits.
    let a = scheduler
        .reserve(key(1), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let b = scheduler
        .reserve(key(1), ScopeWorkClass::Normal)
        .await
        .unwrap();
    // Two further scope-1 producers must wait at the scope cap.
    let mut c = Box::pin(scheduler.reserve(key(1), ScopeWorkClass::Normal));
    let mut d = Box::pin(scheduler.reserve(key(1), ScopeWorkClass::Normal));
    assert!(poll!(&mut c).is_pending());
    assert!(poll!(&mut d).is_pending());
    // Another scope still finds both remaining global credits.
    let e = scheduler
        .reserve(key(2), ScopeWorkClass::Normal)
        .now_or_never()
        .expect("scope 2 is not queued behind scope 1's excess")
        .unwrap();
    let f = scheduler
        .reserve(key(2), ScopeWorkClass::Normal)
        .now_or_never()
        .expect("scope 2 second credit")
        .unwrap();
    drop((a, b, e, f));
}

#[tokio::test]
async fn start_errors_retain_the_unresolved_resident_entitlement() {
    for in_lane in [false, true] {
        let owner = owner();
        let scheduler = owner.scheduler();
        let lane = ScopeLane::new(key(1));
        let holder = lane.acquire(ScopeWorkClass::Normal).await.unwrap();
        let reservation = run(&scheduler, ScopeWorkClass::Normal, 1)
            .await
            .finish_unknown();
        owner.close();
        let failed = if in_lane {
            reservation.start_in_lane(&holder).await
        } else {
            reservation.start().await
        };
        let failed = failed.unwrap_err();
        assert_eq!(failed.error(), ScopeSchedulerError::Closed);
        assert_eq!(
            scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
            1,
            "a failed start must return the unresolved reservation to its owner"
        );
        let retained = failed.into_reservation();
        assert_eq!(retained.class(), ScopeWorkClass::Normal);
        assert_eq!(
            scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
            1
        );
        drop(retained);
        assert_eq!(
            scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
            0
        );
    }
}

#[tokio::test]
async fn lane_scope_mismatch_retains_the_unresolved_resident_entitlement() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let wrong_lane = ScopeLane::new(key(2));
    let holder = wrong_lane.acquire(ScopeWorkClass::Normal).await.unwrap();
    let reservation = run(&scheduler, ScopeWorkClass::Normal, 1)
        .await
        .finish_unknown();
    let failed = reservation.start_in_lane(&holder).await.unwrap_err();
    assert_eq!(failed.error(), ScopeSchedulerError::ScopeMismatch);
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
        1,
        "a composition error must not discard unresolved work"
    );
    let right_lane = ScopeLane::new(key(1));
    let right_guard = right_lane.acquire(ScopeWorkClass::Normal).await.unwrap();
    let permit = failed
        .into_reservation()
        .start_in_lane(&right_guard)
        .now_or_never()
        .expect("recovered reservation starts without reserving again")
        .unwrap();
    drop(permit);
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
        0
    );
}

#[test]
fn class_priority_and_forwarded_wire_tags_have_independent_fixed_contracts() {
    let order = [
        ScopeWorkClass::SafetyControl,
        ScopeWorkClass::Emergency,
        ScopeWorkClass::EmergencyClassification,
        ScopeWorkClass::Normal,
        ScopeWorkClass::Maintenance,
    ];
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(order
        .windows(2)
        .all(|pair| pair[0].priority_rank() < pair[1].priority_rank()));
    // Independently pinned tags must not move if a future class is inserted
    // between existing classes in scheduling priority.
    for (class, tag) in [
        (ScopeWorkClass::SafetyControl, 0),
        (ScopeWorkClass::Emergency, 1),
        (ScopeWorkClass::EmergencyClassification, 2),
        (ScopeWorkClass::Normal, 3),
        (ScopeWorkClass::Maintenance, 4),
    ] {
        assert_eq!(postcard::to_allocvec(&class).unwrap(), [tag]);
        assert_eq!(
            postcard::from_bytes::<ScopeWorkClass>(&[tag]).unwrap(),
            class
        );
    }
    assert!(postcard::from_bytes::<ScopeWorkClass>(&[5]).is_err());
}

#[tokio::test]
async fn public_zero_key_cannot_claim_the_internal_scope_cap_exemption() {
    let budgets = ScopeSchedulerBudgets::default().with_budget(
        ScopeWorkClass::Normal,
        ClassBudget {
            queued: 4,
            running: 2,
        },
    );
    let owner = ScopeSchedulerOwner::new(budgets).unwrap();
    let scheduler = owner.scheduler();
    let first = run(&scheduler, ScopeWorkClass::Normal, 0).await;
    let extra = scheduler
        .reserve(key(0), ScopeWorkClass::Normal)
        .await
        .unwrap();
    let mut extra = Box::pin(extra.start());
    assert!(poll!(&mut extra).is_pending());
    let other = run(&scheduler, ScopeWorkClass::Normal, 1)
        .now_or_never()
        .expect("zero is still an ordinary public scope key");
    drop((first, other));
    assert!(poll!(&mut extra).is_ready());
}

#[tokio::test]
async fn control_reservation_cannot_run_under_a_data_lane_guard() {
    let owner = owner();
    let scheduler = owner.scheduler();
    let lane = ScopeLane::new(key(1));
    let guard = lane.acquire(ScopeWorkClass::Normal).await.unwrap();
    let control = scheduler
        .reserve(key(1), ScopeWorkClass::SafetyControl)
        .await
        .unwrap();
    let failed = control.start_in_lane(&guard).await.unwrap_err();
    assert_eq!(failed.error(), ScopeSchedulerError::SafetyControlOnDataLane);
    let counts = scheduler.snapshot().class(ScopeWorkClass::SafetyControl);
    assert_eq!((counts.resident, counts.running), (1, 0));
    // The retained control entitlement can still use its independent path.
    drop(failed.into_reservation().start().await.unwrap());
}
