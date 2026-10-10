use super::*;
use std::sync::Arc;

fn limits(views: usize, readers: usize, native: u64, wal: u64) -> RetentionLimits {
    RetentionLimits::new(views, readers, native, wal).unwrap()
}

#[test]
fn a_fifth_default_view_waits_without_evicting_an_active_view() {
    let mut queue = AdmissionQueue::new(RetentionLimits::default());
    let mut active = Vec::new();
    for scope in 0..4 {
        queue.enqueue(scope, CaptureCost::Native(1), ()).unwrap();
        active.push(
            queue
                .admit_next(None)
                .expect("view is within the cap")
                .ticket,
        );
    }
    let waiting = queue.enqueue(5, CaptureCost::Native(1), ()).unwrap();
    assert!(queue.admit_next(None).is_none());
    assert_eq!(queue.metrics().active_views, 4);
    assert_eq!(queue.metrics().waiting_views, 1);
    assert!(
        !queue.cancel(active[0]),
        "a queued cancellation cannot evict a view"
    );
    assert!(queue.admit_next(None).is_none());
    assert!(queue.release(active[0]));
    assert_eq!(queue.admit_next(None).unwrap().ticket, waiting);
    assert_eq!(queue.metrics().active_views, 4);
}

#[test]
fn waiting_scopes_rotate_while_requests_within_each_scope_remain_fifo() {
    let mut queue = AdmissionQueue::new(limits(1, 1, 64, 64));
    queue.enqueue(1, CaptureCost::Native(1), "a1").unwrap();
    queue.enqueue(1, CaptureCost::Native(1), "a2").unwrap();
    queue.enqueue(1, CaptureCost::Native(1), "a3").unwrap();
    queue.enqueue(2, CaptureCost::Native(1), "b1").unwrap();
    queue.enqueue(3, CaptureCost::Native(1), "c1").unwrap();
    let mut observed = Vec::new();
    while let Some(grant) = queue.admit_next(None) {
        observed.push(grant.resident);
        assert!(queue.release(grant.ticket));
    }
    assert_eq!(observed, ["a1", "b1", "c1", "a2", "a3"]);
    assert_eq!(queue.metrics().waiting_views, 0);
}

#[test]
fn native_byte_capacity_waits_and_duplicate_release_cannot_create_capacity() {
    let mut queue = AdmissionQueue::new(limits(3, 1, 128, 64));
    queue.enqueue(1, CaptureCost::Native(64), ()).unwrap();
    let first = queue.admit_next(None).unwrap().ticket;
    queue.enqueue(2, CaptureCost::Native(64), ()).unwrap();
    let second = queue.admit_next(None).unwrap().ticket;
    let third = queue.enqueue(3, CaptureCost::Native(64), ()).unwrap();
    assert!(queue.admit_next(None).is_none());
    assert!(queue.release(first));
    assert!(!queue.release(first));
    assert_eq!(queue.admit_next(None).unwrap().ticket, third);
    queue.enqueue(4, CaptureCost::Native(1), ()).unwrap();
    assert!(queue.admit_next(None).is_none());
    assert_eq!(queue.metrics().native_bytes, 128);
    assert!(queue.release(second));
    assert!(queue.admit_next(None).is_some());
}

#[test]
fn reader_and_wal_limits_gate_new_views_without_revoking_current_readers() {
    let mut queue = AdmissionQueue::new(limits(3, 1, 64, 128));
    queue.enqueue(1, CaptureCost::Sqlite, ()).unwrap();
    let first = queue.admit_next(Some(0)).unwrap().ticket;
    let second = queue.enqueue(2, CaptureCost::Sqlite, ()).unwrap();
    assert!(
        queue.admit_next(Some(0)).is_none(),
        "reader slot is occupied"
    );
    assert!(queue.admit_next(Some(1_000)).is_none());
    assert_eq!(queue.metrics().sqlite_readers, 1);
    assert!(queue.release(first));
    assert!(
        queue.admit_next(None).is_none(),
        "unknown WAL size cannot admit a reader"
    );
    assert!(
        queue.admit_next(Some(128)).is_none(),
        "the high-water mark gates admission"
    );
    assert_eq!(queue.admit_next(Some(127)).unwrap().ticket, second);
}

#[test]
fn a_capacity_blocked_scope_does_not_block_an_eligible_scope() {
    let mut queue = AdmissionQueue::new(limits(3, 1, 10, 128));
    queue.enqueue(1, CaptureCost::Native(8), ()).unwrap();
    let held = queue.admit_next(None).unwrap().ticket;
    let blocked = queue.enqueue(2, CaptureCost::Native(5), ()).unwrap();
    let eligible = queue.enqueue(3, CaptureCost::Native(2), ()).unwrap();
    assert_eq!(queue.admit_next(None).unwrap().ticket, eligible);
    assert!(queue.admit_next(None).is_none());
    assert!(queue.release(held));
    assert_eq!(queue.admit_next(None).unwrap().ticket, blocked);
}

#[test]
fn cancelling_a_waiter_releases_its_resident_credit_and_preserves_scope_order() {
    let mut queue = AdmissionQueue::new(limits(1, 1, 64, 64));
    let credit = Arc::new(());
    let weak = Arc::downgrade(&credit);
    let cancelled = queue.enqueue(1, CaptureCost::Native(1), credit).unwrap();
    let next = queue
        .enqueue(1, CaptureCost::Native(1), Arc::new(()))
        .unwrap();
    assert!(weak.upgrade().is_some());
    assert!(queue.cancel(cancelled));
    assert!(!queue.cancel(cancelled));
    assert!(
        weak.upgrade().is_none(),
        "cancelled wait retained its ingress credit"
    );
    assert_eq!(queue.metrics().waiting_views, 1);
    assert_eq!(queue.admit_next(None).unwrap().ticket, next);
}

#[test]
fn a_grant_transfers_its_resident_credit_to_the_operation() {
    let mut queue = AdmissionQueue::new(limits(1, 1, 64, 64));
    let credit = Arc::new(());
    let weak = Arc::downgrade(&credit);
    queue.enqueue(1, CaptureCost::Native(1), credit).unwrap();
    let grant = queue.admit_next(None).unwrap();
    assert!(weak.upgrade().is_some());
    drop(grant.resident);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        queue.metrics().active_views,
        1,
        "retention outlives ingress work"
    );
    assert!(queue.release(grant.ticket));
}

#[test]
fn native_accounting_cannot_wrap_and_admit_a_second_capture() {
    let mut queue = AdmissionQueue::new(limits(2, 1, u64::MAX, 64));
    queue.enqueue(1, CaptureCost::Native(u64::MAX), ()).unwrap();
    let held = queue.admit_next(None).unwrap().ticket;
    queue.enqueue(2, CaptureCost::Native(1), ()).unwrap();
    assert!(queue.admit_next(None).is_none());
    assert_eq!(queue.metrics().native_bytes, u64::MAX);
    assert!(queue.release(held));
    assert!(queue.admit_next(None).is_some());
    assert_eq!(queue.metrics().native_bytes, 1);
}

#[test]
fn invalid_limits_or_never_fit_capture_costs_do_not_enter_the_waiting_queue() {
    for (views, readers, native, wal) in [
        (0, 1, 1, 1),
        (1, 0, 1, 1),
        (1, 2, 1, 1),
        (1, 1, 0, 1),
        (1, 1, 1, 0),
    ] {
        assert!(RetentionLimits::new(views, readers, native, wal).is_err());
    }
    let mut queue = AdmissionQueue::new(limits(1, 1, 64, 64));
    assert_eq!(
        queue.enqueue(1, CaptureCost::Native(0), ()),
        Err(AdmissionError::InvalidCost)
    );
    assert_eq!(
        queue.enqueue(1, CaptureCost::Native(65), ()),
        Err(AdmissionError::CaptureTooLarge)
    );
    queue.next_ticket = u64::MAX;
    assert_eq!(
        queue.enqueue(1, CaptureCost::Native(1), ()),
        Err(AdmissionError::MetadataExhausted)
    );
    assert_eq!(queue.metrics().waiting_views, 0);
    assert_eq!(queue.metrics().active_views, 0);
}
