use super::*;

fn at(start: Instant, seconds: u64) -> Instant {
    start + Duration::from_secs(seconds)
}

#[test]
fn accepted_work_protects_a_view_until_thirty_seconds_after_it_finishes() {
    let start = Instant::now();
    let mut view = ViewActivity::new(Duration::from_secs(30), start).unwrap();
    view.begin(at(start, 1)).unwrap();
    assert_eq!(view.state(at(start, 3_600)), ViewState::Retained);
    view.finish(at(start, 3_600)).unwrap();
    assert_eq!(view.state(at(start, 3_629)), ViewState::Retained);
    assert_eq!(view.state(at(start, 3_630)), ViewState::IdleExpired);
}

#[test]
fn overlapping_requests_keep_retention_until_the_last_request_finishes() {
    let start = Instant::now();
    let mut view = ViewActivity::new(Duration::from_secs(30), start).unwrap();
    view.begin(start).unwrap();
    view.begin(at(start, 10)).unwrap();
    view.finish(at(start, 80)).unwrap();
    assert_eq!(view.state(at(start, 179)), ViewState::Retained);
    view.finish(at(start, 180)).unwrap();
    assert_eq!(view.state(at(start, 209)), ViewState::Retained);
    assert_eq!(view.state(at(start, 210)), ViewState::IdleExpired);
}

#[test]
fn idle_expiry_is_terminal_even_if_the_resource_clock_regresses() {
    let start = Instant::now();
    let mut view = ViewActivity::new(Duration::from_secs(30), start).unwrap();
    assert_eq!(view.state(at(start, 29)), ViewState::Retained);
    assert_eq!(view.state(at(start, 30)), ViewState::IdleExpired);
    assert_eq!(
        view.begin(at(start, 10)),
        Err(ActivityError::Ended(ViewState::IdleExpired))
    );
    assert_eq!(view.state(start), ViewState::IdleExpired);
}

#[test]
fn backend_invalidation_is_not_undone_by_a_late_request_completion() {
    for reason in [
        ViewInvalidation::BackendRestarted,
        ViewInvalidation::SnapshotInstalled,
        ViewInvalidation::ConfigurationChanged,
        ViewInvalidation::Closed,
    ] {
        let start = Instant::now();
        let mut view = ViewActivity::new(Duration::from_secs(30), start).unwrap();
        view.begin(at(start, 1)).unwrap();
        view.invalidate(reason);
        assert_eq!(view.state(at(start, 2)), ViewState::Invalidated(reason));
        view.finish(at(start, 3_600)).unwrap();
        assert_eq!(
            view.begin(at(start, 3_601)),
            Err(ActivityError::Ended(ViewState::Invalidated(reason)))
        );
        assert_eq!(view.state(start), ViewState::Invalidated(reason));
    }
}

#[test]
fn an_earlier_invalidation_reason_is_retained() {
    let start = Instant::now();
    let mut view = ViewActivity::new(Duration::from_secs(30), start).unwrap();
    view.invalidate(ViewInvalidation::SnapshotInstalled);
    view.invalidate(ViewInvalidation::Closed);
    assert_eq!(
        view.state(start),
        ViewState::Invalidated(ViewInvalidation::SnapshotInstalled)
    );
}

#[test]
fn a_regressing_activity_clock_does_not_move_the_idle_boundary_backwards() {
    let start = Instant::now();
    let mut view = ViewActivity::new(Duration::from_secs(30), at(start, 100)).unwrap();
    view.begin(at(start, 90)).unwrap();
    view.finish(at(start, 95)).unwrap();
    assert_eq!(view.state(at(start, 129)), ViewState::Retained);
    assert_eq!(view.state(at(start, 130)), ViewState::IdleExpired);
}

#[test]
fn invalid_or_unbalanced_activity_cannot_extend_retention() {
    let start = Instant::now();
    assert!(ViewActivity::new(Duration::ZERO, start).is_err());
    let mut view = ViewActivity::new(Duration::from_secs(30), start).unwrap();
    assert_eq!(
        view.finish(at(start, 29)),
        Err(ActivityError::UnbalancedFinish)
    );
    assert_eq!(view.state(at(start, 30)), ViewState::IdleExpired);
    assert_eq!(
        view.finish(at(start, 100)),
        Err(ActivityError::UnbalancedFinish)
    );
    assert_eq!(view.state(at(start, 101)), ViewState::IdleExpired);
}

#[test]
fn in_flight_counter_overflow_refuses_the_operation_without_losing_activity() {
    let start = Instant::now();
    let mut view = ViewActivity::new(Duration::from_secs(30), start).unwrap();
    view.in_flight = usize::MAX;
    assert_eq!(
        view.begin(start),
        Err(ActivityError::OperationCountOverflow)
    );
    assert_eq!(view.state(at(start, 3_600)), ViewState::Retained);
}
