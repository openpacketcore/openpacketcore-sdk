use super::*;

fn retry(attempt: u32, limit: usize, millis: u64, reopen: bool) -> RetryDecision {
    RetryDecision::Retry {
        attempt,
        row_limit: limit,
        delay: Duration::from_millis(millis),
        reopen,
    }
}

#[test]
fn no_progress_shrinks_the_next_page_and_never_uses_a_zero_limit() {
    let mut state = RestoreRetryState::new(ScopeScanRetryPolicy::default(), 8).unwrap();
    assert_eq!(
        state.failed(ScopeScanRetryCause::WorkBudgetExceeded),
        retry(1, 4, 25, false)
    );
    assert_eq!(
        state.failed(ScopeScanRetryCause::WorkBudgetExceeded),
        retry(2, 2, 50, false)
    );
    assert_eq!(
        state.failed(ScopeScanRetryCause::WorkBudgetExceeded),
        retry(3, 1, 100, false)
    );
    assert_eq!(
        state.failed(ScopeScanRetryCause::WorkBudgetExceeded),
        retry(4, 1, 200, false)
    );
}

#[test]
fn default_budget_returns_final_stalled_on_the_sixteenth_failure() {
    let mut state = RestoreRetryState::new(ScopeScanRetryPolicy::default(), 256).unwrap();
    for _ in 0..15 {
        assert!(matches!(
            state.failed(ScopeScanRetryCause::Unavailable),
            RetryDecision::Retry { .. }
        ));
    }
    let RetryDecision::Stalled(stalled) = state.failed(ScopeScanRetryCause::Unavailable) else {
        panic!("the restore continued past its recovery budget");
    };
    assert_eq!(stalled.cause(), ScopeScanRetryCause::Unavailable);
    assert_eq!(stalled.attempts(), 16);
    assert_eq!(stalled.attempts_for(ScopeScanRetryCause::Unavailable), 16);
    assert_eq!(stalled.attempts_for(ScopeScanRetryCause::IdleExpired), 0);
    assert_eq!(
        state.failed(ScopeScanRetryCause::IdleExpired),
        RetryDecision::Stalled(stalled),
        "a terminal restore must not silently acquire a fresh budget"
    );
}

#[test]
fn different_restart_causes_share_the_restore_budget_and_keep_the_reduced_limit() {
    let policy =
        ScopeScanRetryPolicy::new(4, Duration::from_millis(25), Duration::from_secs(1)).unwrap();
    let mut state = RestoreRetryState::new(policy, 8).unwrap();
    assert_eq!(
        state.failed(ScopeScanRetryCause::WorkBudgetExceeded),
        retry(1, 4, 25, false)
    );
    assert_eq!(
        state.failed(ScopeScanRetryCause::SnapshotInstalled),
        retry(2, 4, 50, true)
    );
    assert_eq!(
        state.failed(ScopeScanRetryCause::Unavailable),
        retry(3, 4, 100, false)
    );
    let RetryDecision::Stalled(stalled) = state.failed(ScopeScanRetryCause::SnapshotInstalled)
    else {
        panic!("switching failure causes restarted the attempt counter");
    };
    assert_eq!(stalled.attempts(), 4);
    assert_eq!(
        stalled.attempts_for(ScopeScanRetryCause::WorkBudgetExceeded),
        1
    );
    assert_eq!(
        stalled.attempts_for(ScopeScanRetryCause::SnapshotInstalled),
        2
    );
    assert_eq!(stalled.attempts_for(ScopeScanRetryCause::Unavailable), 1);
}

#[test]
fn backoff_is_bounded_and_only_lost_captures_request_reopen() {
    let mut state = RestoreRetryState::new(ScopeScanRetryPolicy::default(), 3).unwrap();
    for (cause, millis, reopen, attempt) in [
        (ScopeScanRetryCause::Unavailable, 25, false, 1),
        (ScopeScanRetryCause::IdleExpired, 50, true, 2),
        (ScopeScanRetryCause::BackendRestarted, 100, true, 3),
        (ScopeScanRetryCause::SnapshotInstalled, 200, true, 4),
        (ScopeScanRetryCause::ConfigurationChanged, 400, true, 5),
        (ScopeScanRetryCause::AdmissionPressure, 800, false, 6),
        (ScopeScanRetryCause::Unavailable, 1_000, false, 7),
        (ScopeScanRetryCause::Unavailable, 1_000, false, 8),
    ] {
        assert_eq!(state.failed(cause), retry(attempt, 3, millis, reopen));
    }
}

#[test]
fn one_attempt_policy_stalls_without_scheduling_an_extra_attempt() {
    let policy =
        ScopeScanRetryPolicy::new(1, Duration::from_millis(1), Duration::from_secs(1)).unwrap();
    let mut state = RestoreRetryState::new(policy, 1).unwrap();
    let RetryDecision::Stalled(stalled) = state.failed(ScopeScanRetryCause::AdmissionPressure)
    else {
        panic!("one-attempt policy scheduled an additional attempt");
    };
    assert_eq!(stalled.attempts(), 1);
}

#[test]
fn invalid_policy_or_page_limits_cannot_create_a_retry_loop() {
    for (attempts, first, cap) in [
        (0, Duration::from_millis(1), Duration::from_secs(1)),
        (1, Duration::ZERO, Duration::from_secs(1)),
        (1, Duration::from_secs(1), Duration::ZERO),
        (1, Duration::from_secs(2), Duration::from_secs(1)),
    ] {
        assert!(ScopeScanRetryPolicy::new(attempts, first, cap).is_err());
    }
    assert!(RestoreRetryState::new(ScopeScanRetryPolicy::default(), 0).is_err());
    assert!(RestoreRetryState::new(ScopeScanRetryPolicy::default(), 1_025).is_err());
}

#[test]
fn extreme_backoff_saturates_without_arithmetic_overflow() {
    let policy = ScopeScanRetryPolicy::new(4, Duration::MAX, Duration::MAX).unwrap();
    let mut state = RestoreRetryState::new(policy, 1).unwrap();
    for attempt in 1..=3 {
        assert_eq!(
            state.failed(ScopeScanRetryCause::Unavailable),
            RetryDecision::Retry {
                attempt,
                row_limit: 1,
                delay: Duration::MAX,
                reopen: false,
            }
        );
    }
}
