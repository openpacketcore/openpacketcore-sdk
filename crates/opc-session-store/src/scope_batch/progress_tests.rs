use super::*;
use std::time::{Duration, Instant};

// Removing the terminal-conflict bound must stop this test from reaching Stalled.
#[test]
fn guarded_conflicts_back_off_then_stall_without_a_seventeenth_replan() {
    let mut retry = GuardRetryProgress::default();
    let delays_ms = [
        25, 50, 100, 200, 400, 800, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000,
    ];
    for delay_ms in delays_ms {
        assert_eq!(
            retry.resolved_conflict(),
            GuardRetryDecision::Delay(Duration::from_millis(delay_ms))
        );
    }
    assert_eq!(retry.resolved_conflict(), GuardRetryDecision::Stalled);
    for _ in 0..300 {
        assert_eq!(retry.resolved_conflict(), GuardRetryDecision::Stalled);
    }
}

// Redelivery must not conceal a reconciler that has stopped acknowledging.
#[test]
fn redelivery_preserves_the_first_observation_and_refuses_a_different_result() {
    let start = Instant::now();
    let mut ages = CompletionAges::default();
    assert_eq!(ages.observe(7, [1; 32], start), Ok(()));
    assert_eq!(
        ages.observe(7, [1; 32], start + Duration::from_secs(5)),
        Ok(())
    );
    assert_eq!(
        ages.observe(7, [2; 32], start + Duration::from_secs(6)),
        Err(CompletionAgeError::Occupied)
    );
    let snapshot = ages.ages(start + Duration::from_secs(9));
    assert_eq!(snapshot[7], Some(Duration::from_secs(9)));
    assert_eq!(&snapshot[..7], &[None; 7]);
}

// Omitting the exact digest comparison must free the wrong attempt here.
#[test]
fn only_an_exact_acknowledgement_clears_its_own_lane() {
    let start = Instant::now();
    let mut ages = CompletionAges::default();
    ages.observe(0, [1; 32], start).unwrap();
    ages.observe(7, [2; 32], start + Duration::from_secs(2))
        .unwrap();
    assert!(!ages.ack(0, &[2; 32]));
    assert!(!ages.ack(7, &[1; 32]));
    assert_eq!(
        ages.ages(start + Duration::from_secs(5))[0],
        Some(Duration::from_secs(5))
    );
    assert!(ages.ack(0, &[1; 32]));
    assert_eq!(ages.ages(start + Duration::from_secs(5))[0], None);
    assert_eq!(
        ages.ages(start + Duration::from_secs(5))[7],
        Some(Duration::from_secs(3))
    );
    ages.observe(0, [3; 32], start + Duration::from_secs(5))
        .unwrap();
    assert!(!ages.ack(0, &[1; 32]));
    assert_eq!(
        ages.ages(start + Duration::from_secs(8))[0],
        Some(Duration::from_secs(3))
    );
}

// Time is diagnostic only; even a very old observation cannot be reclaimed.
#[test]
fn elapsed_time_never_clears_an_unacknowledged_result() {
    let start = Instant::now();
    let mut ages = CompletionAges::default();
    ages.observe(3, [4; 32], start).unwrap();
    let age = Duration::from_secs(365 * 24 * 60 * 60);
    assert_eq!(ages.ages(start + age)[3], Some(age));
    assert_eq!(
        ages.observe(3, [5; 32], start + age),
        Err(CompletionAgeError::Occupied)
    );
    assert!(ages.ack(3, &[4; 32]));
}

// An invalid diagnostic index must not alias or clear any real replay lane.
#[test]
fn invalid_lanes_cannot_alias_a_retained_observation() {
    let start = Instant::now();
    let mut ages = CompletionAges::default();
    ages.observe(7, [6; 32], start).unwrap();
    for lane in [8, 255] {
        assert_eq!(
            ages.observe(lane, [6; 32], start),
            Err(CompletionAgeError::InvalidLane)
        );
        assert!(!ages.ack(lane, &[6; 32]));
    }
    assert_eq!(ages.ages(start)[7], Some(Duration::ZERO));
}

// Reopen has no durable clock; it reports only the new observation interval.
#[test]
fn recovered_receipt_starts_a_new_local_observation_interval() {
    let old = Instant::now();
    let reopened = old + Duration::from_secs(10);
    let mut ages = CompletionAges::default();
    ages.observe(2, [7; 32], reopened).unwrap();
    assert_eq!(ages.ages(reopened)[2], Some(Duration::ZERO));
    assert_eq!(
        ages.ages(reopened + Duration::from_secs(3))[2],
        Some(Duration::from_secs(3))
    );
    assert_eq!(ages.ages(old)[2], Some(Duration::ZERO));
}
