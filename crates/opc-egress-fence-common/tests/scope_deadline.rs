use opc_egress_fence_common::scope_time::{ScopeClockCorrelation, ScopeClockError};

const SECOND: u64 = 1_000_000_000;

#[test]
fn delayed_replies_and_retries_keep_the_original_absolute_stop() {
    let sample = ScopeClockCorrelation::new(10, 20, 950, 1_000, 0, 0, 1_000).unwrap();
    let original = sample.deadline_for(1_300, 20).unwrap();
    assert_eq!(original.stop_boot_ns(), 310);
    assert_eq!(sample.deadline_for(1_300, 200), Ok(original));
    assert_eq!(sample.deadline_for(1_300, 309), Ok(original));
    assert_eq!(
        sample.deadline_for(1_300, 310),
        Err(ScopeClockError::Expired)
    );
    assert_eq!(
        sample.deadline_for(1_300, 500),
        Err(ScopeClockError::Expired)
    );
}

#[test]
fn a_late_sample_uses_remaining_absolute_time_not_a_new_grant_lifetime() {
    let issued = 1_700_000_000_i128 * i128::from(SECOND);
    let stop = issued + 61 * i128::from(SECOND);
    let sample = ScopeClockCorrelation::new(
        100 * SECOND,
        100 * SECOND + 1,
        issued + 19 * i128::from(SECOND),
        issued + 20 * i128::from(SECOND),
        0,
        0,
        200 * SECOND,
    )
    .unwrap();
    let deadline = sample.deadline_for(stop, 110 * SECOND).unwrap();
    assert_eq!(deadline.stop_boot_ns(), 141 * SECOND);
}

#[test]
fn sampling_delay_is_charged_from_the_first_boot_observation() {
    let sample = ScopeClockCorrelation::new(100, 200, 990, 1_000, 0, 0, 1_000).unwrap();
    let deadline = sample.deadline_for(1_300, 200).unwrap();
    assert_eq!(deadline.stop_boot_ns(), 400);
    assert!(!deadline.is_live_at(199));
    assert!(deadline.is_live_at(200));
    assert!(deadline.is_live_at(399));
    assert!(!deadline.is_live_at(400));
    assert_eq!(
        sample.deadline_for(1_050, 200),
        Err(ScopeClockError::Expired)
    );
    assert_eq!(
        sample.deadline_for(1_300, 199),
        Err(ScopeClockError::ClockRegressed)
    );
}

#[test]
fn rate_error_and_suspend_error_shorten_the_deadline_with_downward_rounding() {
    // At most 1.5 common-time ns elapse per BOOTTIME ns, plus 2 ns total
    // discontinuous error. Only 11 - 2 = 9 ns remain: 6 local clock ticks.
    let sample = ScopeClockCorrelation::new(10, 10, 0, 0, 500_000_000, 2, 100).unwrap();
    assert_eq!(sample.deadline_for(11, 10).unwrap().stop_boot_ns(), 16);
    // A fractional budget must round toward an earlier expiry.
    assert_eq!(sample.deadline_for(10, 10).unwrap().stop_boot_ns(), 15);
    assert_eq!(sample.deadline_for(3, 10), Err(ScopeClockError::Expired));
    assert_eq!(sample.deadline_for(2, 10), Err(ScopeClockError::Expired));
}

#[test]
fn clock_guarantee_has_an_absolute_horizon_even_if_the_lease_lasts_longer() {
    let sample = ScopeClockCorrelation::new(100, 110, 0, 0, 0, 0, 150).unwrap();
    let deadline = sample.deadline_for(1_000, 110).unwrap();
    assert_eq!(deadline.stop_boot_ns(), 150);
    assert_eq!(sample.deadline_for(1_000, 149), Ok(deadline));
    assert!(!deadline.is_live_at(150));
    assert_eq!(
        sample.deadline_for(1_000, 150),
        Err(ScopeClockError::BoundExpired)
    );
}

#[test]
fn modeled_boot_advance_expires_without_a_userspace_tick() {
    let sample = ScopeClockCorrelation::new(SECOND, SECOND, 0, 0, 0, 0, 100 * SECOND).unwrap();
    let deadline = sample
        .deadline_for(61 * i128::from(SECOND), SECOND)
        .unwrap();
    assert!(deadline.is_live_at(61 * SECOND));
    // Model a clock that accounts for elapsed suspend time. Hypervisor pause
    // can instead freeze guest BOOTTIME; this test does not qualify a platform.
    assert!(!deadline.is_live_at(70 * SECOND));
    assert!(!deadline.is_live_at(62 * SECOND));
    assert!(!deadline.is_live_at(0));
}

#[test]
fn malformed_or_overwide_clock_samples_are_refused() {
    assert_eq!(
        ScopeClockCorrelation::new(11, 10, 0, 0, 0, 0, 100),
        Err(ScopeClockError::InvalidCorrelation)
    );
    assert_eq!(
        ScopeClockCorrelation::new(10, 10, 1, 0, 0, 0, 100),
        Err(ScopeClockError::InvalidCorrelation)
    );
    for horizon in [0, 9, 10] {
        assert_eq!(
            ScopeClockCorrelation::new(10, 10, 0, 0, 0, 0, horizon),
            Err(ScopeClockError::InvalidCorrelation)
        );
    }
    assert_eq!(
        ScopeClockCorrelation::new(10, 10, 0, i128::from(SECOND) + 1, 0, 0, 100),
        Err(ScopeClockError::ClockUncertain)
    );
    assert!(ScopeClockCorrelation::new(10, 10, 0, i128::from(SECOND), 0, 0, 100).is_ok());
}

#[test]
fn expired_common_deadlines_cannot_be_turned_into_positive_lifetimes() {
    let sample = ScopeClockCorrelation::new(10, 10, 0, 10, 0, 1, 100).unwrap();
    for stop in [-100, 0, 9, 10, 11] {
        assert_eq!(sample.deadline_for(stop, 10), Err(ScopeClockError::Expired));
    }
}

#[test]
fn common_time_is_signed_and_independent_of_the_local_boot_origin() {
    let sample = ScopeClockCorrelation::new(0, 0, -1_010, -1_000, 0, 0, 100).unwrap();
    assert_eq!(sample.deadline_for(-990, 0).unwrap().stop_boot_ns(), 10);
}

#[test]
fn every_unrepresentable_clock_operation_fails_closed() {
    assert_eq!(
        ScopeClockCorrelation::new(0, 0, i128::MIN, i128::MAX, 0, 0, 100),
        Err(ScopeClockError::Overflow)
    );
    let edge = ScopeClockCorrelation::new(0, 0, i128::MAX, i128::MAX, 0, 1, 100).unwrap();
    assert_eq!(
        edge.deadline_for(i128::MAX, 0),
        Err(ScopeClockError::Overflow)
    );
    let edge = ScopeClockCorrelation::new(0, 0, -1, -1, 0, 0, 100).unwrap();
    assert_eq!(
        edge.deadline_for(i128::MAX, 0),
        Err(ScopeClockError::Overflow)
    );
    let edge = ScopeClockCorrelation::new(0, 0, 0, 0, 0, 0, 100).unwrap();
    assert_eq!(
        edge.deadline_for(i128::MAX, 0),
        Err(ScopeClockError::Overflow)
    );
    assert_eq!(
        edge.deadline_for(i128::from(u64::MAX) + 1, 0),
        Err(ScopeClockError::Overflow)
    );
    let edge =
        ScopeClockCorrelation::new(u64::MAX - 5, u64::MAX - 5, 0, 0, 0, 0, u64::MAX).unwrap();
    assert_eq!(
        edge.deadline_for(10, u64::MAX - 5),
        Err(ScopeClockError::Overflow)
    );
}

#[test]
fn all_live_ticks_obey_the_common_time_upper_bound() {
    // Cross multiplication is an independent safety oracle, including the
    // maximal accepted drift value. There is no floating-point tolerance.
    let scale = 1_000_000_000_u128;
    for drift in [0, 1, 500_000_000, u32::MAX] {
        for jump in 0..=4 {
            for sample_delay in 0..=3 {
                for stop in 11..=60 {
                    let sample = ScopeClockCorrelation::new(
                        100,
                        100 + sample_delay,
                        9,
                        10,
                        drift,
                        jump,
                        140,
                    )
                    .unwrap();
                    match sample.deadline_for(stop, 100 + sample_delay) {
                        Ok(deadline) => {
                            assert!(deadline.is_live_at(100 + sample_delay));
                            assert!(deadline.stop_boot_ns() <= 140);
                            for now in 100 + sample_delay..deadline.stop_boot_ns() {
                                let upper_scaled = (10 + u128::from(jump)) * scale
                                    + u128::from(now - 100) * (scale + u128::from(drift));
                                assert!(upper_scaled < stop as u128 * scale);
                            }
                            assert!(!deadline.is_live_at(deadline.stop_boot_ns()));
                        }
                        Err(error) => assert_eq!(error, ScopeClockError::Expired),
                    }
                }
            }
        }
    }
}

#[test]
fn conditional_deadline_bound_precedes_the_exclusion_margin() {
    let issued = 10 * i128::from(SECOND);
    let stop = issued + 61 * i128::from(SECOND);
    let excluded_until = stop + i128::from(SECOND);
    let old_clock = ScopeClockCorrelation::new(
        SECOND,
        SECOND + 10,
        issued - i128::from(SECOND),
        issued,
        500_000_000,
        1_000,
        100 * SECOND,
    )
    .unwrap();
    let deadline = old_clock.deadline_for(stop, SECOND + 10).unwrap();
    let last_live_boot = deadline.stop_boot_ns() - 1;
    let old_true_upper_twice = 2 * (issued + 1_000) + 3 * i128::from(last_live_boot - SECOND);
    assert!(old_true_upper_twice < 2 * stop);
    // Illustrate the conditional inequality for intervals of width <= 1 s.
    // This does not exercise a store, admission operation or leader change.
    for true_now in [
        stop,
        excluded_until - 1,
        excluded_until,
        excluded_until + i128::from(SECOND),
    ] {
        for uncertainty in [0, 1, i128::from(SECOND)] {
            let successor_earliest = true_now - uncertainty;
            if successor_earliest >= excluded_until {
                assert!(old_true_upper_twice < 2 * true_now);
            }
            if true_now < excluded_until {
                assert!(successor_earliest < excluded_until);
            }
        }
    }
}
