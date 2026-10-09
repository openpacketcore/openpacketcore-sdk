//! Public counter inputs must not admit a decreasing stable-scope floor.

use opc_session_store::scope_batch::ScopeCounterMutation;

#[test]
fn every_counter_rejects_a_decrease_within_the_valid_numeric_range() {
    for counter in 0..16 {
        for (expected, next) in [(1, 0), (17, 16), (i64::MAX as u64, i64::MAX as u64 - 1)] {
            assert!(
                ScopeCounterMutation::new(counter, expected, next).is_err(),
                "counter {counter} accepted a decrease {expected} -> {next}"
            );
        }
    }
}

#[test]
fn every_counter_accepts_equality_and_a_rise_at_numeric_boundaries() {
    for counter in 0..16 {
        for (expected, next) in [(0, 0), (0, 1), (16, 17), (i64::MAX as u64, i64::MAX as u64)] {
            let comparison = ScopeCounterMutation::new(counter, expected, next).unwrap();
            assert_eq!(comparison.expected(), expected);
            assert_eq!(comparison.next(), next);
        }
    }
}
