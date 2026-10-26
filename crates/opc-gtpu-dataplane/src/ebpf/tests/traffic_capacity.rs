//! Boundary coverage for the guards used by production traffic-proof paths.

use super::super::{
    traffic_attempt_capacity_available, traffic_observation_batch_full, MAX_TRAFFIC_PROOF_ATTEMPTS,
    MAX_TRAFFIC_PROOF_DRAIN_BATCH,
};

#[test]
fn attempt_capacity_predicate_fails_closed_at_the_exact_boundary() {
    assert!(traffic_attempt_capacity_available(0));
    assert!(traffic_attempt_capacity_available(
        MAX_TRAFFIC_PROOF_ATTEMPTS - 1
    ));
    assert!(!traffic_attempt_capacity_available(
        MAX_TRAFFIC_PROOF_ATTEMPTS
    ));
    assert!(!traffic_attempt_capacity_available(
        MAX_TRAFFIC_PROOF_ATTEMPTS + 1
    ));
}

#[test]
fn observation_drain_marks_the_exact_batch_boundary_overflowed() {
    assert!(!traffic_observation_batch_full(
        0,
        MAX_TRAFFIC_PROOF_DRAIN_BATCH
    ));
    assert!(!traffic_observation_batch_full(
        MAX_TRAFFIC_PROOF_DRAIN_BATCH - 1,
        MAX_TRAFFIC_PROOF_DRAIN_BATCH
    ));
    assert!(traffic_observation_batch_full(
        MAX_TRAFFIC_PROOF_DRAIN_BATCH,
        MAX_TRAFFIC_PROOF_DRAIN_BATCH
    ));
    assert!(traffic_observation_batch_full(
        MAX_TRAFFIC_PROOF_DRAIN_BATCH + 1,
        MAX_TRAFFIC_PROOF_DRAIN_BATCH
    ));
}
