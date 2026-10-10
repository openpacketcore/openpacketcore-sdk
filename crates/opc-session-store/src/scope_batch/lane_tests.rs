use super::*;

fn attempt(sequence: u64, id: u8, binding: u8) -> LaneAttemptKey {
    LaneAttemptKey {
        sequence,
        request_id: [id; 16],
        binding_digest: [binding; 32],
    }
}

fn retained(sequence: u64, id: u8, binding: u8) -> LaneFrontier {
    LaneFrontier {
        sequence,
        discarded_through: sequence - 1,
        retained: Some(attempt(sequence, id, binding)),
    }
}

#[test]
fn unrecorded_frontier_needs_permanent_fencing_for_a_negative_proof() {
    let lane = LaneFrontier::default();
    let query = attempt(1, 1, 1);
    assert_eq!(lane.lookup(&query, false), Ok(LaneLookup::NotRecorded));
    assert_eq!(lane.lookup(&query, true), Ok(LaneLookup::NotApplied));
    assert_eq!(lane, LaneFrontier::default());
}

#[test]
fn exact_retained_identity_wins_even_after_authority_is_fenced() {
    let lane = retained(3, 3, 3);
    assert_eq!(
        lane.lookup(&attempt(3, 3, 3), false),
        Ok(LaneLookup::Retained)
    );
    assert_eq!(
        lane.lookup(&attempt(3, 3, 3), true),
        Ok(LaneLookup::Retained)
    );
}

#[test]
fn reused_id_with_changed_binding_or_sequence_is_an_identity_conflict() {
    let lane = retained(3, 3, 3);
    for query in [attempt(3, 3, 4), attempt(4, 3, 3), attempt(2, 3, 3)] {
        for fenced in [false, true] {
            assert_eq!(
                lane.lookup(&query, fenced),
                Err(LaneProtocolError::IdempotencyConflict)
            );
        }
    }
}

#[test]
fn a_different_terminal_id_proves_only_that_same_sequence_not_applied() {
    let lane = retained(3, 3, 3);
    assert_eq!(
        lane.lookup(&attempt(3, 4, 4), false),
        Ok(LaneLookup::NotApplied)
    );
    assert_eq!(
        lane.lookup(&attempt(4, 4, 4), false),
        Ok(LaneLookup::NotRecorded)
    );
}

#[test]
fn a_discarded_outcome_is_pruned_even_when_old_authority_is_fenced() {
    let lane = retained(3, 3, 3);
    for sequence in [1, 2] {
        for fenced in [false, true] {
            assert_eq!(
                lane.lookup(&attempt(sequence, 1, 1), fenced),
                Ok(LaneLookup::Pruned)
            );
        }
    }
}

#[test]
fn advancing_a_lane_is_contiguous_and_never_overwrites_an_occupied_sequence() {
    let empty = LaneFrontier::default();
    assert_eq!(empty.next_sequence(), Ok(1));
    assert_eq!(
        empty.advance(attempt(2, 2, 2)),
        Err(LaneProtocolError::SequenceConflict)
    );
    let first = empty.advance(attempt(1, 1, 1)).unwrap();
    assert_eq!(first.sequence, 1);
    assert_eq!(first.discarded_through, 0);
    assert_eq!(
        first.advance(attempt(1, 2, 2)),
        Err(LaneProtocolError::SequenceConflict)
    );
    assert_eq!(
        first.advance(attempt(1, 1, 1)),
        Err(LaneProtocolError::SequenceConflict)
    );
    let second = first.advance(attempt(2, 2, 2)).unwrap();
    assert_eq!(second.sequence, 2);
    assert_eq!(second.discarded_through, 1);
    assert_eq!(
        second.lookup(&attempt(1, 1, 1), true),
        Ok(LaneLookup::Pruned)
    );
    assert_eq!(
        second.lookup(&attempt(2, 2, 2), true),
        Ok(LaneLookup::Retained)
    );
    assert_eq!(first.sequence, 1);
}

#[test]
fn sequence_exhaustion_cannot_wrap_or_make_an_old_frontier_empty() {
    let lane = retained(i64::MAX as u64, 1, 1);
    assert_eq!(
        lane.next_sequence(),
        Err(LaneProtocolError::SequenceExhausted)
    );
    assert_eq!(
        lane.lookup(&attempt(i64::MAX as u64, 1, 1), true),
        Ok(LaneLookup::Retained)
    );
    assert_eq!(lane.sequence, i64::MAX as u64);
}

#[test]
fn invalid_attempts_are_not_classified_as_absent_or_fenced() {
    for query in [attempt(0, 1, 1), attempt(u64::MAX, 1, 1), attempt(1, 0, 1)] {
        assert_eq!(
            LaneFrontier::default().lookup(&query, true),
            Err(LaneProtocolError::InvalidAttempt)
        );
    }
}

#[test]
fn missing_receipt_or_regressed_floor_is_corrupt_not_empty() {
    let valid = retained(3, 3, 3);
    let cases = [
        LaneFrontier {
            retained: None,
            ..valid
        },
        LaneFrontier {
            discarded_through: 0,
            ..valid
        },
        LaneFrontier {
            discarded_through: 3,
            ..valid
        },
        LaneFrontier {
            retained: Some(attempt(2, 2, 2)),
            ..valid
        },
        LaneFrontier {
            retained: Some(attempt(3, 0, 3)),
            ..valid
        },
        LaneFrontier {
            sequence: 0,
            discarded_through: 0,
            retained: valid.retained,
        },
        LaneFrontier {
            sequence: u64::MAX,
            discarded_through: u64::MAX - 1,
            retained: Some(attempt(u64::MAX, 1, 1)),
        },
    ];
    for corrupt in cases {
        assert_eq!(
            corrupt.lookup(&attempt(4, 4, 4), true),
            Err(LaneProtocolError::Corrupt)
        );
        assert_eq!(corrupt.next_sequence(), Err(LaneProtocolError::Corrupt));
    }
}

#[test]
fn higher_sequences_cannot_reuse_a_retained_operation_id() {
    let lane = retained(1, 1, 1);
    assert_eq!(
        lane.advance(attempt(2, 1, 2)),
        Err(LaneProtocolError::IdempotencyConflict)
    );
    assert_eq!(lane, retained(1, 1, 1));
}
