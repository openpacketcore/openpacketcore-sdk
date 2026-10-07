use super::*;
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};

pub(crate) fn identity(name: &str) -> SessionConsumerIdentity {
    SessionConsumerIdentity::new(format!("spiffe://scope.test/{name}")).unwrap()
}

pub(crate) fn scope() -> ScopeLeaseId {
    let cluster = ConsensusClusterId::new("scope-test").unwrap();
    let epoch = ConsensusConfigurationEpoch::new(1).unwrap();
    ScopeLeaseId::new(
        SessionConsensusIdentity::new(
            cluster,
            derive_configuration_id(cluster, epoch, &[[1; 32]]),
            epoch,
        ),
        TenantId::new("scope-test").unwrap(),
        NetworkFunctionKind::new("test").unwrap(),
        [1; 32],
    )
    .unwrap()
}

pub(crate) fn execution(n: u8) -> ScopeExecution {
    ScopeExecution::new(
        identity(&format!("worker-{n}")),
        u64::from(n),
        [n; 16],
        [n; 16],
        [n; 16],
    )
    .unwrap()
}

pub(crate) fn at(seconds: i64) -> Timestamp {
    Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_800_000_000 + seconds).unwrap(),
    )
}

pub(crate) fn bounds(seconds: i64) -> ScopeClockBounds {
    ScopeClockBounds::new(at(seconds), at(seconds)).unwrap()
}

pub(crate) fn request(revision: u64, n: u8, operation: ScopeLeaseOperation) -> ScopeLeaseRequest {
    ScopeLeaseRequest::new(scope(), [n; 16], revision, operation).unwrap()
}

fn apply(
    state: &ScopeState,
    request: &ScopeLeaseRequest,
    seconds: i64,
) -> Result<ScopeState, ScopeLeaseError> {
    state.transition(request, bounds(seconds))
}

fn selected() -> ScopeState {
    apply(
        &ScopeState::empty(scope()),
        &request(
            0,
            1,
            ScopeLeaseOperation::Select {
                execution: execution(1),
            },
        ),
        0,
    )
    .unwrap()
}

fn acquired() -> ScopeState {
    apply(
        &selected(),
        &request(
            1,
            2,
            ScopeLeaseOperation::Acquire {
                execution: execution(1),
                selection: 1,
            },
        ),
        0,
    )
    .unwrap()
}

#[test]
fn scope_identity_survives_configuration_replacement() {
    let before = acquired();
    let cluster = ConsensusClusterId::new("scope-test").unwrap();
    let epoch = ConsensusConfigurationEpoch::new(2).unwrap();
    let after = ScopeLeaseId::new(
        SessionConsensusIdentity::new(
            cluster,
            derive_configuration_id(cluster, epoch, &[[2; 32]]),
            epoch,
        ),
        before.view.scope.tenant.clone(),
        before.view.scope.nf_kind.clone(),
        before.view.scope.slot,
    )
    .unwrap();
    assert_eq!(before.view.scope, after, "membership is not scope identity");
    let decoded = ScopeState::decode(&before.encode().unwrap(), &after).unwrap();
    let renewal = ScopeLeaseRequest::new(
        after,
        [3; 16],
        decoded.view.revision,
        ScopeLeaseOperation::Renew {
            permit: decoded.view.permit.clone().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(apply(&decoded, &renewal, 1).unwrap().view.grant_floor, 1);
}

#[test]
fn early_resume_has_a_retryable_clock_boundary_result() {
    let before = acquired();
    let resume = request(
        2,
        3,
        ScopeLeaseOperation::ResumeSameExecution {
            permit: before.view.permit.clone().unwrap(),
        },
    );
    assert_eq!(
        before.transition(&resume, ScopeClockBounds::new(at(60), at(61)).unwrap()),
        Err(ScopeLeaseError::Held),
    );
    assert!(apply(&before, &resume, 61).is_ok());
}

#[test]
fn selection_is_a_monotonic_compare_and_set() {
    let first = selected();
    assert_eq!(first.view.revision(), 1);
    assert_eq!(first.view.selection(), 1);
    assert_eq!(first.view.selected(), Some(&execution(1)));
    assert_eq!(
        apply(
            &first,
            &request(
                0,
                3,
                ScopeLeaseOperation::Select {
                    execution: execution(2)
                }
            ),
            1
        ),
        Err(ScopeLeaseError::Conflict)
    );
    let second = apply(
        &first,
        &request(
            1,
            3,
            ScopeLeaseOperation::Select {
                execution: execution(2),
            },
        ),
        1,
    )
    .unwrap();
    assert_eq!(second.view.selection(), 2);
    assert!(second.view.permit().is_none());
}

#[test]
fn selection_cannot_supersede_a_still_live_execution() {
    let first = acquired();
    assert_eq!(
        apply(
            &first,
            &request(
                2,
                3,
                ScopeLeaseOperation::Select {
                    execution: execution(2)
                }
            ),
            1
        ),
        Err(ScopeLeaseError::Held)
    );
}

#[test]
fn selection_after_expiry_loses_to_an_intervening_in_place_resume() {
    let first = acquired();
    let delayed_selection = request(
        2,
        3,
        ScopeLeaseOperation::Select {
            execution: execution(2),
        },
    );
    let resumed = apply(
        &first,
        &request(
            2,
            4,
            ScopeLeaseOperation::ResumeSameExecution {
                permit: first.view.permit().unwrap().clone(),
            },
        ),
        61,
    )
    .unwrap();
    assert_eq!(
        apply(&resumed, &delayed_selection, 62),
        Err(ScopeLeaseError::Conflict)
    );
    assert_eq!(
        apply(
            &resumed,
            &request(
                3,
                5,
                ScopeLeaseOperation::Select {
                    execution: execution(2)
                }
            ),
            62
        ),
        Err(ScopeLeaseError::Held)
    );
}

#[test]
fn admission_generation_gaps_are_retained_without_a_history_or_counter_wrap() {
    let mut admitted = execution(1);
    admitted.admission_generation = i64::MAX as u64;
    let selected = apply(
        &ScopeState::empty(scope()),
        &request(
            0,
            1,
            ScopeLeaseOperation::Select {
                execution: admitted.clone(),
            },
        ),
        0,
    )
    .unwrap();
    assert_eq!(selected.view.revision(), 1);
    assert_eq!(
        ScopeState::decode(&selected.encode().unwrap(), &scope()).unwrap(),
        selected
    );
    let acquired = apply(
        &selected,
        &request(
            1,
            2,
            ScopeLeaseOperation::Acquire {
                execution: admitted.clone(),
                selection: admitted.admission_generation,
            },
        ),
        0,
    )
    .unwrap();
    assert_eq!(acquired.view.grant_floor(), 1);
    let mut invalid = admitted;
    invalid.admission_generation = u64::MAX;
    assert_eq!(
        ScopeLeaseRequest::new(
            scope(),
            [3; 16],
            2,
            ScopeLeaseOperation::Select { execution: invalid }
        ),
        Err(ScopeLeaseError::InvalidRequest)
    );
}

#[test]
fn selection_rejects_an_old_admission_even_with_a_fresh_record_revision() {
    let first = selected();
    let second = apply(
        &first,
        &request(
            1,
            2,
            ScopeLeaseOperation::Select {
                execution: execution(2),
            },
        ),
        1,
    )
    .unwrap();
    assert_eq!(
        apply(
            &second,
            &request(
                2,
                3,
                ScopeLeaseOperation::Select {
                    execution: execution(1)
                }
            ),
            2
        ),
        Err(ScopeLeaseError::Superseded)
    );
}

#[test]
fn acquire_returns_fixed_renewal_stop_and_exclusion_deadlines() {
    let state = acquired();
    let permit = state.view.permit().unwrap();
    assert_eq!(permit.renew_by(), at(1));
    assert_eq!(permit.stop_at(), at(61));
    assert_eq!(permit.excluded_until(), at(62));
    assert_eq!(permit.grant_epoch(), 1);
    assert_eq!(permit.selection(), 1);
    assert_eq!(permit.scope(), &scope());
    assert!(permit.is_live_at(bounds(60)));
    assert!(!permit.is_live_at(bounds(61)));
}

#[test]
fn exact_retry_never_extends_a_permit_and_reused_id_is_rejected() {
    let state = acquired();
    let original = request(
        1,
        2,
        ScopeLeaseOperation::Acquire {
            execution: execution(1),
            selection: 1,
        },
    );
    assert_eq!(apply(&state, &original, 120).unwrap(), state);
    let changed = request(
        1,
        2,
        ScopeLeaseOperation::Acquire {
            execution: execution(2),
            selection: 1,
        },
    );
    assert_eq!(
        apply(&state, &changed, 120),
        Err(ScopeLeaseError::IdempotencyConflict)
    );
    assert_eq!(
        apply(
            &state,
            &request(
                1,
                4,
                ScopeLeaseOperation::Acquire {
                    execution: execution(1),
                    selection: 1
                }
            ),
            120
        ),
        Err(ScopeLeaseError::Conflict)
    );
}

#[test]
fn renewal_replaces_the_exact_permit_and_old_requests_cannot_extend_it() {
    let first = acquired();
    let permit = first.view.permit().unwrap().clone();
    let renewal = request(
        2,
        3,
        ScopeLeaseOperation::Renew {
            permit: permit.clone(),
        },
    );
    let renewed = apply(&first, &renewal, 1).unwrap();
    assert_eq!(renewed.view.permit().unwrap().stop_at(), at(62));
    assert_eq!(renewed.view.permit().unwrap().grant_epoch(), 1);
    assert_eq!(apply(&renewed, &renewal, 50).unwrap(), renewed);
    assert_eq!(
        apply(
            &renewed,
            &request(3, 4, ScopeLeaseOperation::Renew { permit }),
            2
        ),
        Err(ScopeLeaseError::StalePermit)
    );
}

#[test]
fn expired_execution_resumes_in_place_only_without_intervening_selection() {
    let first = acquired();
    let permit = first.view.permit().unwrap().clone();
    assert_eq!(
        apply(
            &first,
            &request(
                2,
                3,
                ScopeLeaseOperation::Renew {
                    permit: permit.clone()
                }
            ),
            61
        ),
        Err(ScopeLeaseError::Expired)
    );
    let resume = request(
        2,
        4,
        ScopeLeaseOperation::ResumeSameExecution {
            permit: permit.clone(),
        },
    );
    let resumed = apply(&first, &resume, 70).unwrap();
    assert_eq!(
        resumed.view.permit().unwrap().execution(),
        permit.execution()
    );
    assert_eq!(
        resumed.view.permit().unwrap().grant_epoch(),
        permit.grant_epoch()
    );
    assert_eq!(resumed.view.permit().unwrap().stop_at(), at(131));
    let staged = apply(
        &first,
        &request(
            2,
            5,
            ScopeLeaseOperation::Select {
                execution: execution(2),
            },
        ),
        61,
    )
    .unwrap();
    assert_eq!(
        apply(
            &staged,
            &request(
                3,
                6,
                ScopeLeaseOperation::ResumeSameExecution {
                    permit: permit.clone()
                }
            ),
            70
        ),
        Err(ScopeLeaseError::Superseded)
    );
    assert_eq!(
        apply(
            &staged,
            &request(3, 7, ScopeLeaseOperation::Renew { permit }),
            71
        ),
        Err(ScopeLeaseError::Superseded)
    );
}

#[test]
fn remote_successor_waits_for_the_full_exclusion_deadline() {
    let first = acquired();
    let staged = apply(
        &first,
        &request(
            2,
            3,
            ScopeLeaseOperation::Select {
                execution: execution(2),
            },
        ),
        61,
    )
    .unwrap();
    let acquire = request(
        3,
        4,
        ScopeLeaseOperation::Acquire {
            execution: execution(2),
            selection: 2,
        },
    );
    assert_eq!(apply(&staged, &acquire, 61), Err(ScopeLeaseError::Held));
    let successor = apply(&staged, &acquire, 62).unwrap();
    assert_eq!(successor.view.permit().unwrap().grant_epoch(), 2);
    assert_eq!(
        apply(
            &successor,
            &request(
                4,
                5,
                ScopeLeaseOperation::ResumeSameExecution {
                    permit: first.view.permit().unwrap().clone()
                }
            ),
            200
        ),
        Err(ScopeLeaseError::StalePermit)
    );
}

#[test]
fn graceful_release_allows_immediate_successor_but_never_reacquires_old_selection() {
    let first = acquired();
    let permit = first.view.permit().unwrap().clone();
    let release = request(
        2,
        3,
        ScopeLeaseOperation::Release {
            closed: ScopeGateClosed::after_gate_closed(permit.clone()),
        },
    );
    let released = apply(&first, &release, 1).unwrap();
    assert!(released.view.permit().is_none());
    assert_eq!(apply(&released, &release, 2).unwrap(), released);
    assert_eq!(
        apply(
            &released,
            &request(
                3,
                4,
                ScopeLeaseOperation::Acquire {
                    execution: execution(1),
                    selection: 1
                }
            ),
            2
        ),
        Err(ScopeLeaseError::Superseded)
    );
    let staged = apply(
        &released,
        &request(
            3,
            5,
            ScopeLeaseOperation::Select {
                execution: execution(2),
            },
        ),
        1,
    )
    .unwrap();
    let next = apply(
        &staged,
        &request(
            4,
            6,
            ScopeLeaseOperation::Acquire {
                execution: execution(2),
                selection: 2,
            },
        ),
        1,
    )
    .unwrap();
    assert_eq!(next.view.permit().unwrap().grant_epoch(), 2);
    assert_eq!(
        apply(
            &next,
            &request(
                5,
                7,
                ScopeLeaseOperation::Release {
                    closed: ScopeGateClosed::after_gate_closed(permit)
                }
            ),
            2
        ),
        Err(ScopeLeaseError::StalePermit)
    );
}

#[test]
fn predecessor_can_release_after_successor_selection_without_reviving_itself() {
    let first = acquired();
    let staged = apply(
        &first,
        &request(
            2,
            3,
            ScopeLeaseOperation::Select {
                execution: execution(2),
            },
        ),
        61,
    )
    .unwrap();
    let released = apply(
        &staged,
        &request(
            3,
            4,
            ScopeLeaseOperation::Release {
                closed: ScopeGateClosed::after_gate_closed(first.view.permit().unwrap().clone()),
            },
        ),
        61,
    )
    .unwrap();
    assert!(apply(
        &released,
        &request(
            4,
            5,
            ScopeLeaseOperation::Acquire {
                execution: execution(2),
                selection: 2
            }
        ),
        61
    )
    .is_ok());
}

#[test]
fn selection_away_and_back_still_fences_the_original_permit() {
    let first = acquired();
    let second = apply(
        &first,
        &request(
            2,
            3,
            ScopeLeaseOperation::Select {
                execution: execution(2),
            },
        ),
        61,
    )
    .unwrap();
    let mut readmitted = execution(1);
    readmitted.admission_generation = 3;
    readmitted.process = [3; 16];
    let third = apply(
        &second,
        &request(
            3,
            4,
            ScopeLeaseOperation::Select {
                execution: readmitted,
            },
        ),
        62,
    )
    .unwrap();
    assert_eq!(
        apply(
            &third,
            &request(
                4,
                5,
                ScopeLeaseOperation::ResumeSameExecution {
                    permit: first.view.permit().unwrap().clone()
                }
            ),
            100
        ),
        Err(ScopeLeaseError::Superseded)
    );
}

#[test]
fn conservative_clock_edges_refuse_early_takeover_and_late_traffic() {
    assert_eq!(
        ScopeClockBounds::new(at(2), at(1)),
        Err(ScopeLeaseError::ClockUncertain)
    );
    assert_eq!(
        ScopeClockBounds::new(at(0), at(2)),
        Err(ScopeLeaseError::ClockUncertain)
    );
    let first = acquired();
    let permit = first.view.permit().unwrap();
    assert!(!permit.is_live_at(ScopeClockBounds::new(at(60), at(61)).unwrap()));
    assert_eq!(
        first.transition(
            &request(
                2,
                3,
                ScopeLeaseOperation::Select {
                    execution: execution(2)
                }
            ),
            ScopeClockBounds::new(at(60), at(61)).unwrap()
        ),
        Err(ScopeLeaseError::Held)
    );
    let staged = apply(
        &first,
        &request(
            2,
            3,
            ScopeLeaseOperation::Select {
                execution: execution(2),
            },
        ),
        61,
    )
    .unwrap();
    assert_eq!(
        staged.transition(
            &request(
                3,
                4,
                ScopeLeaseOperation::Acquire {
                    execution: execution(2),
                    selection: 2
                }
            ),
            ScopeClockBounds::new(at(61), at(62)).unwrap()
        ),
        Err(ScopeLeaseError::Held)
    );
    assert_eq!(
        apply(
            &staged,
            &request(
                3,
                4,
                ScopeLeaseOperation::Acquire {
                    execution: execution(2),
                    selection: 2
                }
            ),
            0
        ),
        Err(ScopeLeaseError::ClockUncertain)
    );
}

#[test]
fn stored_profile_is_exact_bounded_and_preserves_floors_across_restart() {
    let first = acquired();
    let encoded = first.encode().unwrap();
    assert!(encoded.len() <= MAX_SCOPE_LEASE_RECORD_BYTES);
    assert_eq!(ScopeState::decode(&encoded, &scope()).unwrap(), first);
    let mut wrong = encoded.clone();
    wrong[4] ^= 1;
    assert_eq!(
        ScopeState::decode(&wrong, &scope()),
        Err(ScopeLeaseError::FormatMismatch)
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        ScopeState::decode(&trailing, &scope()),
        Err(ScopeLeaseError::FormatMismatch)
    );
    let mut other_scope = scope();
    other_scope.slot = [9; 32];
    assert_eq!(
        ScopeState::decode(&first.encode().unwrap(), &other_scope),
        Err(ScopeLeaseError::FormatMismatch)
    );
}

#[test]
fn all_execution_fields_and_scope_are_part_of_the_fence() {
    let first = acquired();
    for field in 0..6 {
        let mut permit = first.view.permit().unwrap().clone();
        match field {
            0 => permit.execution.incarnation = [9; 16],
            1 => permit.execution.workload = [9; 16],
            2 => permit.execution.process = [9; 16],
            3 => permit.execution.identity = identity("foreign"),
            4 => permit.execution.admission_generation = 2,
            _ => permit.scope.slot = [9; 32],
        }
        assert_eq!(
            apply(
                &first,
                &request(2, 3, ScopeLeaseOperation::Renew { permit }),
                1
            ),
            Err(ScopeLeaseError::StalePermit)
        );
    }
}
