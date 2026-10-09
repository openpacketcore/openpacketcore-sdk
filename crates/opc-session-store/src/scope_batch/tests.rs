use super::*;
use crate::scope_authority::tests::{admitted, close, retired_fixture, scope, successor};
use crate::scope_authority::ScopeState;
use std::collections::HashMap;

pub(crate) fn key(n: u8) -> ScopeChildKey {
    ScopeChildKey::new([n; 32]).unwrap()
}

pub(crate) fn claim(n: u8) -> ScopeClaimKey {
    ScopeClaimKey::new([n; 32]).unwrap()
}

pub(crate) fn value(n: u8) -> ScopeSealedValue {
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{AeadAlgorithm, KeyId};
    ScopeSealedValue::new(
        CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            key_id: KeyId::new("synthetic-scope-key").unwrap(),
            nonce: vec![n; 12],
            aad: vec![n; 32],
            ciphertext_and_tag: vec![n; 32],
        }
        .encode()
        .unwrap(),
    )
    .unwrap()
}

fn authority() -> ScopeState {
    admitted()
}

struct State {
    authority: ScopeState,
    checkpoint: ScopeBatchCheckpoint,
    rows: HashMap<SessionKey, crate::scope_storage::ScopeRow>,
}

impl State {
    fn new() -> Self {
        Self {
            authority: authority(),
            checkpoint: ScopeBatchCheckpoint::empty(scope()),
            rows: HashMap::new(),
        }
    }

    fn command(&self, n: u8, operations: Vec<ScopeChildMutation>) -> ScopeBatchCommand {
        ScopeBatchCommand {
            request: ScopeBatchRequest::new(
                self.authority.view.stamp().unwrap(),
                [n; 16],
                self.checkpoint.revision,
                operations,
                vec![],
            )
            .unwrap(),
        }
    }

    fn apply(&mut self, command: &ScopeBatchCommand) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        let plan = command.plan(&self.authority, &self.checkpoint, |key| {
            Ok(self.rows.get(key).cloned())
        })?;
        self.rows.extend(plan.rows);
        self.checkpoint = plan.checkpoint;
        Ok(self
            .checkpoint
            .outcome(command.request.lane())
            .cloned()
            .unwrap())
    }

    fn child(&self, n: u8) -> Option<&ScopeChildRecord> {
        let row = self.rows.get(
            &crate::scope_storage::child_key(
                self.authority.view.stamp().unwrap().namespace(),
                key(n),
            )
            .unwrap(),
        )?;
        match row {
            crate::scope_storage::ScopeRow::Child(record) if record.value.is_some() => Some(record),
            _ => None,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut rows: Vec<_> = self
            .rows
            .values()
            .map(|row| postcard::to_allocvec(row).unwrap())
            .collect();
        rows.sort();
        postcard::to_allocvec(&(&self.checkpoint, rows)).unwrap()
    }
}

pub(crate) fn create(n: u8, claims: &[u8]) -> ScopeChildMutation {
    ScopeChildMutation::Create {
        key: key(n),
        value: value(n),
        claims: claims.iter().copied().map(claim).collect(),
    }
}

#[test]
fn current_execution_needs_no_time_input() {
    let state = State::new();
    let command = state.command(3, vec![create(1, &[1])]);
    let result = command.plan(&state.authority, &state.checkpoint, |key| {
        Ok(state.rows.get(key).cloned())
    });
    assert!(
        result.is_ok(),
        "an unchanged admitted execution must remain authorized after elapsed time: {:?}",
        result.err()
    );
}

#[test]
fn counter_floors_cannot_decrease() {
    assert!(matches!(
        ScopeCounterMutation::new(0, 7, 6),
        Err(ScopeBatchError::InvalidRequest)
    ));
}

#[test]
fn scope_batch_apply_rejects_decoded_counter_decrease_without_mutation() {
    let mut state = State::new();
    let mut initial = state.command(1, vec![create(1, &[1])]);
    initial.request.counters = vec![ScopeCounterMutation::new(0, 0, 7).unwrap()];
    state.apply(&initial).unwrap();
    let mut compare = state.command(2, vec![create(2, &[2])]);
    compare.request.counters = vec![ScopeCounterMutation::new(0, 7, 7).unwrap()];
    let before = state.bytes();

    // A replicated decode bypasses the public constructor. Apply must repeat
    // its validation before publishing any child, claim, receipt or floor.
    let mut encoded = serde_json::to_value(&compare).unwrap();
    encoded["request"]["counters"][0]["next"] = 6.into();
    let decoded: ScopeBatchCommand = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.request.counters[0].next(), 6);
    assert_eq!(state.apply(&decoded), Err(ScopeBatchError::InvalidRequest));
    assert_eq!(
        state.bytes(),
        before,
        "decoded decreases have no row effects"
    );

    let outcome = state.apply(&compare).unwrap();
    assert_eq!(
        outcome.counters()[0],
        7,
        "equal-value compares remain valid"
    );
}

#[test]
fn scope_batch_reserves_lane_sequence_and_eight_durable_slots() {
    let mut state = State::new();
    let command = state.command(3, vec![create(1, &[1])]);
    let request = serde_json::to_value(&command.request).unwrap();
    assert_eq!(
        request["lane"], 0,
        "the initial batch profile uses lane zero"
    );
    assert_eq!(request["sequence"], 1, "the first lane sequence is one");
    let outcome = state.apply(&command).unwrap();
    let outcome_wire = serde_json::to_value(&outcome).unwrap();
    assert_eq!(outcome_wire["lane"], 0);
    assert_eq!(outcome_wire["sequence"], 1);
    let checkpoint = serde_json::to_value(&state.checkpoint).unwrap();
    let lanes = checkpoint["lanes"]
        .as_array()
        .expect("fixed durable lane slots");
    assert_eq!(lanes.len(), 8);
    assert_eq!(lanes[0]["sequence"], 1);
    assert_eq!(lanes[0]["floor"], 0);
    for lane in &lanes[1..] {
        assert_eq!(lane["sequence"], 0);
        assert_eq!(lane["floor"], 0);
        assert_eq!(lane["outcome"], serde_json::Value::Null);
    }
    for (field, value) in [("lane", 1), ("sequence", 2)] {
        let mut invalid = request.clone();
        invalid[field] = value.into();
        let request: ScopeBatchRequest = serde_json::from_value(invalid).unwrap();
        assert_eq!(request.validate(), Err(ScopeBatchError::InvalidRequest));
    }
    let bytes = postcard::to_allocvec(&state.checkpoint).unwrap();
    let decoded: ScopeBatchCheckpoint = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, state.checkpoint);
    assert_eq!(state.apply(&command).unwrap(), outcome);
    let mut corrupt = state.checkpoint.clone();
    corrupt.lanes[1].floor = 1;
    assert_eq!(
        corrupt.validate_stored(),
        Err(ScopeBatchError::FormatMismatch)
    );
}

#[test]
fn scope_batch_reserved_lane_layout_fits_eight_maximum_outcomes() {
    let mut state = State::new();
    state
        .apply(&state.command(3, vec![create(1, &[1])]))
        .unwrap();
    let mut future = state.checkpoint;
    future.revision = COUNTER_MAX;
    future.birth_floor = COUNTER_MAX;
    future.counters = [COUNTER_MAX; SCOPE_COUNTERS];
    let mut lane = future.lanes[0].clone();
    lane.floor = COUNTER_MAX - 1;
    lane.sequence = COUNTER_MAX;
    let outcome = lane.outcome.as_mut().unwrap();
    outcome.sequence = COUNTER_MAX;
    outcome.revision = COUNTER_MAX;
    outcome.counters = future.counters;
    outcome.rows =
        vec![ScopeChildRevision::new(COUNTER_MAX, COUNTER_MAX).unwrap(); MAX_SCOPE_BATCH_CHILDREN];
    for (index, slot) in future.lanes.iter_mut().enumerate() {
        *slot = lane.clone();
        slot.outcome.as_mut().unwrap().lane = index as u8;
    }
    // This proves space for future lanes, not permission to use them yet.
    assert_eq!(
        future.validate_stored(),
        Err(ScopeBatchError::FormatMismatch)
    );
    let row = crate::scope_storage::ScopeRow::Batch(Box::new(future));
    let bytes = postcard::to_allocvec(&row).unwrap();
    assert!(
        bytes.len() <= 16 * 1024,
        "all eight maximum outcomes fit the metadata row cap"
    );
    let decoded: crate::scope_storage::ScopeRow = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(postcard::to_allocvec(&decoded).unwrap(), bytes);
}

#[test]
fn scope_batch_mixed_conflict_leaves_children_claims_counters_and_birth_floor_unchanged() {
    let mut state = State::new();
    state
        .apply(&state.command(3, vec![create(1, &[1])]))
        .unwrap();
    let before = state.bytes();
    let mut mixed = state.command(4, vec![create(2, &[2]), create(1, &[3])]);
    mixed
        .request
        .counters
        .push(ScopeCounterMutation::new(0, 0, 1).unwrap());
    assert!(matches!(
        state.apply(&mixed),
        Err(ScopeBatchError::Conflict(_))
    ));
    assert_eq!(state.bytes(), before);
    assert!(state.child(2).is_none());
    let committed = state
        .apply(&state.command(5, vec![create(2, &[2])]))
        .unwrap();
    assert_eq!(
        committed.rows[0].birth(),
        2,
        "failed batches must not consume births"
    );
}

#[test]
fn scope_batch_claim_conflict_rolls_back_every_row_and_claim_swaps_are_atomic() {
    let mut state = State::new();
    state
        .apply(&state.command(3, vec![create(1, &[1]), create(2, &[2])]))
        .unwrap();
    let before = state.bytes();
    assert!(matches!(
        state.apply(&state.command(4, vec![create(3, &[3]), create(4, &[1])])),
        Err(ScopeBatchError::Conflict(_))
    ));
    assert_eq!(state.bytes(), before);
    let first = state.child(1).unwrap().revision;
    let second = state.child(2).unwrap().revision;
    let swap = state.command(
        5,
        vec![
            ScopeChildMutation::CompareAndSet {
                key: key(1),
                expected: first,
                value: value(3),
                claims: vec![claim(2)],
            },
            ScopeChildMutation::CompareAndSet {
                key: key(2),
                expected: second,
                value: value(4),
                claims: vec![claim(1)],
            },
        ],
    );
    state.apply(&swap).unwrap();
    assert_eq!(state.child(1).unwrap().claims, vec![claim(2)]);
    assert_eq!(state.child(2).unwrap().claims, vec![claim(1)]);
}

#[test]
fn scope_batch_exact_birth_and_generation_fence_delete_and_replacement() {
    let mut state = State::new();
    let create = state.command(3, vec![create(1, &[1])]);
    let first = state.apply(&create).unwrap().rows[0];
    let delete = state.command(
        4,
        vec![ScopeChildMutation::Delete {
            key: key(1),
            expected: first,
        }],
    );
    state.apply(&delete).unwrap();
    assert!(state.child(1).is_none());
    assert_eq!(state.apply(&create), Err(ScopeBatchError::RevisionConflict));
    let next = state
        .apply(&state.command(5, vec![super::tests::create(1, &[1])]))
        .unwrap()
        .rows[0];
    assert!(next.birth() > first.birth());
    assert_eq!(next.generation(), 1);
    let before = state.bytes();
    for mutation in [
        ScopeChildMutation::Delete {
            key: key(1),
            expected: first,
        },
        ScopeChildMutation::CompareAndSet {
            key: key(1),
            expected: first,
            value: value(9),
            claims: vec![],
        },
    ] {
        assert!(matches!(
            state.apply(&state.command(6, vec![mutation])),
            Err(ScopeBatchError::Conflict(_))
        ));
        assert_eq!(state.bytes(), before);
    }
    let updated = state
        .apply(&state.command(
            7,
            vec![ScopeChildMutation::CompareAndSet {
                key: key(1),
                expected: next,
                value: value(8),
                claims: vec![claim(1)],
            }],
        ))
        .unwrap()
        .rows[0];
    assert_eq!(updated.birth(), next.birth());
    assert_eq!(updated.generation(), 2);
    assert!(matches!(
        state.apply(&state.command(
            8,
            vec![ScopeChildMutation::Delete {
                key: key(1),
                expected: next,
            }]
        )),
        Err(ScopeBatchError::Conflict(_))
    ));
}

#[test]
fn scope_batch_ordered_after_closure_succession_or_retirement_has_no_effect() {
    for transition in 0..3 {
        let mut state = State::new();
        let pending = state.command(3, vec![create(1, &[1])]);
        let before = state.bytes();
        state.authority = match transition {
            0 => state
                .authority
                .transition(&close(&state.authority, 2))
                .unwrap(),
            1 => state
                .authority
                .transition(&successor(&state.authority, 2))
                .unwrap(),
            _ => retired_fixture(&state.authority, 2),
        };
        assert!(matches!(
            state.apply(&pending),
            Err(ScopeBatchError::Scope(_))
        ));
        assert_eq!(state.bytes(), before);
    }
}

#[test]
fn incarnation_change_keeps_all_counters_birth_and_sequence_floors() {
    let mut state = State::new();
    let mut first = state.command(3, vec![create(1, &[1])]);
    first.request.counters = (0..16)
        .map(|n| ScopeCounterMutation::new(n, 0, u64::from(n) + 5).unwrap())
        .collect();
    state.apply(&first).unwrap();
    let old_namespace = state.authority.view.stamp().unwrap().namespace().clone();
    let old_key = crate::scope_storage::child_key(&old_namespace, key(1)).unwrap();
    state.authority = retired_fixture(&state.authority, 2);
    let current = state.command(4, vec![create(1, &[1])]);
    assert_ne!(
        crate::scope_storage::child_key(current.request.namespace(), key(1)).unwrap(),
        old_key
    );
    let after = state.apply(&current).unwrap();
    assert_eq!(after.rows()[0].birth(), 2);
    assert_eq!(after.revision(), 2);
    assert_eq!(after.sequence(), 2);
    assert_eq!(after.counters(), &std::array::from_fn(|n| n as u64 + 5));
    assert!(state.rows.contains_key(&old_key));
    let encoded = crate::scope_storage::ScopeRow::Batch(Box::new(state.checkpoint.clone()))
        .to_record()
        .unwrap();
    let roundtrip = crate::scope_storage::ScopeRow::from_record(&encoded).unwrap();
    assert_eq!(
        postcard::to_allocvec(&roundtrip).unwrap(),
        postcard::to_allocvec(&crate::scope_storage::ScopeRow::Batch(Box::new(
            state.checkpoint.clone()
        )))
        .unwrap()
    );
}

#[test]
fn required_zero_ledger_encoding_is_canonical() {
    let row = crate::scope_storage::ScopeRow::Batch(Box::new(ScopeBatchCheckpoint::empty(scope())));
    let record = row.to_record().unwrap();
    assert_eq!(record.generation.get(), 0);
    assert_eq!(
        crate::scope_storage::ScopeRow::from_record(&record).unwrap(),
        row
    );
    for field in 0..19 {
        let mut wire = serde_json::to_value(&row).unwrap();
        match field {
            0..=15 => wire["Batch"]["counters"][field] = 1.into(),
            16 => wire["Batch"]["birth_floor"] = 1.into(),
            17 => wire["Batch"]["lanes"][0]["floor"] = 1.into(),
            _ => {
                wire["Batch"]["lanes"][7]["last_request_id"] =
                    serde_json::to_value([1; 16]).unwrap()
            }
        }
        let forged: crate::scope_storage::ScopeRow = serde_json::from_value(wire).unwrap();
        assert!(
            forged.to_record().is_err(),
            "nonzero field {field} at revision zero"
        );
    }
}

#[test]
fn snapshot_may_not_lower_any_stable_counter_or_birth_floor() {
    let mut state = State::new();
    let mut first = state.command(3, vec![create(1, &[1])]);
    first.request.counters = (0..16)
        .map(|n| ScopeCounterMutation::new(n, 0, 8).unwrap())
        .collect();
    state.apply(&first).unwrap();
    let before = crate::scope_storage::ScopeRow::Batch(Box::new(state.checkpoint.clone()))
        .facts()
        .unwrap();
    state
        .apply(&state.command(4, vec![create(2, &[2])]))
        .unwrap();
    for n in 0..17 {
        let mut lower = state.checkpoint.clone();
        if n == 16 {
            lower.birth_floor = 0;
            lower.lanes[0].outcome.as_mut().unwrap().rows.clear();
        } else {
            lower.counters[n] = 7;
            lower.lanes[0].outcome.as_mut().unwrap().counters[n] = 7;
        }
        let after = crate::scope_storage::ScopeRow::Batch(Box::new(lower))
            .facts()
            .unwrap();
        assert!(!after.can_replace(before), "floor {n} cannot decrease");
    }
}

#[test]
fn predecessor_outcomes_distinguish_applied_not_applied_and_pruned() {
    let mut state = State::new();
    let first = state.command(3, vec![create(1, &[1])]);
    let pending = state.command(4, vec![create(2, &[2])]);
    assert_eq!(
        state.checkpoint.resolve(&first.request).unwrap(),
        ScopeBatchResolution::NotApplied
    );
    let outcome = state.apply(&first).unwrap();
    assert_eq!(
        state.checkpoint.resolve(&first.request).unwrap(),
        ScopeBatchResolution::Applied(Box::new(outcome.clone()))
    );
    assert_eq!(
        state.checkpoint.resolve(&pending.request).unwrap(),
        ScopeBatchResolution::NotApplied
    );
    state.authority = state
        .authority
        .transition(&successor(&state.authority, 2))
        .unwrap();
    assert_eq!(
        state.apply(&first).unwrap(),
        outcome,
        "an exact receipt replay has no effects"
    );
    assert!(
        state.apply(&pending).is_err(),
        "predecessor writes can never first apply after succession"
    );
    let next = state.command(5, vec![create(2, &[2])]);
    state.apply(&next).unwrap();
    assert_eq!(
        state.checkpoint.resolve(&first.request).unwrap(),
        ScopeBatchResolution::Unknown
    );
}

#[test]
fn scope_batch_replay_is_exact_and_counter_conflicts_are_atomic() {
    let mut state = State::new();
    let mut command = state.command(3, vec![create(1, &[1])]);
    command
        .request
        .counters
        .push(ScopeCounterMutation::new(0, 0, 1).unwrap());
    let result = state.apply(&command).unwrap();
    let before = state.bytes();
    assert_eq!(state.apply(&command).unwrap(), result);
    assert_eq!(state.bytes(), before);
    let mut changed = command;
    changed.request.operations[0] = create(2, &[]);
    assert_eq!(
        state.apply(&changed),
        Err(ScopeBatchError::IdempotencyConflict)
    );
    let mut counter_conflict = state.command(4, vec![create(2, &[2])]);
    counter_conflict
        .request
        .counters
        .push(ScopeCounterMutation::new(0, 0, 2).unwrap());
    assert!(matches!(
        state.apply(&counter_conflict),
        Err(ScopeBatchError::Conflict(_))
    ));
    assert_eq!(state.bytes(), before);
    assert!(ScopeCounterMutation::new(16, 0, 1).is_err());
    assert!(ScopeCounterMutation::new(0, 0, i64::MAX as u64 + 1).is_err());
}

#[test]
fn scope_batch_rejects_duplicate_rows_claims_counts_and_encoded_byte_overflow() {
    let state = State::new();
    let permit = state.authority.view.stamp().unwrap();
    let make = |operations| ScopeBatchRequest::new(permit, [3; 16], 0, operations, vec![]);
    assert!(make(vec![create(1, &[]), create(1, &[])]).is_err());
    assert!(make(vec![create(1, &[1, 1])]).is_err());
    assert!(make((1..=65).map(|n| create(n, &[])).collect()).is_err());
    let full = make((1..=64).map(|n| create(n, &[])).collect()).unwrap();
    assert_eq!(full.operations.len(), MAX_SCOPE_BATCH_CHILDREN);
    let mut large = value(1).envelope().to_vec();
    // Build canonical maximum-size ciphertext rather than padding a valid
    // envelope with trailing garbage.
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(&large).unwrap();
    let overhead = large.len() - envelope.ciphertext_and_tag.len();
    envelope
        .ciphertext_and_tag
        .resize(MAX_SCOPE_CHILD_VALUE_BYTES - overhead, 1);
    large = envelope.encode().unwrap();
    let maximum = ScopeSealedValue::new(large).unwrap();
    let mutation = ScopeChildMutation::Create {
        key: key(1),
        value: maximum.clone(),
        claims: (1..=8).map(claim).collect(),
    };
    let one = make(vec![mutation]).expect("a maximum sealed child plus every index fits");
    let command = ScopeBatchCommand { request: one };
    assert!(serde_json::to_vec(&command).unwrap().len() < MAX_SCOPE_BATCH_COMMAND_BYTES);
    assert!(make(vec![
        ScopeChildMutation::Create {
            key: key(1),
            value: maximum.clone(),
            claims: vec![]
        },
        ScopeChildMutation::Create {
            key: key(2),
            value: maximum,
            claims: vec![]
        },
    ])
    .is_err());
}

#[test]
fn current_batch_revision_cannot_hide_any_forged_authority_field() {
    let mut state = State::new();
    let original = state.command(7, vec![create(1, &[1])]);
    let before = state.bytes();
    for field in 0..7 {
        let mut wire = serde_json::to_value(&original).unwrap();
        let stamp = &mut wire["request"]["stamp"];
        match field {
            0 => stamp["namespace"]["incarnation"] = 2.into(),
            1 => stamp["revision"] = 2.into(),
            2 => stamp["execution"]["admission_generation"] = 2.into(),
            3 => stamp["execution"]["workload"] = serde_json::to_value([8; 16]).unwrap(),
            4 => stamp["execution"]["process"] = serde_json::to_value([8; 16]).unwrap(),
            5 => stamp["execution"]["boot_key"] = serde_json::to_value([8; 32]).unwrap(),
            _ => stamp["execution"]["identity"] = "spiffe://scope.test/worker-2".into(),
        }
        let forged: ScopeBatchCommand = serde_json::from_value(wire).unwrap();
        assert!(
            matches!(state.apply(&forged), Err(ScopeBatchError::Scope(_))),
            "field {field}"
        );
        assert_eq!(state.bytes(), before);
    }
    assert!(state.apply(&original).is_ok());
}

#[test]
fn a_current_closed_stamp_cannot_authorize_a_new_batch() {
    let mut state = State::new();
    state.authority = state
        .authority
        .transition(&close(&state.authority, 2))
        .unwrap();
    let pending = state.command(3, vec![create(1, &[1])]);
    let before = state.bytes();
    assert!(matches!(
        state.apply(&pending),
        Err(ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority))
    ));
    assert_eq!(state.bytes(), before);
}

/// Independently well-formed rows, deliberately detached from authority. The
/// initial-admission tests insert each one alone to simulate orphaned storage.
pub(crate) fn orphan_rows(scope: ScopeId) -> Vec<crate::scope_storage::ScopeRow> {
    use crate::scope_authority::{
        ScopeAuthorityOperation, ScopeAuthorityRequest, ScopeIncarnation, ScopeNamespace,
    };
    use crate::scope_storage::ScopeRow;
    let authority = ScopeState::empty(scope.clone())
        .transition(
            &ScopeAuthorityRequest::new(
                scope.clone(),
                [1; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: crate::scope_authority::tests::execution(1),
                },
            )
            .unwrap(),
        )
        .unwrap();
    let command = ScopeBatchCommand {
        request: ScopeBatchRequest::new(
            authority.view.stamp().unwrap(),
            [2; 16],
            0,
            vec![create(1, &[1])],
            vec![ScopeCounterMutation::new(0, 0, 9).unwrap()],
        )
        .unwrap(),
    };
    let plan = command
        .plan(
            &authority,
            &ScopeBatchCheckpoint::empty(scope.clone()),
            |_| Ok(None),
        )
        .unwrap();
    let mut rows: Vec<_> = plan.rows.into_values().collect();
    let next_namespace = ScopeNamespace::new(scope, ScopeIncarnation::new(2).unwrap()).unwrap();
    for mut row in rows.clone() {
        match &mut row {
            ScopeRow::Child(child) => child.namespace = next_namespace.clone(),
            ScopeRow::Claim(claim) => claim.namespace = next_namespace.clone(),
            _ => continue,
        }
        rows.push(row);
    }
    assert_eq!(rows.len(), 5);
    rows
}
