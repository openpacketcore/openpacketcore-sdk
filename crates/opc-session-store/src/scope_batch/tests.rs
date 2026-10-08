use super::*;
use crate::scope_lease::tests::{bounds, execution, request, scope};
use crate::scope_lease::{ScopeGateClosed, ScopeLeaseOperation, ScopeState};
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
    let selected = ScopeState::empty(scope())
        .transition(
            &request(
                0,
                1,
                ScopeLeaseOperation::Select {
                    execution: execution(1),
                },
            ),
            bounds(0),
        )
        .unwrap();
    selected
        .transition(
            &request(
                1,
                2,
                ScopeLeaseOperation::Acquire {
                    execution: execution(1),
                    selection: 1,
                },
            ),
            bounds(0),
        )
        .unwrap()
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
                self.authority.view.permit().unwrap(),
                [n; 16],
                self.checkpoint.revision,
                operations,
                vec![],
            )
            .unwrap(),
            bounds: bounds(1),
        }
    }

    fn apply(&mut self, command: &ScopeBatchCommand) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        let plan = command.plan(
            &self.authority,
            &self.checkpoint,
            command.bounds.latest(),
            |key| Ok(self.rows.get(key).cloned()),
        )?;
        self.rows.extend(plan.rows);
        self.checkpoint = plan.checkpoint;
        Ok(self
            .checkpoint
            .outcome(command.request.lane())
            .cloned()
            .unwrap())
    }

    fn child(&self, n: u8) -> Option<&ScopeChildRecord> {
        let row = self
            .rows
            .get(&crate::scope_storage::child_key(&scope(), key(n)).unwrap())?;
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
fn scope_batch_fence_survives_renewal_but_rejects_release_expiry_and_intervening_grant() {
    let mut state = State::new();
    let pending = state.command(3, vec![create(1, &[])]);
    let old_permit = state.authority.view.permit().unwrap().clone();
    state.authority = state
        .authority
        .transition(
            &request(
                2,
                4,
                ScopeLeaseOperation::Renew {
                    permit: old_permit.clone(),
                },
            ),
            bounds(1),
        )
        .unwrap();
    state
        .apply(&pending)
        .expect("renewal revisions are not batch fences");
    let pending = state.command(5, vec![create(2, &[])]);
    let permit = state.authority.view.permit().unwrap().clone();
    let live = state.authority.clone();
    let before = state.bytes();
    state.authority = live
        .transition(
            &request(
                3,
                6,
                ScopeLeaseOperation::Release {
                    closed: ScopeGateClosed::after_gate_closed(permit),
                },
            ),
            bounds(2),
        )
        .unwrap();
    assert!(matches!(
        state.apply(&pending),
        Err(ScopeBatchError::Scope(ScopeLeaseError::StalePermit))
    ));
    assert_eq!(state.bytes(), before);
    state.authority = live;
    let mut expired = pending.clone();
    expired.bounds = bounds(79);
    assert!(matches!(
        state.apply(&expired),
        Err(ScopeBatchError::Scope(ScopeLeaseError::Expired))
    ));
    assert!(
        matches!(
            pending.plan(
                &state.authority,
                &state.checkpoint,
                crate::scope_lease::tests::at(79),
                |key| { Ok(state.rows.get(key).cloned()) }
            ),
            Err(ScopeBatchError::Scope(ScopeLeaseError::Expired))
        ),
        "application delay cannot reuse preparation time"
    );
    state.authority = state
        .authority
        .transition(
            &request(
                3,
                7,
                ScopeLeaseOperation::Select {
                    execution: execution(2),
                },
            ),
            bounds(100),
        )
        .unwrap();
    state.authority = state
        .authority
        .transition(
            &request(
                4,
                8,
                ScopeLeaseOperation::Acquire {
                    execution: execution(2),
                    selection: 2,
                },
            ),
            bounds(100),
        )
        .unwrap();
    assert!(matches!(
        state.apply(&pending),
        Err(ScopeBatchError::Scope(ScopeLeaseError::StalePermit))
    ));
    assert_eq!(state.bytes(), before);
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
    let permit = state.authority.view.permit().unwrap();
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
    let command = ScopeBatchCommand {
        request: one,
        bounds: bounds(1),
    };
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
