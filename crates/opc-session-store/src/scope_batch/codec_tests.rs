use super::*;

#[test]
fn attempt_and_terminal_codecs_bind_cancel_to_the_complete_original_attempt() {
    let mut state = State::new();
    let request = state.command(1, vec![create(1, &[])]).request;
    let attempt = request.attempt().unwrap();
    let bytes = attempt.encode_canonical().unwrap();
    assert_eq!(
        ScopeBatchAttempt::decode_canonical(&bytes).unwrap(),
        attempt
    );
    let cancel = ScopeBatchCancelCommand {
        attempt: attempt.clone(),
    };
    let plan = cancel.plan(&state.authority, &state.checkpoint).unwrap();
    let receipt = plan.checkpoint.receipt(0).unwrap();
    let bytes = receipt.encode_canonical().unwrap();
    assert_eq!(
        ScopeBatchReceipt::decode_canonical(&bytes).unwrap(),
        *receipt
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(ScopeBatchReceipt::decode_canonical(&trailing).is_err());
    assert_ne!(cancel.proposal_id().unwrap(), *request.request_id());
    let digest = attempt.cancellation_digest().unwrap();
    for field in 0..4 {
        let mut changed = attempt.clone();
        match field {
            0 => changed.request_id = [2; 16],
            1 => changed.lane = 7,
            2 => changed.sequence += 1,
            _ => changed.request_digest[0] ^= 1,
        }
        assert_ne!(changed.cancellation_digest().unwrap(), digest);
        assert!(!ScopeBatchCancelCommand { attempt: changed }.matches(receipt));
    }
    state.apply(&ScopeBatchCommand { request }).unwrap();
    let receipt = state.checkpoint.receipt(0).unwrap();
    assert!(cancel.matches(receipt));
    let mut changed = receipt.clone();
    changed.revision += 1;
    assert!(
        changed.encode_canonical().is_err(),
        "applied revision must match its receipt"
    );
}

#[test]
fn canonical_request_codec_binds_every_predicate_and_rejects_noncanonical_bytes() {
    let state = State::new();
    let request = ScopeBatchRequest::in_lane(
        state.authority.view.stamp().unwrap(),
        [1; 16],
        7,
        1,
        vec![create(1, &[])],
        vec![],
    )
    .unwrap()
    .with_read_conditions(
        vec![ScopeChildCondition::new(key(2), ScopeChildRevision::new(1, 2).unwrap()).unwrap()],
        vec![ScopeClaimCondition::new(claim(3), 4, None).unwrap()],
    )
    .unwrap();
    let bytes = request.encode_canonical().unwrap();
    assert_eq!(
        ScopeBatchRequest::decode_canonical(&bytes).unwrap(),
        request
    );
    for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        assert!(ScopeBatchRequest::decode_canonical(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ScopeBatchRequest::decode_canonical(&trailing).is_err());
    let offset = postcard::to_allocvec(request.stamp()).unwrap().len() + 16 + 1;
    assert_eq!(bytes[offset], 1);
    let mut overlong = bytes;
    overlong.splice(offset..offset + 1, [0x81, 0]);
    assert!(ScopeBatchRequest::decode_canonical(&overlong).is_err());
    let digest = request.digest().unwrap();
    let mut changed = request.clone();
    changed.child_conditions[0] =
        ScopeChildCondition::new(key(2), ScopeChildRevision::new(1, 3).unwrap()).unwrap();
    assert_ne!(changed.digest().unwrap(), digest);
    changed = request.clone();
    changed.claim_conditions[0] = ScopeClaimCondition::new(claim(3), 5, None).unwrap();
    assert_ne!(changed.digest().unwrap(), digest);
    changed = request.with_revision_guard(0).unwrap();
    assert_ne!(changed.digest().unwrap(), digest);
}

#[test]
fn outcome_matching_rejects_another_request_or_forged_effect_fields() {
    let mut state = State::new();
    let request = state.command(1, vec![create(1, &[])]).request;
    let outcome = state
        .apply(&ScopeBatchCommand {
            request: request.clone(),
        })
        .unwrap();
    assert!(outcome.matches_request(&request));
    let bytes = outcome.encode_canonical().unwrap();
    assert_eq!(
        ScopeBatchOutcome::decode_canonical(&bytes).unwrap(),
        outcome
    );
    let mut wrong = request.clone();
    wrong.request_id = [2; 16];
    assert!(!outcome.matches_request(&wrong));
    for field in 0..4 {
        let mut forged = outcome.clone();
        match field {
            0 => forged.rows[0].generation += 1,
            1 => forged.sequence += 1,
            2 => forged.revision += 1,
            _ => forged.request_digest[0] ^= 1,
        }
        assert!(!forged.matches_request(&request), "outcome field {field}");
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(ScopeBatchOutcome::decode_canonical(&trailing).is_err());
}

#[test]
fn outcome_matching_binds_every_mutated_counter_value() {
    let mut state = State::new();
    let mut command = state.command(1, vec![create(1, &[])]);
    command.request.counters = (0..SCOPE_COUNTERS as u8)
        .map(|counter| ScopeCounterMutation::new(counter, 0, u64::from(counter) + 2).unwrap())
        .collect();
    let outcome = state.apply(&command).unwrap();
    assert!(outcome.matches_request(&command.request));
    for counter in 0..SCOPE_COUNTERS {
        let mut forged = outcome.clone();
        forged.counters[counter] -= 1;
        assert!(
            !forged.matches_request(&command.request),
            "counter {counter}"
        );
    }
}

#[test]
fn read_predicates_share_the_complete_child_claim_and_byte_bounds() {
    let state = State::new();
    let request = state.command(1, vec![create(1, &[])]).request;
    let condition =
        |n| ScopeChildCondition::new(key(n), ScopeChildRevision::new(1, 1).unwrap()).unwrap();
    assert!(request
        .clone()
        .with_read_conditions((2..=64).map(condition).collect(), vec![])
        .is_ok());
    assert!(request
        .clone()
        .with_read_conditions((2..=65).map(condition).collect(), vec![])
        .is_err());
    assert!(request
        .clone()
        .with_read_conditions(vec![condition(1)], vec![])
        .is_err());
    assert!(request
        .clone()
        .with_read_conditions(vec![condition(2), condition(2)], vec![])
        .is_err());
    let mut oversized = request;
    oversized.child_conditions = (2..=65).map(condition).collect();
    assert!(
        ScopeBatchRequest::decode_canonical(&postcard::to_allocvec(&oversized).unwrap()).is_err()
    );
    assert!(
        ScopeBatchRequest::decode_canonical(&vec![0; MAX_SCOPE_BATCH_COMMAND_BYTES + 1]).is_err()
    );
}

#[test]
fn lookup_and_reopen_codecs_reject_incoherent_frontiers_and_preserve_exact_status() {
    let mut state = State::new();
    let first = state.command(1, vec![create(1, &[])]).request;
    let applied = state
        .apply(&ScopeBatchCommand {
            request: first.clone(),
        })
        .unwrap();
    let pending = ScopeBatchRequest::in_lane(
        state.authority.view.stamp().unwrap(),
        [2; 16],
        7,
        1,
        vec![create(2, &[])],
        vec![],
    )
    .unwrap();
    state.checkpoint = ScopeBatchCancelCommand {
        attempt: pending.attempt().unwrap(),
    }
    .plan(&state.authority, &state.checkpoint)
    .unwrap()
    .checkpoint;
    let observation = ScopeBatchReadCut::new(
        &scope(),
        Some(state.authority.clone()),
        Some(state.checkpoint.clone()),
    )
    .unwrap()
    .reopen();
    let bytes = observation.encode_canonical().unwrap();
    assert_eq!(
        ScopeBatchReopen::decode_canonical(&bytes).unwrap(),
        observation
    );
    assert_eq!(
        observation.lookup(&first.attempt().unwrap()).unwrap(),
        ScopeBatchLookup::Applied(Box::new(applied.clone()))
    );
    assert_eq!(
        observation.lookup(&pending.attempt().unwrap()).unwrap(),
        ScopeBatchLookup::Cancelled
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ScopeBatchReopen::decode_canonical(&trailing).is_err());
    for case in 0..5 {
        let mut wire = serde_json::to_value(&observation).unwrap();
        let view = &mut wire["Initialized"];
        match case {
            0 => view["lanes"][0]["sequence"] = 0.into(),
            1 => view["lanes"][0]["discarded_through"] = 2.into(),
            2 => view["revision"] = 4.into(),
            3 => view["authority"]["revision"] = 0.into(),
            _ => view["lanes"][0]["receipt"]["attempt"]["stamp"]["revision"] = 2.into(),
        }
        let forged: ScopeBatchReopen = serde_json::from_value(wire).unwrap();
        assert!(
            ScopeBatchReopen::decode_canonical(&postcard::to_allocvec(&forged).unwrap()).is_err(),
            "incoherent field {case}"
        );
    }
    for lookup in [
        ScopeBatchLookup::Applied(Box::new(applied)),
        ScopeBatchLookup::Cancelled,
        ScopeBatchLookup::NotApplied,
        ScopeBatchLookup::NotRecorded,
        ScopeBatchLookup::Pruned,
    ] {
        let bytes = lookup.encode_canonical().unwrap();
        assert_eq!(ScopeBatchLookup::decode_canonical(&bytes).unwrap(), lookup);
    }
    assert!(
        ScopeBatchReopen::decode_canonical(&vec![0; MAX_SCOPE_BATCH_REOPEN_BYTES + 1]).is_err()
    );
    assert_eq!(
        ScopeBatchReopen::decode_canonical(
            &ScopeBatchReopen::Uninitialized.encode_canonical().unwrap()
        )
        .unwrap(),
        ScopeBatchReopen::Uninitialized
    );
}

#[test]
fn stored_child_claim_count_is_bounded_before_allocator_reservation() {
    use crate::scope_storage::ScopeRow;
    let mut state = State::new();
    state
        .apply(&state.command(1, vec![create(1, &[])]))
        .unwrap();
    let child = ScopeRow::Child(state.child(1).unwrap().clone());
    let original = child.to_record().unwrap();
    assert_eq!(ScopeRow::from_record(&original).unwrap(), child);
    let mut bytes = original.payload.as_bytes().to_vec();
    assert_eq!(bytes.pop(), Some(0), "claims is the final empty sequence");
    // Keep enough trailing bytes for the decoder to report the claimed count,
    // but far too few for 1,024 complete 32-byte claim keys.
    bytes.extend(postcard::to_allocvec(&1024usize).unwrap());
    bytes.extend_from_slice(&[1; 1024]);
    let mut forged = original;
    forged.payload = crate::EncryptedSessionPayload::new_zeroizing(zeroize::Zeroizing::new(bytes));
    let measured = allocation_counter::measure(|| {
        assert_eq!(
            ScopeRow::from_record(&forged),
            Err(ScopeBatchError::FormatMismatch)
        );
    });
    assert!(
        measured.bytes_max < 16 * 1024,
        "malicious child count must be refused before speculative reservation: {} bytes",
        measured.bytes_max
    );
}

#[test]
fn response_conflict_lists_are_bounded_before_allocator_reservation() {
    for field in 0..3 {
        let error = ScopeBatchError::Conflict(ScopeBatchConflicts::default());
        let mut bytes = postcard::to_allocvec(&error).unwrap();
        assert!(bytes.ends_with(&[0, 0, 0]));
        bytes.truncate(bytes.len() - 3 + field);
        bytes.extend(postcard::to_allocvec(&1024usize).unwrap());
        bytes.extend_from_slice(&[1; 1024]);
        let measured = allocation_counter::measure(|| {
            assert!(postcard::from_bytes::<ScopeBatchError>(&bytes).is_err());
        });
        assert!(measured.bytes_max < 16 * 1024,
            "malicious conflict count {field} must be refused before speculative reservation: {} bytes", measured.bytes_max);
    }
    for field in 0..3 {
        let mut conflicts = ScopeBatchConflicts::default();
        match field {
            0 => conflicts.children = vec![key(1); MAX_SCOPE_BATCH_CHILDREN + 1],
            1 => {
                conflicts.claims =
                    vec![claim(1); MAX_SCOPE_BATCH_CHILDREN * MAX_SCOPE_CHILD_CLAIMS + 1]
            }
            _ => conflicts.counters = vec![0; SCOPE_COUNTERS + 1],
        }
        let bytes = postcard::to_allocvec(&ScopeBatchError::Conflict(conflicts)).unwrap();
        assert!(postcard::from_bytes::<ScopeBatchError>(&bytes).is_err());
    }
}

#[test]
fn error_codec_preserves_every_retry_and_cancellation_status() {
    let mut errors = vec![
        ScopeBatchError::InvalidRequest,
        ScopeBatchError::Conflict(ScopeBatchConflicts {
            children: vec![key(1)],
            claims: vec![claim(2)],
            counters: vec![0, 15],
        }),
        ScopeBatchError::RevisionConflict,
        ScopeBatchError::IdempotencyConflict,
        ScopeBatchError::FormatMismatch,
        ScopeBatchError::OutcomeUnknown,
        ScopeBatchError::Unavailable,
        ScopeBatchError::SequenceConflict,
        ScopeBatchError::Cancelled,
        ScopeBatchError::ScopeGuardStalled,
    ];
    errors.extend(
        [
            ScopeAuthorityError::InvalidRequest,
            ScopeAuthorityError::Unauthorized,
            ScopeAuthorityError::Conflict,
            ScopeAuthorityError::IdempotencyConflict,
            ScopeAuthorityError::StaleAuthority,
            ScopeAuthorityError::Retired,
            ScopeAuthorityError::Superseded,
            ScopeAuthorityError::ClosureRequired,
            ScopeAuthorityError::FormatMismatch,
            ScopeAuthorityError::FreshInstallationRequired,
            ScopeAuthorityError::DurableConsensusRequired,
            ScopeAuthorityError::OutcomeUnknown,
            ScopeAuthorityError::Unavailable,
            ScopeAuthorityError::ProfileNotActivated,
        ]
        .map(ScopeBatchError::Scope),
    );
    for error in errors {
        let bytes = error.encode_canonical().unwrap();
        assert_eq!(bytes, postcard::to_allocvec(&error).unwrap());
        assert_eq!(ScopeBatchError::decode_canonical(&bytes).unwrap(), error);
    }
}

#[test]
fn error_codec_accepts_the_complete_conflict_envelope() {
    let opaque_key = |n: usize| {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&(n as u64 + 1).to_le_bytes());
        bytes
    };
    let error = ScopeBatchError::Conflict(ScopeBatchConflicts {
        children: (0..MAX_SCOPE_BATCH_CHILDREN)
            .map(|n| ScopeChildKey::new(opaque_key(n)).unwrap())
            .collect(),
        claims: (0..MAX_SCOPE_BATCH_CHILDREN * MAX_SCOPE_CHILD_CLAIMS)
            .map(|n| ScopeClaimKey::new(opaque_key(n)).unwrap())
            .collect(),
        counters: (0..SCOPE_COUNTERS as u8).collect(),
    });
    let bytes = error.encode_canonical().unwrap();
    assert!(bytes.len() > COMMAND_HEADROOM);
    assert!(bytes.len() <= MAX_SCOPE_BATCH_ERROR_BYTES);
    assert_eq!(ScopeBatchError::decode_canonical(&bytes).unwrap(), error);
}

#[test]
fn error_codec_rejects_noncanonical_bytes_and_speculative_conflict_allocation() {
    let error = ScopeBatchError::Conflict(ScopeBatchConflicts {
        children: vec![key(1)],
        ..Default::default()
    });
    let bytes = error.encode_canonical().unwrap();
    for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        assert!(ScopeBatchError::decode_canonical(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ScopeBatchError::decode_canonical(&trailing).is_err());
    let mut overlong = bytes;
    assert_eq!(overlong[0], 2);
    overlong.splice(0..1, [0x82, 0]);
    assert!(ScopeBatchError::decode_canonical(&overlong).is_err());
    assert!(ScopeBatchError::decode_canonical(&[127]).is_err());
    assert!(ScopeBatchError::decode_canonical(&vec![0; MAX_SCOPE_BATCH_ERROR_BYTES + 1]).is_err());
    for field in 0..3 {
        let mut bytes =
            postcard::to_allocvec(&ScopeBatchError::Conflict(ScopeBatchConflicts::default()))
                .unwrap();
        bytes.truncate(bytes.len() - 3 + field);
        bytes.extend(postcard::to_allocvec(&1024usize).unwrap());
        bytes.extend_from_slice(&[1; 1024]);
        let measured = allocation_counter::measure(|| {
            assert!(ScopeBatchError::decode_canonical(&bytes).is_err());
        });
        assert!(measured.bytes_max < 16 * 1024);
    }
}

#[test]
fn error_codec_refuses_invalid_public_conflict_fields_before_encoding() {
    for case in 0..9 {
        let mut conflicts = ScopeBatchConflicts::default();
        match case {
            0 => conflicts.children = vec![key(1); MAX_SCOPE_BATCH_CHILDREN + 1],
            1 => {
                conflicts.claims =
                    vec![claim(1); MAX_SCOPE_BATCH_CHILDREN * MAX_SCOPE_CHILD_CLAIMS + 1]
            }
            2 => conflicts.counters = vec![0; SCOPE_COUNTERS + 1],
            3 => conflicts.children = vec![ScopeChildKey([0; 32])],
            4 => conflicts.claims = vec![ScopeClaimKey([0; 32])],
            5 => conflicts.counters = vec![SCOPE_COUNTERS as u8],
            6 => conflicts.children = vec![key(1), key(1)],
            7 => conflicts.claims = vec![claim(1), claim(1)],
            _ => conflicts.counters = vec![0, 0],
        }
        let error = ScopeBatchError::Conflict(conflicts);
        assert_eq!(
            error.encode_canonical(),
            Err(ScopeBatchError::InvalidRequest)
        );
        let bytes = postcard::to_allocvec(&error).unwrap();
        assert_eq!(
            ScopeBatchError::decode_canonical(&bytes),
            Err(ScopeBatchError::InvalidRequest)
        );
    }
}
