use super::*;
use crate::backend::ReplicationOp;
use crate::consensus::native::changes::tests::{apply, clock, command, fixture, request, time};
use crate::fenced_transition::{FencedTransitionLease, FencedTransitionMutation};
use crate::{EncryptedSessionPayload, FenceToken};

#[path = "generation_roster_codec_tests.rs"]
mod roster;

#[test]
fn native_generation_cold_key_preflight_matches_complete_postcard_and_original_payload_bound() {
    let (storage, _, _) = fixture();
    let (key, row) = storage.business.keys.iter().next().unwrap();
    for fields in 0..4 {
        let mut row = (**row).clone();
        if fields & 1 != 0 {
            row.record = None;
        }
        if fields & 2 != 0 {
            row.lease = None;
        }
        let bytes = postcard::to_allocvec(&(key, Some(&row))).unwrap();
        assert_eq!(
            key_scratch(&bytes).unwrap(),
            METADATA + 6 * row.record.as_ref().map_or(0, |record| record.payload.len())
        );
        verify_key(&bytes, &storage.business.frontiers, &|| Ok(())).unwrap();
        let mut bad = row.clone();
        bad.fence = storage.business.frontiers.next_fence;
        let bad = postcard::to_allocvec(&(key, Some(&bad))).unwrap();
        assert!(
            key_scratch(&bad).is_ok(),
            "preflight is not semantic admission"
        );
        assert!(verify_key(&bad, &storage.business.frontiers, &|| Ok(())).is_err());
        for prefix in 0..bytes.len() {
            assert!(key_scratch(&bytes[..prefix]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(key_scratch(&trailing).is_err());
    }
    let absent = postcard::to_allocvec(&(key, None::<NativeKeyState>)).unwrap();
    verify_key(&absent, &storage.business.frontiers, &|| Ok(())).unwrap();

    let mut row = (**row).clone();
    let record = row.record.as_mut().unwrap();
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(record.payload.as_bytes()).unwrap();
    let overhead = record.payload.len() - envelope.ciphertext_and_tag.len();
    let limit = crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES;
    envelope.ciphertext_and_tag = vec![0; limit - overhead];
    record.payload = EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
    assert_eq!(record.payload.len(), limit);
    let bytes = postcard::to_allocvec(&(key, Some(&row))).unwrap();
    verify_key(&bytes, &storage.business.frontiers, &|| Ok(())).unwrap();
    envelope.ciphertext_and_tag.push(0);
    row.record.as_mut().unwrap().payload =
        EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
    assert!(key_scratch(&postcard::to_allocvec(&(key, Some(&row))).unwrap()).is_err());
    // A forged length is rejected while the cursor still borrows the input.
    assert!(key_scratch(&postcard::to_allocvec(&usize::MAX).unwrap()).is_err());
}

#[test]
fn native_generation_cold_notification_preflight_covers_all_six_versioned_effect_pairs() {
    let (storage, _, _) = fixture();
    let original = storage
        .business
        .notifications
        .front()
        .unwrap()
        .resident()
        .unwrap();
    let ReplicationOp::Batch { ops } = &original.op else {
        panic!("native V2 notification")
    };
    let ReplicationOp::AcquireLease {
        key,
        owner,
        fence,
        credential_id,
        ttl,
        expires_at,
    } = &ops[0]
    else {
        panic!("acquired lease")
    };
    for renew in [false, true] {
        for mutation in 0..3 {
            let lease = if renew {
                ReplicationOp::RenewLease {
                    key: key.clone(),
                    owner: owner.clone(),
                    fence: *fence,
                    credential_id: *credential_id,
                    ttl: *ttl,
                    expires_at: *expires_at,
                }
            } else {
                ops[0].clone()
            };
            let effect = match mutation {
                0 => ops[1].clone(),
                1 => ReplicationOp::DeleteFenced {
                    key: key.clone(),
                    owner: owner.clone(),
                    fence: *fence,
                },
                _ => ReplicationOp::RefreshTtl {
                    key: key.clone(),
                    owner: owner.clone(),
                    fence: *fence,
                    ttl: *ttl,
                    expires_at: *expires_at,
                },
            };
            let row = ReplicationEntry {
                op: ReplicationOp::Batch {
                    ops: vec![lease, effect],
                },
                ..original.clone()
            };
            let bytes = postcard::to_allocvec(&row).unwrap();
            assert!(notification_scratch(&bytes).is_ok());
            verify_notification(
                &bytes,
                original.sequence,
                &storage.business.frontiers,
                &|| Ok(()),
            )
            .unwrap();
            assert!(verify_notification(
                &bytes,
                original.sequence + 1,
                &storage.business.frontiers,
                &|| Ok(())
            )
            .is_err());
            let decoded: ReplicationEntry = binary::decode(&bytes).unwrap();
            assert_eq!(postcard::to_allocvec(&decoded).unwrap(), bytes);
        }
    }
    let prefix = postcard::to_allocvec(&(original.sequence, &original.tx_id)).unwrap();
    for length in [0, 1, 3, usize::MAX] {
        let mut bytes = prefix.clone();
        bytes.extend(postcard::to_allocvec(&(7u32, length)).unwrap());
        assert!(notification_scratch(&bytes).is_err());
    }
    let mut nested = prefix;
    nested.extend_from_slice(&[7, 2, 7, 2]);
    nested.extend(std::iter::repeat_n(7, 16 * 1024));
    assert!(notification_scratch(&nested).is_err());
}

#[test]
fn native_generation_cold_clock_receipts_use_original_unit_and_error_discriminants() {
    let (mut storage, _, _) = fixture();
    apply(&mut storage, &[clock(2, time(2))]);
    let (id, original) = storage.business.generic_receipts.iter().next().unwrap();
    for result in [
        Ok(SessionMutationOutcome::Unit),
        Err(StoreError::TopologyAuthorityRevoked),
    ] {
        let mut row = (**original).clone();
        ordinary_mut(&mut row).result = result;
        let bytes = postcard::to_allocvec(&(id, Some(&row))).unwrap();
        assert_eq!(generic_scratch(&bytes).unwrap(), METADATA);
        verify_generic(&bytes, &storage.business.frontiers, &|| Ok(())).unwrap();
        let mut bad = row.clone();
        ordinary_mut(&mut bad).sequence = 0;
        let bad = postcard::to_allocvec(&(id, Some(&bad))).unwrap();
        assert!(generic_scratch(&bad).is_ok());
        assert!(verify_generic(&bad, &storage.business.frontiers, &|| Ok(())).is_err());
        for end in 0..bytes.len() {
            assert!(generic_scratch(&bytes[..end]).is_err());
        }
    }
    let absent = postcard::to_allocvec(&(id, None::<NativeGenericReceipt>)).unwrap();
    verify_generic(&absent, &storage.business.frontiers, &|| Ok(())).unwrap();
    let mut recursive = (**original).clone();
    ordinary_mut(&mut recursive).result =
        Ok(SessionMutationOutcome::FencedTransitionV2Batch(vec![]));
    assert!(generic_scratch(&postcard::to_allocvec(&(id, Some(&recursive))).unwrap()).is_err());
}

#[test]
fn native_ordinary_generic_codec_matches_every_result_and_detaches_retained_records() {
    use crate::backend::CompareAndSetResult;
    let (mut storage, _, previous) = fixture();
    apply(&mut storage, &[clock(2, time(2))]);
    let (id, original) = storage.business.generic_receipts.iter().next().unwrap();
    let record = storage
        .business
        .keys
        .values()
        .find_map(|row| row.record.as_ref())
        .unwrap();
    let mut outcomes = vec![
        Ok(SessionMutationOutcome::Unit),
        Ok(SessionMutationOutcome::Lease(previous.lease().clone())),
        Ok(SessionMutationOutcome::ConsumerRecord(None)),
        Ok(SessionMutationOutcome::ConsumerRecord(Some(record.clone()))),
        Ok(SessionMutationOutcome::CompareAndSet(
            CompareAndSetResult::Success,
        )),
        Ok(SessionMutationOutcome::CompareAndSet(
            CompareAndSetResult::Conflict { current: None },
        )),
        Ok(SessionMutationOutcome::CompareAndSet(
            CompareAndSetResult::Conflict {
                current: Some(record.clone()),
            },
        )),
    ];
    outcomes.extend(
        [
            StoreError::NotFound,
            StoreError::StaleFence,
            StoreError::CasConflict,
            StoreError::TopologyAuthorityRevoked,
            StoreError::InvalidSessionTtl,
            StoreError::InvalidRecordExpiry,
            StoreError::LeaseHeld,
            StoreError::LeaseExpired,
            StoreError::SessionRecordReserved,
            StoreError::FencedTransitionRequestExpired,
            StoreError::FencedTransitionStorageExhausted,
            StoreError::InvalidKey("compare-and-set key does not match record key".into()),
            StoreError::PayloadTooLarge {
                actual: usize::MAX,
                max: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
            },
        ]
        .into_iter()
        .map(Err),
    );
    fn retained(response: &SessionConsensusResponse) -> Option<&StoredSessionRecord> {
        match &response.result {
            Ok(
                SessionMutationOutcome::ConsumerRecord(Some(record))
                | SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
                    current: Some(record),
                }),
            ) => Some(record),
            _ => None,
        }
    }
    for result in outcomes {
        let mut row = (**original).clone();
        ordinary_mut(&mut row).result = result;
        let bytes = postcard::to_allocvec(&(id, Some(&row))).unwrap();
        assert_eq!(
            generic_scratch(&bytes).unwrap(),
            METADATA + 6 * retained(row.response().unwrap()).map_or(0, |row| row.payload.len())
        );
        let (actual_id, facts) =
            inspect_generic(&bytes, &storage.business.frontiers, &|| Ok(())).unwrap();
        let copied = owned_generic(
            &bytes,
            actual_id,
            facts.unwrap(),
            &storage.business.frontiers,
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(
            postcard::to_allocvec(&copied).unwrap(),
            postcard::to_allocvec(&row).unwrap()
        );
        if let (Some(expected), Some(actual)) = (
            retained(row.response().unwrap()),
            retained(copied.response().unwrap()),
        ) {
            assert_ne!(
                expected.payload.as_bytes().as_ptr(),
                actual.payload.as_bytes().as_ptr()
            );
            assert_ne!(
                expected.key.stable_id.as_bytes().as_ptr(),
                actual.key.stable_id.as_bytes().as_ptr()
            );
        }
        for prefix in 0..bytes.len() {
            assert!(generic_scratch(&bytes[..prefix]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(generic_scratch(&trailing).is_err());
    }
    let mut row = (**original).clone();
    ordinary_mut(&mut row).result = Err(StoreError::BackendUnavailable(
        "infrastructure must not bind".into(),
    ));
    assert!(generic_scratch(&postcard::to_allocvec(&(id, Some(&row))).unwrap()).is_err());
}

#[test]
fn native_ordinary_single_notifications_and_logs_keep_full_owned_bodies() {
    let (storage, _, previous) = fixture();
    let original = storage
        .business
        .notifications
        .front()
        .unwrap()
        .resident()
        .unwrap();
    let ReplicationOp::Batch { ops } = &original.op else {
        panic!("fixture V2 pair")
    };
    let guard = previous.lease();
    let record = storage
        .business
        .keys
        .values()
        .find_map(|row| row.record.as_ref())
        .unwrap();
    let notifications = vec![
        ops[0].clone(),
        ops[1].clone(),
        ReplicationOp::RenewLease {
            key: guard.key().clone(),
            owner: guard.owner().clone(),
            fence: guard.fence(),
            credential_id: guard.credential_id(),
            ttl: std::time::Duration::from_secs(60),
            expires_at: guard.expires_at(),
        },
        ReplicationOp::ReleaseLease {
            key: guard.key().clone(),
            owner: guard.owner().clone(),
            fence: guard.fence(),
            credential_id: guard.credential_id(),
        },
        ReplicationOp::DeleteFenced {
            key: guard.key().clone(),
            owner: guard.owner().clone(),
            fence: guard.fence(),
        },
        ReplicationOp::RefreshTtl {
            key: guard.key().clone(),
            owner: guard.owner().clone(),
            fence: guard.fence(),
            ttl: std::time::Duration::from_secs(60),
            expires_at: guard.expires_at(),
        },
    ];
    for op in notifications {
        let row = ReplicationEntry {
            op,
            ..original.clone()
        };
        let bytes = postcard::to_allocvec(&row).unwrap();
        verify_notification(
            &bytes,
            row.sequence,
            &storage.business.frontiers,
            &|| Ok(()),
        )
        .unwrap();
        let owned =
            owned_notification(
                &bytes,
                row.sequence,
                &storage.business.frontiers,
                &|| Ok(()),
            )
            .unwrap();
        assert_eq!(postcard::to_allocvec(owned.entry()).unwrap(), bytes);
    }
    let intents = vec![
        SessionMutationIntent::BindConsumerRequest {
            request_commitment: [0x93; 32],
        },
        SessionMutationIntent::ReadConsumerRecord {
            key: guard.key().clone(),
        },
        SessionMutationIntent::CompareAndSet(std::sync::Arc::new(crate::backend::CompareAndSet {
            key: guard.key().clone(),
            expected_generation: Some(record.generation),
            lease: guard.clone(),
            new_record: record.clone(),
        })),
        SessionMutationIntent::DeleteFenced(guard.clone()),
        SessionMutationIntent::ReleaseLease(guard.clone()),
        SessionMutationIntent::RefreshTtl {
            lease: guard.clone(),
            ttl: std::time::Duration::from_secs(60),
        },
        SessionMutationIntent::RenewLease {
            lease: guard.clone(),
            ttl: std::time::Duration::from_secs(60),
        },
        SessionMutationIntent::AcquireLease {
            key: guard.key().clone(),
            owner: guard.owner().clone(),
            ttl: std::time::Duration::from_secs(60),
        },
    ];
    for intent in intents {
        for authorized in [false, true] {
            let mut entry = clock(2, time(2));
            let EntryPayload::Normal(command) = &mut entry.payload else {
                unreachable!()
            };
            command.intent = if authorized {
                SessionMutationIntent::Authorized {
                    origin: *storage.business.members.first().unwrap(),
                    authority_identity: storage.business.identity,
                    mutation: Box::new(intent.clone()),
                }
            } else {
                intent.clone()
            };
            let bytes = serde_json::to_vec(&entry).unwrap();
            verify_log(
                &bytes,
                entry.log_id.index,
                storage.business.identity,
                &storage.business.members,
                &|| Ok(()),
            )
            .unwrap();
            let output = owned_log(
                &bytes,
                entry.log_id.index,
                storage.business.identity,
                &storage.business.members,
                &|| Ok(()),
            )
            .unwrap();
            assert_eq!(serde_json::to_vec(output.entry()).unwrap(), bytes);
        }
    }
}

#[test]
fn native_history_maintenance_log_codec_admits_only_the_raw_internal_intent() {
    let (storage, _, _) = fixture();
    let mut entry = super::super::super::lifecycle_tests::maintenance(&storage, 2, time(2));
    let bytes = serde_json::to_vec(&entry).unwrap();
    verify_log(
        &bytes,
        entry.log_id.index,
        storage.business.identity,
        &storage.business.members,
        &|| Ok(()),
    )
    .unwrap();
    let output = owned_log(
        &bytes,
        entry.log_id.index,
        storage.business.identity,
        &storage.business.members,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(serde_json::to_vec(output.entry()).unwrap(), bytes);
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.intent = SessionMutationIntent::Authorized {
        origin: *storage.business.members.first().unwrap(),
        authority_identity: storage.business.identity,
        mutation: Box::new(command.intent.clone()),
    };
    let wrapped = serde_json::to_vec(&entry).unwrap();
    assert!(
        json::log_scratch(&wrapped).is_err(),
        "allocation preflight rejects the application-authority wrapper"
    );
    assert!(verify_log(
        &wrapped,
        entry.log_id.index,
        storage.business.identity,
        &storage.business.members,
        &|| Ok(())
    )
    .is_err());
    assert!(owned::entry(&entry).is_err());
    assert!(scratch::log_owned(&entry).is_err());
    assert!(log::NativeLog::validate_entry(&entry, &storage.business).is_err());
    assert!(storage.business.prepare(&[entry]).is_err());
}

#[test]
fn native_generation_cold_log_preflight_preserves_complete_decoder_and_legacy_metadata() {
    let (storage, _, previous) = fixture();
    let identity = storage.business.identity;
    let members = &storage.business.members;
    for row in storage.log.entries.values() {
        verify_log(
            &row.resident().unwrap().encoded,
            row.id().index,
            identity,
            members,
            &|| Ok(()),
        )
        .unwrap();
    }
    let renewed = command(2, &request(2, Some(&previous)), time(2), false);
    let mut current_clock = clock(3, time(3));
    let EntryPayload::Normal(value) = &mut current_clock.payload else {
        panic!("clock command")
    };
    value.intent = SessionMutationIntent::Authorized {
        origin: *members.first().unwrap(),
        authority_identity: identity,
        mutation: Box::new(value.intent.clone()),
    };
    for entry in [renewed, current_clock] {
        verify_log(
            &serde_json::to_vec(&entry).unwrap(),
            entry.log_id.index,
            identity,
            members,
            &|| Ok(()),
        )
        .unwrap();
    }
    let membership = storage
        .log
        .entries
        .values()
        .find(|row| {
            matches!(
                row.resident().unwrap().entry.payload,
                EntryPayload::Membership(_)
            )
        })
        .unwrap()
        .resident()
        .unwrap();
    let mut legacy: serde_json::Value = serde_json::from_slice(&membership.encoded).unwrap();
    // Exceed the V2 body metadata counter in deliberately ignored legacy
    // fields. Neither preflight nor the original decoder retains these trees.
    legacy["future_outer"] = serde_json::json!({"ignored":vec![serde_json::json!({"a":[]} );1024]});
    legacy["payload"]["Membership"]["future_member"] =
        serde_json::json!({"also_ignored":vec![0u8;4096]});
    let encoded = serde_json::to_vec(&legacy).unwrap();
    let decoded = crate::sqlite::consensus::decode_consensus_log_entry(&encoded).unwrap();
    assert!(decoded == membership.entry);
    verify_log(
        &encoded,
        decoded.log_id.index,
        identity,
        members,
        &|| Ok(()),
    )
    .unwrap();
    // Distinct-node count, not raw duplicate count, controls membership memory.
    let original = String::from_utf8(membership.encoded.to_vec()).unwrap();
    let duplicate = original.replace("[7,8,9]", &format!("[{},8,9]", vec!["7"; 1024].join(",")));
    let decoded =
        crate::sqlite::consensus::decode_consensus_log_entry(duplicate.as_bytes()).unwrap();
    assert!(decoded == membership.entry);
    verify_log(
        duplicate.as_bytes(),
        decoded.log_id.index,
        identity,
        members,
        &|| Ok(()),
    )
    .unwrap();
    let normal = storage
        .log
        .entries
        .values()
        .find(|row| {
            matches!(
                row.resident().unwrap().entry.payload,
                EntryPayload::Normal(_)
            )
        })
        .unwrap()
        .resident()
        .unwrap();
    let mut unknown: serde_json::Value = serde_json::from_slice(&normal.encoded).unwrap();
    unknown["unknown"] = serde_json::json!(1);
    let unknown = serde_json::to_vec(&unknown).unwrap();
    assert!(
        json::log_scratch(&unknown).is_ok(),
        "shape is not exact durable schema"
    );
    assert!(verify_log(
        &unknown,
        normal.entry.log_id.index,
        identity,
        members,
        &|| Ok(())
    )
    .is_err());
    let mut blank = serde_json::json!({"log_id":normal.entry.log_id,"payload":"Blank","unknown":{"FencedTransitionV2":null}});
    let hidden = serde_json::to_vec(&blank).unwrap();
    assert!(json::log_scratch(&hidden).is_ok());
    assert!(verify_log(
        &hidden,
        normal.entry.log_id.index,
        identity,
        members,
        &|| Ok(())
    )
    .is_err());
    blank.as_object_mut().unwrap().remove("unknown");
    verify_log(
        &serde_json::to_vec(&blank).unwrap(),
        normal.entry.log_id.index,
        identity,
        members,
        &|| Ok(()),
    )
    .unwrap();
}

#[test]
fn native_generation_cold_log_preflight_accepts_original_256_profile_and_exact_16mib_conflict() {
    let _large_row = scratch::LARGE_ROW_TEST.lock().unwrap();
    let (storage, original, _) = fixture();
    let identity = storage.business.identity;
    let members = &storage.business.members;
    let mut entry = clock(2, time(2));
    let EntryPayload::Normal(value) = &mut entry.payload else {
        panic!("normal command")
    };
    let requests = (0..crate::consensus::types::MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS)
        .map(|nonce| request(100 + nonce as u64, None))
        .collect::<Vec<_>>();
    value.request_id = SessionConsensusRequestId::from_bytes(
        crate::consensus::types::fenced_transition_v2_batch_outer_request_id(&requests).unwrap(),
    );
    value.intent = SessionMutationIntent::FencedTransitionV2Batch(requests.clone());
    verify_log(
        &serde_json::to_vec(&entry).unwrap(),
        2,
        identity,
        members,
        &|| Ok(()),
    )
    .unwrap();
    let EntryPayload::Normal(value) = &mut entry.payload else {
        unreachable!()
    };
    value.intent = SessionMutationIntent::Authorized {
        origin: *members.first().unwrap(),
        authority_identity: identity,
        mutation: Box::new(value.intent.clone()),
    };
    verify_log(
        &serde_json::to_vec(&entry).unwrap(),
        2,
        identity,
        members,
        &|| Ok(()),
    )
    .unwrap();
    let EntryPayload::Normal(value) = &mut entry.payload else {
        unreachable!()
    };
    let mut too_many = requests;
    too_many.push(request(1000, None));
    value.intent = SessionMutationIntent::FencedTransitionV2Batch(too_many);
    assert!(json::log_scratch(&serde_json::to_vec(&entry).unwrap()).is_err());

    #[derive(Serialize)]
    struct Wire<'a> {
        request_id: FencedTransitionV2RequestId,
        lease: &'a FencedTransitionLease,
        mutation: FencedTransitionMutation,
    }
    let conflict = |length: usize, extra_digit: bool| {
        let mut record = original.mutation().record().unwrap().clone();
        let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(record.payload.as_bytes()).unwrap();
        envelope.ciphertext_and_tag = vec![0; length];
        if extra_digit {
            *envelope.ciphertext_and_tag.last_mut().unwrap() = 10;
        }
        record.payload = EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
        let bytes = postcard::to_allocvec(&Wire {
            request_id: original.request_id(),
            lease: original.lease(),
            mutation: FencedTransitionMutation::create(record),
        })
        .unwrap();
        postcard::from_bytes::<FencedTransitionV2Request>(&bytes).unwrap()
    };
    let small = serde_json::to_vec(&command(2, &conflict(16, false), time(2), false))
        .unwrap()
        .len();
    let limit = crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES;
    let extra = limit - small;
    let large = conflict(16 + extra / 2, !extra.is_multiple_of(2));
    assert!(matches!(
        large.validate(),
        Err(StoreError::FencedTransitionRequestConflict)
    ));
    let bytes = serde_json::to_vec(&command(2, &large, time(2), false)).unwrap();
    assert_eq!(bytes.len(), limit);
    assert!(json::log_scratch(&bytes).unwrap() + bytes.len() < 128 * 1024 * 1024);
    verify_log(&bytes, 2, identity, members, &|| Ok(())).unwrap();
    let copied = owned_log(&bytes, 2, identity, members, &|| Ok(())).unwrap();
    assert!(
        copied.entry() == &command(2, &large, time(2), false),
        "owned copy preserves the complete original conflict body"
    );
    drop(copied);
    assert!(verify_log(&bytes, 3, identity, members, &|| Ok(())).is_err());
    let mut oversized = bytes;
    oversized.push(b' ');
    assert!(json::log_scratch(&oversized).is_err());
}

#[test]
fn native_generation_cold_log_preflight_rejects_recursive_authority_and_unbounded_request_metadata()
{
    let (storage, original, _) = fixture();
    let mut row = serde_json::to_value(command(2, &original, time(2), false)).unwrap();
    let intent = row["payload"]["Normal"]["intent"].clone();
    row["payload"]["Normal"]["intent"] =
        serde_json::json!({"Authorized":{"mutation":{"Authorized":{"mutation":intent}}}});
    assert!(json::log_scratch(&serde_json::to_vec(&row).unwrap()).is_err());
    row = serde_json::to_value(command(2, &original, time(2), false)).unwrap();
    let body = row["payload"]["Normal"]["intent"]["FencedTransitionV2"]
        .as_object_mut()
        .unwrap();
    for index in 0..129 {
        body.insert(format!("unknown{index}"), serde_json::json!({}));
    }
    assert!(json::log_scratch(&serde_json::to_vec(&row).unwrap()).is_err());
    let bytes = serde_json::to_vec(&command(2, &original, time(2), false)).unwrap();
    assert!(verify_log(
        &bytes,
        2,
        storage.business.identity,
        &storage.business.members,
        &|| Err(invalid("cancelled before preflight"))
    )
    .is_err());
}

#[test]
fn native_owned_key_notification_and_log_copies_release_decoder_backing_with_large_valid_aad() {
    use crate::fenced_transition::{FencedTransitionV2CallerNonce, FencedTransitionV2HistoryEpoch};
    use std::time::Duration;
    let (mut storage, original, _) = fixture();
    let mut record = original.mutation().record().unwrap().clone();
    record.key.stable_id = bytes::Bytes::from(vec![b'k'; crate::model::STABLE_ID_MAX_BYTES])
        .try_into()
        .unwrap();
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("native-owned-copy-test").unwrap(),
        opc_key::KeyPurpose::Session,
        record.key.tenant.clone(),
        opc_key::Zeroizing::new([0x44; opc_key::AES_256_GCM_SIV_KEY_LEN]),
    );
    let namespace = "n".repeat(128 * 1024);
    let aad = crate::record::build_session_envelope_aad(&record, &namespace, &handle).unwrap();
    let encoded = opc_crypto::encrypt_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        b"native owned output",
        [0x45; opc_key::AES_256_GCM_SIV_NONCE_LEN],
    )
    .unwrap();
    assert_eq!(
        opc_crypto::decrypt_envelope_with_handle(&handle, &aad, &encoded)
            .unwrap()
            .as_slice(),
        b"native owned output"
    );
    assert!(encoded.len() > namespace.len());
    record.payload = EncryptedSessionPayload::try_envelope(encoded).unwrap();
    let lease = FencedTransitionLease::acquire(
        record.key.clone(),
        record.owner.clone(),
        FenceToken::new(0),
        Duration::from_secs(60),
    )
    .unwrap();
    let request = FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
        FencedTransitionV2CallerNonce::from_bytes([0x46; 16]),
        lease,
        FencedTransitionMutation::create(record),
    )
    .unwrap();
    let entry = command(2, &request, time(2), false);
    apply(&mut storage, std::slice::from_ref(&entry));

    let (key, row) = storage
        .business
        .keys
        .iter()
        .find(|(key, _)| **key == *request.lease().key())
        .unwrap();
    let key_bytes = postcard::to_allocvec(&(key, Some(&**row))).unwrap();
    let (key_id, facts) = inspect_key(&key_bytes, &storage.business.frontiers, &|| Ok(())).unwrap();
    let owned_key = owned_key(
        &key_bytes,
        key_id,
        facts.unwrap(),
        &storage.business.frontiers,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(
        postcard::to_allocvec(&(&owned_key.key, Some(&owned_key.row))).unwrap(),
        key_bytes
    );
    assert_ne!(
        owned_key.key.stable_id.as_bytes().as_ptr(),
        key.stable_id.as_bytes().as_ptr()
    );
    assert_ne!(
        owned_key
            .row
            .record
            .as_ref()
            .unwrap()
            .payload
            .as_bytes()
            .as_ptr(),
        row.record.as_ref().unwrap().payload.as_bytes().as_ptr()
    );
    drop(owned_key);

    fn notification_record(entry: &ReplicationEntry) -> &StoredSessionRecord {
        let ReplicationOp::Batch { ops } = &entry.op else {
            panic!("notification batch")
        };
        let ReplicationOp::CompareAndSet { new_record, .. } = &ops[1] else {
            panic!("notification record")
        };
        new_record
    }
    let notification = storage
        .business
        .notifications
        .back()
        .unwrap()
        .resident()
        .unwrap();
    let bytes = postcard::to_allocvec(notification).unwrap();
    let _notification_memory =
        VerificationMemory::reserve(notification_scratch(&bytes).unwrap()).unwrap();
    let decoded: ReplicationEntry = binary::decode(&bytes).unwrap();
    validation::validate_notification(&decoded, notification.sequence, &storage.business.frontiers)
        .unwrap();
    let weak = notification_record(&decoded)
        .payload
        .log_row_reuse_test_weak_bytes();
    let copied = owned::notification(&decoded).unwrap();
    assert_ne!(
        notification_record(&copied).payload.as_bytes().as_ptr(),
        notification_record(&decoded).payload.as_bytes().as_ptr()
    );
    assert_ne!(
        notification_record(&copied)
            .key
            .stable_id
            .as_bytes()
            .as_ptr(),
        notification_record(&decoded)
            .key
            .stable_id
            .as_bytes()
            .as_ptr()
    );
    drop(decoded);
    assert!(
        weak.upgrade().is_none(),
        "no notification decoder allocation survives its boundary"
    );
    assert_eq!(postcard::to_allocvec(&copied).unwrap(), bytes);
    drop(copied);
    drop(_notification_memory);
    let output = owned_notification(
        &bytes,
        notification.sequence,
        &storage.business.frontiers,
        &|| Ok(()),
    )
    .unwrap();
    assert_eq!(postcard::to_allocvec(output.entry()).unwrap(), bytes);
    drop(output);

    fn log_request(entry: &Entry<SessionRaftTypeConfig>) -> &FencedTransitionV2Request {
        let EntryPayload::Normal(command) = &entry.payload else {
            panic!("normal log")
        };
        let SessionMutationIntent::FencedTransitionV2(request) = &command.intent else {
            panic!("V2 log")
        };
        request
    }
    let bytes = serde_json::to_vec(&entry).unwrap();
    let _log_memory = VerificationMemory::reserve(json::log_scratch(&bytes).unwrap()).unwrap();
    let decoded = crate::sqlite::consensus::decode_consensus_log_entry(&bytes).unwrap();
    let decoded_record = log_request(&decoded).mutation().record().unwrap();
    let weak = decoded_record.payload.log_row_reuse_test_weak_bytes();
    let copied = owned::entry(&decoded).unwrap();
    let copied_record = log_request(&copied).mutation().record().unwrap();
    assert_ne!(
        copied_record.payload.as_bytes().as_ptr(),
        decoded_record.payload.as_bytes().as_ptr()
    );
    assert_ne!(
        copied_record.key.stable_id.as_bytes().as_ptr(),
        decoded_record.key.stable_id.as_bytes().as_ptr()
    );
    assert_ne!(
        log_request(&copied)
            .lease()
            .key()
            .stable_id
            .as_bytes()
            .as_ptr(),
        log_request(&decoded)
            .lease()
            .key()
            .stable_id
            .as_bytes()
            .as_ptr()
    );
    drop(decoded);
    assert!(
        weak.upgrade().is_none(),
        "no log decoder allocation survives its boundary"
    );
    assert!(copied == entry);
    drop(copied);
    drop(_log_memory);
    let output = owned_log(
        &bytes,
        2,
        storage.business.identity,
        &storage.business.members,
        &|| Ok(()),
    )
    .unwrap();
    assert!(output.entry() == &entry);
}

fn ordinary_mut(row: &mut NativeGenericReceipt) -> &mut SessionConsensusResponse {
    let NativeGenericReceipt::Ordinary(row) = row else {
        panic!("ordinary fixture");
    };
    &mut row.response
}

#[test]
fn native_v1_codec_preflights_closed_results_versions_and_expired_tombstones() {
    let (storage, first, _) = super::super::super::v1::tests::fixture();
    let id = SessionConsensusRequestId::from_bytes(*first.request_id().as_bytes());
    let original = &**storage.business.generic_receipts.get(&id).unwrap();
    let NativeGenericReceipt::FencedV1(value) = original else {
        unreachable!()
    };
    let mut results = vec![value.response.as_ref().unwrap().result.clone()];
    results.extend(
        [
            StoreError::TopologyAuthorityRevoked,
            StoreError::NotFound,
            StoreError::StaleFence,
            StoreError::CasConflict,
            StoreError::InvalidSessionTtl,
            StoreError::InvalidRecordExpiry,
            StoreError::LeaseHeld,
            StoreError::LeaseExpired,
            StoreError::PayloadTooLarge {
                actual: usize::MAX,
                max: 1,
            },
            StoreError::FencedTransitionStorageExhausted,
        ]
        .into_iter()
        .map(Err),
    );
    for result in results {
        let mut row = value.clone();
        row.response.as_mut().unwrap().result = result;
        let row = NativeGenericReceipt::FencedV1(row);
        let bytes = postcard::to_allocvec(&(id, Some(&row))).unwrap();
        assert_eq!(generic_scratch(&bytes).unwrap(), METADATA);
        let (_, facts) = inspect_generic(&bytes, &storage.business.frontiers, &|| Ok(())).unwrap();
        let copied = owned_generic(
            &bytes,
            id,
            facts.unwrap(),
            &storage.business.frontiers,
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(
            postcard::to_allocvec(&copied).unwrap(),
            postcard::to_allocvec(&row).unwrap()
        );
        if let (
            Ok(SessionMutationOutcome::FencedTransition(expected)),
            Ok(SessionMutationOutcome::FencedTransition(actual)),
        ) = (
            &row.response().unwrap().result,
            &copied.response().unwrap().result,
        ) {
            assert_ne!(
                expected.lease().key().stable_id.as_bytes().as_ptr(),
                actual.lease().key().stable_id.as_bytes().as_ptr()
            );
        }
        let full = postcard::to_allocvec(&(id, &row)).unwrap();
        assert_eq!(
            postcard::to_allocvec(
                &full_generic(&full, Format::V3, &storage.business.frontiers)
                    .unwrap()
                    .1
            )
            .unwrap(),
            postcard::to_allocvec(&row).unwrap()
        );
        assert!(inspect_generic_format(
            &bytes,
            Format::V2,
            &storage.business.frontiers,
            &|| Ok(())
        )
        .is_err());
        for end in 0..bytes.len() {
            assert!(generic_scratch(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(generic_scratch(&trailing).is_err());
        let mut unknown = bytes;
        unknown[17] = 2;
        assert!(generic_scratch(&unknown).is_err());
    }
    for result in [
        Err(StoreError::SessionRecordReserved),
        Err(StoreError::FencedTransitionRequestExpired),
        Err(StoreError::InvalidKey("untrusted diagnostic".into())),
        Ok(SessionMutationOutcome::ConsumerRecord(None)),
        Ok(SessionMutationOutcome::FencedTransitionV2Batch(Vec::new())),
    ] {
        let mut row = value.clone();
        row.response.as_mut().unwrap().result = result;
        let row = NativeGenericReceipt::FencedV1(row);
        assert!(verify_generic(
            &postcard::to_allocvec(&(id, Some(&row))).unwrap(),
            &storage.business.frontiers,
            &|| Ok(())
        )
        .is_err());
        assert!(full_generic(
            &postcard::to_allocvec(&(id, &row)).unwrap(),
            Format::V3,
            &storage.business.frontiers
        )
        .is_err());
    }
    let tombstone = NativeGenericReceipt::FencedV1(NativeV1Receipt {
        response: None,
        ..value.clone()
    });
    let bytes = postcard::to_allocvec(&(id, Some(&tombstone))).unwrap();
    assert_eq!(generic_scratch(&bytes).unwrap(), METADATA);
    assert!(verify_generic(&bytes, &storage.business.frontiers, &|| Ok(())).is_err());
    let mut expired = storage.business.frontiers.clone();
    expired.logical_time = Some(value.retained_until);
    verify_generic(&bytes, &expired, &|| Ok(())).unwrap();
    expired.v1_activation = None;
    assert!(verify_generic(&bytes, &expired, &|| Ok(())).is_err());
}
