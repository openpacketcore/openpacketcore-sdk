use super::*;
use crate::backend::ProtectedRosterEstablishedSuccessor as Successor;
use crate::consensus::types::{
    protected_roster_profile_v2_voter_set_digest, ConsensusRosterAdmissionCommand,
    RosterV2PersistenceFixture,
};
use opc_consensus::engine::CommittedLeaderId;

fn members() -> BTreeSet<SessionConsensusNodeId> {
    [7, 8, 9]
        .into_iter()
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .collect()
}

fn admission(signed: &RosterV2PersistenceFixture) -> ConsensusRosterAdmissionCommand {
    ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id_v2(
        signed.admission.clone(),
        signed.authority.clone(),
        signed.admission_ingress.request_id(),
        signed.admission_ingress.clone(),
        signed.admission_provenance.clone(),
    )
    .unwrap()
}

fn entry(
    signed: &RosterV2PersistenceFixture,
    index: u64,
    request_id: SessionConsensusRequestId,
    mutation: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    let origin = SessionConsensusNodeId::new(7).unwrap();
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, origin), index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: signed.identity,
            request_id,
            logical_time: signed.authority.acquired_at().add_seconds(1).unwrap(),
            intent: SessionMutationIntent::Authorized {
                origin,
                authority_identity: signed.identity,
                mutation: Box::new(mutation),
            },
        }),
    }
}

fn inner(value: &Entry<SessionRaftTypeConfig>) -> &SessionMutationIntent {
    let EntryPayload::Normal(command) = &value.payload else {
        unreachable!()
    };
    let SessionMutationIntent::Authorized { mutation, .. } = &command.intent else {
        unreachable!()
    };
    mutation
}

fn copy_log(value: &Entry<SessionRaftTypeConfig>, identity: SessionConsensusIdentity) {
    let bytes = serde_json::to_vec(value).unwrap();
    let model = crate::sqlite::consensus::decode_consensus_log_entry(&bytes).unwrap();
    let copied = owned::entry(&model).unwrap();
    assert!(copied == model);
    let different_key = |left: &SessionKey, right: &SessionKey| {
        assert_eq!(left, right);
        assert_ne!(
            left.stable_id.as_bytes().as_ptr(),
            right.stable_id.as_bytes().as_ptr()
        );
    };
    match (inner(&model), inner(&copied)) {
        (
            SessionMutationIntent::RosterAdmissionV2(left),
            SessionMutationIntent::RosterAdmissionV2(right),
        ) => {
            different_key(left.authority().key(), right.authority().key());
            different_key(left.admission().key(), right.admission().key());
            for (left, right) in [
                (
                    left.admission().protected_plan(),
                    right.admission().protected_plan(),
                ),
                (
                    left.admission().terminal_checkpoint(),
                    right.admission().terminal_checkpoint(),
                ),
                (
                    left.admission().terminal_result(),
                    right.admission().terminal_result(),
                ),
            ] {
                assert_eq!(left, right);
                if !left.is_empty() {
                    assert_ne!(left.as_ptr(), right.as_ptr());
                }
            }
            for (left, right) in left
                .admission()
                .members()
                .iter()
                .zip(right.admission().members())
            {
                assert_ne!(left.descriptor().as_ptr(), right.descriptor().as_ptr());
            }
        }
        (
            SessionMutationIntent::RosterTerminalV2(left),
            SessionMutationIntent::RosterTerminalV2(right),
        ) => {
            different_key(left.authority().key(), right.authority().key());
            assert_ne!(left.record_bytes().as_ptr(), right.record_bytes().as_ptr());
        }
        (
            SessionMutationIntent::ActivateProtectedRosterProfileV2 { .. },
            SessionMutationIntent::ActivateProtectedRosterProfileV2 { .. },
        ) => {}
        _ => unreachable!(),
    }
    drop(model);
    assert_eq!(serde_json::to_vec(&copied).unwrap(), bytes);
    drop(copied);
    verify_log(&bytes, value.log_id.index, identity, &members(), &|| Ok(())).unwrap();
    let mut output =
        owned_log(&bytes, value.log_id.index, identity, &members(), &|| Ok(())).unwrap();
    assert!(output.entry() == value);
    let retained = scratch::log_owned(output.entry()).unwrap();
    assert!(retained < json::log_scratch(&bytes).unwrap());
    output._memory.shrink_to(retained).unwrap();
    assert!(
        output._memory.shrink_to(retained + 1).is_err(),
        "the output keeps exactly its independent allocation reservation"
    );
    let resident = log::NativeLogEntry::new(bytes.into(), value.clone());
    resident
        .validate_full(value.log_id.index, identity, &members(), &|| Ok(()))
        .unwrap();
}

#[test]
fn native_roster_log_codecs_preserve_signed_capsules_and_reject_wrong_authority_shapes() {
    for signed in [
        crate::consensus::types::roster_v2_persistence_fixture(),
        crate::consensus::types::roster_v2_aborted_persistence_fixture(),
    ] {
        let q1 = admission(&signed);
        let entries = [
            entry(
                &signed,
                1,
                q1.request_id().unwrap(),
                SessionMutationIntent::RosterAdmissionV2(Box::new(q1)),
            ),
            entry(
                &signed,
                2,
                signed.terminal_command.request_id().unwrap(),
                SessionMutationIntent::RosterTerminalV2(Box::new(signed.terminal_command.clone())),
            ),
            entry(
                &signed,
                3,
                SessionConsensusRequestId::from_bytes([0xE1; 16]),
                SessionMutationIntent::ActivateProtectedRosterProfileV2 {
                    schema_version: crate::fenced_mutation_roster::Profile::v2().schema(),
                    consumer_revision: crate::fenced_mutation_roster::Profile::v2()
                        .consumer_revision(),
                    scope_identity: signed.identity,
                    voter_set_digest: protected_roster_profile_v2_voter_set_digest(
                        signed.identity,
                        &members(),
                    ),
                    profile_digest: crate::fenced_mutation_roster::Profile::v2().digest(),
                },
            ),
        ];
        for value in &entries {
            copy_log(value, signed.identity);
        }
        for original in &entries[..2] {
            for case in 0..3 {
                let mut value = original.clone();
                let EntryPayload::Normal(command) = &mut value.payload else {
                    unreachable!()
                };
                let mutation = inner(original).clone();
                command.intent = match case {
                    0 => mutation,
                    1 => SessionMutationIntent::Authorized {
                        origin: SessionConsensusNodeId::new(7).unwrap(),
                        authority_identity: signed.identity,
                        mutation: Box::new(command.intent.clone()),
                    },
                    2 => SessionMutationIntent::Authorized {
                        origin: SessionConsensusNodeId::new(10).unwrap(),
                        authority_identity: signed.identity,
                        mutation: Box::new(mutation),
                    },
                    _ => unreachable!(),
                };
                let bytes = serde_json::to_vec(&value).unwrap();
                if case < 2 {
                    assert!(json::log_scratch(&bytes).is_err());
                    assert!(owned::entry(&value).is_err());
                    assert!(scratch::log_owned(&value).is_err());
                }
                assert!(verify_log(
                    &bytes,
                    value.log_id.index,
                    signed.identity,
                    &members(),
                    &|| Ok(())
                )
                .is_err());
                assert!(owned_log(
                    &bytes,
                    value.log_id.index,
                    signed.identity,
                    &members(),
                    &|| Ok(())
                )
                .is_err());
                assert!(log::NativeLog::validate_entry_context(
                    &value,
                    signed.identity,
                    &members()
                )
                .is_err());
            }
            let bytes = serde_json::to_vec(original).unwrap();
            assert!(owned_log(
                &bytes,
                original.log_id.index,
                signed.identity,
                &members(),
                &|| Err(io::Error::other("cancelled"))
            )
            .is_err());
            let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let intent = &mut json["payload"]["Normal"]["intent"]["Authorized"]["mutation"];
            let name = if original.log_id.index == 1 {
                "RosterAdmissionV2"
            } else {
                "RosterTerminalV2"
            };
            intent[name]["ingress_attestation"] = serde_json::json!(vec![
                0u8;
                crate::fenced_mutation_roster::MAX_ROSTER_INGRESS_ATTESTATION_BYTES
                    + 1
            ]);
            let malformed = serde_json::to_vec(&json).unwrap();
            assert!(
                json::log_scratch(&malformed).is_ok(),
                "shape accounting is not capsule admission"
            );
            assert!(verify_log(
                &malformed,
                original.log_id.index,
                signed.identity,
                &members(),
                &|| Ok(())
            )
            .is_err());
        }
    }
}

#[test]
fn native_roster_log_maximum_admission_body_keeps_original_bounds_and_detached_storage() {
    use crate::fenced_mutation_roster::{
        Admission, AdmissionProposal, Member, MemberOperationId, MAX_CHECKPOINT_BYTES,
        MAX_DESCRIPTOR_BYTES, MAX_MEMBERS, MAX_PLAN_BYTES, MAX_RESULT_BYTES,
    };
    let _large = scratch::LARGE_ROW_TEST.lock().unwrap();
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let original = &signed.admission;
    let proposal = AdmissionProposal::new(
        original.profile(),
        original.roster_id(),
        (0..MAX_MEMBERS)
            .map(|index| {
                Member::new(
                    index as u8,
                    MemberOperationId::from_bytes([index as u8 + 1; 16]).unwrap(),
                    vec![0xF1; MAX_DESCRIPTOR_BYTES],
                    u64::MAX,
                )
                .unwrap()
            })
            .collect(),
        original.established_mutation().clone(),
        vec![0xF2; MAX_PLAN_BYTES],
        vec![0xF3; MAX_CHECKPOINT_BYTES],
        vec![0xF4; MAX_RESULT_BYTES],
    )
    .unwrap();
    let maximum = Admission::authenticate(
        proposal,
        original.key().clone(),
        original.scope(),
        original.logical_owner().clone(),
        original.admission_fence(),
        original.expected_generation(),
    )
    .unwrap();
    // Keep the original signed carriers. This is a maximum syntactic command
    // body, not a new authenticated admission; the evaluator must still reject
    // its mismatching provenance. Log ownership must preserve even that body.
    let q1 = ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id_v2(
        maximum,
        signed.authority.clone(),
        signed.admission_ingress.request_id(),
        signed.admission_ingress.clone(),
        signed.admission_provenance.clone(),
    )
    .unwrap();
    let value = entry(
        &signed,
        1,
        q1.request_id().unwrap(),
        SessionMutationIntent::RosterAdmissionV2(Box::new(q1)),
    );
    copy_log(&value, signed.identity);
    let mut state = NativeState::empty(signed.identity, members()).unwrap();
    state.roster_root = Some(Arc::new(signed.root.clone()));
    state.frontiers.roster_v2_activation = Some(NativeActivation {
        identity: signed.identity,
        voters: protected_roster_profile_v2_voter_set_digest(signed.identity, &state.members),
        profile: original.profile().digest(),
    });
    let guard = LeaseGuard::new(
        signed.authority.key().clone(),
        signed.authority.owner().clone(),
        signed.authority.fence(),
        signed.authority.acquired_at(),
        signed.authority.expires_at(),
        signed.authority.credential_id(),
    );
    state.keys.insert(
        guard.key().clone(),
        SharedRow::new(NativeKeyState {
            record: None,
            lease: Some(NativeLease::from_guard(&guard).unwrap()),
            fence: guard.fence().get(),
            reserved: false,
        }),
    );
    state.frontiers.next_fence = guard.fence().get() + 1;
    state.frontiers.next_credential = guard.credential_id() + 1;
    state.frontiers.logical_time = Some(signed.authority.acquired_at().add_seconds(1).unwrap());
    state.admit_business().unwrap();
    let origin = SessionConsensusNodeId::new(7).unwrap();
    state
        .apply(&[Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, origin), 0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![members()],
                members(),
            )),
        }])
        .unwrap();
    let rejected = state.apply(std::slice::from_ref(&value)).unwrap();
    assert!(matches!(
        rejected.responses[0].result,
        Ok(SessionMutationOutcome::RosterAdmissionV2(
            crate::consensus::types::ConsensusRosterAdmissionOutcome::Rejected { .. }
        ))
    ));
    assert!(state.roster.rows.is_empty() && !state.keys[guard.key()].reserved);
    let mut bytes = serde_json::to_vec(&value).unwrap();
    assert!(bytes.len() < crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES);
    bytes.truncate(bytes.len() - 1);
    assert!(verify_log(&bytes, 1, signed.identity, &members(), &|| Ok(())).is_err());
}

#[test]
fn native_roster_notification_codecs_charge_both_records_and_release_decoder_payloads() {
    let (storage, request, previous) = fixture();
    let original = storage
        .business
        .notifications
        .front()
        .unwrap()
        .resident()
        .unwrap();
    let make_record = |generation| {
        let mut record = request.mutation().record().unwrap().clone();
        record.generation = crate::Generation::new(generation);
        let handle = opc_key::KeyHandle::new(
            opc_key::KeyId::new("native-roster-notification-codec").unwrap(),
            opc_key::KeyPurpose::Session,
            record.key.tenant.clone(),
            opc_key::Zeroizing::new([0xE2; opc_key::AES_256_GCM_SIV_KEY_LEN]),
        );
        let aad =
            crate::record::build_session_envelope_aad(&record, &"r".repeat(128 * 1024), &handle)
                .unwrap();
        record.payload = EncryptedSessionPayload::try_envelope(
            opc_crypto::encrypt_envelope_with_handle_and_nonce(
                &handle,
                &aad,
                b"roster event",
                [generation as u8; opc_key::AES_256_GCM_SIV_NONCE_LEN],
            )
            .unwrap(),
        )
        .unwrap();
        record
    };
    let before = make_record(1);
    let after = make_record(2);
    let guard = previous.lease();
    for kind in 0..4 {
        let op = if kind == 3 {
            ReplicationOp::ProtectedRosterEstablishedCreate {
                key: before.key.clone(),
                record: before.clone(),
                owner: guard.owner().clone(),
                fence: guard.fence(),
                credential_id: guard.credential_id(),
                guard_acquired_at: guard.acquired_at(),
                guard_expires_at: guard.expires_at(),
            }
        } else {
            let successor = match kind {
                0 => Successor::Put {
                    record: Box::new(after.clone()),
                },
                1 => Successor::Delete,
                2 => Successor::NoOp,
                _ => unreachable!(),
            };
            ReplicationOp::ProtectedRosterEstablished {
                key: before.key.clone(),
                expected_record: before.clone(),
                successor: Box::new(successor),
                owner: guard.owner().clone(),
                fence: guard.fence(),
                credential_id: guard.credential_id(),
                guard_acquired_at: guard.acquired_at(),
                guard_expires_at: guard.expires_at(),
            }
        };
        let value = ReplicationEntry {
            op,
            ..original.clone()
        };
        let bytes = postcard::to_allocvec(&value).unwrap();
        let payload = before.payload.len() + if kind == 0 { after.payload.len() } else { 0 };
        assert_eq!(changes::notification_payload(&value).unwrap(), payload);
        assert_eq!(
            notification_scratch(&bytes).unwrap(),
            METADATA + 6 * payload
        );
        let records = |entry: &ReplicationEntry| -> Vec<StoredSessionRecord> {
            match &entry.op {
                ReplicationOp::ProtectedRosterEstablished {
                    expected_record,
                    successor,
                    ..
                } => {
                    let mut records = vec![expected_record.clone()];
                    if let Successor::Put { record } = &**successor {
                        records.push((**record).clone());
                    }
                    records
                }
                ReplicationOp::ProtectedRosterEstablishedCreate { record, .. } => {
                    vec![record.clone()]
                }
                _ => unreachable!(),
            }
        };
        let memory = VerificationMemory::reserve(notification_scratch(&bytes).unwrap()).unwrap();
        let decoded: ReplicationEntry = binary::decode(&bytes).unwrap();
        let decoded_records = records(&decoded);
        let weak: Vec<_> = decoded_records
            .iter()
            .map(|record| record.payload.log_row_reuse_test_weak_bytes())
            .collect();
        let copied = owned::notification(&decoded).unwrap();
        let copied_records = records(&copied);
        for (left, right) in decoded_records.iter().zip(&copied_records) {
            assert_ne!(
                left.payload.as_bytes().as_ptr(),
                right.payload.as_bytes().as_ptr()
            );
            assert_ne!(
                left.key.stable_id.as_bytes().as_ptr(),
                right.key.stable_id.as_bytes().as_ptr()
            );
        }
        drop(decoded_records);
        drop(decoded);
        assert!(weak.iter().all(|weak| weak.upgrade().is_none()));
        assert_eq!(postcard::to_allocvec(&copied).unwrap(), bytes);
        drop(copied_records);
        drop(copied);
        drop(memory);
        let output =
            owned_notification(&bytes, value.sequence, &storage.business.frontiers, &|| {
                Ok(())
            })
            .unwrap();
        assert_eq!(postcard::to_allocvec(output.entry()).unwrap(), bytes);
        assert!(owned_notification(
            &bytes,
            value.sequence + 1,
            &storage.business.frontiers,
            &|| Ok(())
        )
        .is_err());
        assert!(owned_notification(
            &bytes,
            value.sequence,
            &storage.business.frontiers,
            &|| Err(io::Error::other("cancelled"))
        )
        .is_err());
        for length in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(notification_scratch(&bytes[..length]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(notification_scratch(&trailing).is_err());
    }
    let invalid_successor = postcard::to_allocvec(&(
        original.sequence,
        &original.tx_id,
        6u32,
        &before.key,
        &before,
        3u32,
    ))
    .unwrap();
    assert!(notification_scratch(&invalid_successor).is_err());
    let nested =
        postcard::to_allocvec(&(original.sequence, &original.tx_id, 7u32, 2usize, 6u32)).unwrap();
    assert!(notification_scratch(&nested).is_err());
}
