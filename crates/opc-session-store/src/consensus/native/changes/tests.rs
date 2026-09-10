use super::*;
use crate::consensus::{
    SessionConsensusClusterId, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
};
use crate::fenced_transition::{
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2CallerNonce,
    FencedTransitionV2HistoryEpoch,
};
use crate::sqlite::consensus::wal::Operation;
use crate::{
    EncryptedSessionPayload, FenceToken, Generation, OwnerId, SessionKeyType, StateClass, StateType,
};
use bytes::Bytes;
use opc_consensus::engine::{CommittedLeaderId, Membership};
use opc_types::{NetworkFunctionKind, TenantId};
use std::str::FromStr;
use std::time::Duration;

fn identity() -> SessionConsensusIdentity {
    SessionConsensusIdentity::new(
        SessionConsensusClusterId::new("native-changes").unwrap(),
        SessionConsensusConfigurationId::from_bytes([0xAC; 32]),
        SessionConsensusConfigurationEpoch::new(1).unwrap(),
    )
}
fn members() -> BTreeSet<SessionConsensusNodeId> {
    [7, 8, 9]
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .into()
}
fn log_id(index: u64) -> LogId<SessionConsensusNodeId> {
    LogId::new(
        CommittedLeaderId::new(1, SessionConsensusNodeId::new(7).unwrap()),
        index,
    )
}
pub(in crate::consensus::native) fn time(second: u8) -> Timestamp {
    Timestamp::from_str(&format!("2026-07-12T00:00:{second:02}Z")).unwrap()
}
fn formation() -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: log_id(0),
        payload: EntryPayload::Membership(Membership::new(vec![members()], members())),
    }
}

pub(in crate::consensus::native) fn request(
    nonce: u64,
    previous: Option<&FencedTransitionOutcome>,
) -> FencedTransitionV2Request {
    let key = SessionKey {
        tenant: TenantId::from_static("native-change-tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"native-change-key").try_into().unwrap(),
    };
    let owner = OwnerId::new("native-change-owner").unwrap();
    let lease = if let Some(previous) = previous {
        FencedTransitionLease::renew(previous.lease().clone(), Duration::from_secs(60)).unwrap()
    } else {
        FencedTransitionLease::acquire(
            key.clone(),
            owner.clone(),
            FenceToken::new(0),
            Duration::from_secs(60),
        )
        .unwrap()
    };
    let mut record = StoredSessionRecord {
        key,
        generation: previous.map_or(Generation::new(1), |previous| {
            previous.committed_generation().next().unwrap()
        }),
        owner,
        fence: FenceToken::new(1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("native-change-test"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("native-change-vector").unwrap(),
        opc_key::KeyPurpose::Session,
        record.key.tenant.clone(),
        opc_key::Zeroizing::new([0xAC; opc_key::AES_256_GCM_SIV_KEY_LEN]),
    );
    let aad =
        crate::record::build_session_envelope_aad(&record, "native-change-test", &handle).unwrap();
    let mut iv = [0; opc_key::AES_256_GCM_SIV_NONCE_LEN];
    iv[4..].copy_from_slice(&nonce.to_be_bytes());
    let encoded = opc_crypto::encrypt_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        b"native change vector",
        iv,
    )
    .unwrap();
    assert_eq!(
        opc_crypto::decrypt_envelope_with_handle(&handle, &aad, &encoded)
            .unwrap()
            .as_slice(),
        b"native change vector"
    );
    record.payload = EncryptedSessionPayload::try_envelope(encoded).unwrap();
    let mutation = if let Some(previous) = previous {
        FencedTransitionMutation::update(previous.committed_generation(), record)
    } else {
        FencedTransitionMutation::create(record)
    };
    FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
        FencedTransitionV2CallerNonce::from_bytes(u128::from(nonce).to_be_bytes()),
        lease,
        mutation,
    )
    .unwrap()
}

pub(in crate::consensus::native) fn command(
    index: u64,
    request: &FencedTransitionV2Request,
    now: Timestamp,
    activate: bool,
) -> Entry<SessionRaftTypeConfig> {
    let intent = if activate {
        SessionMutationIntent::ActivateFencedTransitionV2 {
            request: Box::new(request.clone()),
            scope_identity: identity(),
            voter_set_digest: fenced_transition_voter_set_digest(identity(), &members()),
            profile_digest: fenced_transition_v2_profile_digest(),
        }
    } else {
        SessionMutationIntent::FencedTransitionV2(Box::new(request.clone()))
    };
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes(
                fenced_transition_v2_outer_request_id(request.request_id()),
            ),
            logical_time: now,
            intent,
        }),
    }
}

pub(in crate::consensus::native) fn clock(
    index: u64,
    now: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes(
                u128::from(index + 100).to_be_bytes(),
            ),
            logical_time: now,
            intent: SessionMutationIntent::AdvanceLogicalTime,
        }),
    }
}

pub(in crate::consensus::native) fn apply(
    storage: &mut NativeStorage,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> NativeApplied {
    let encoded = entries
        .iter()
        .map(|entry| serde_json::to_vec(entry).unwrap().into())
        .collect();
    storage
        .log
        .project(&Operation::Append(encoded), &storage.business, None)
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(entries.last().map(|entry| entry.log_id)),
            &storage.business,
            None,
        )
        .unwrap();
    let result = storage.business.apply(entries).unwrap();
    storage.validate_image().unwrap();
    result
}

pub(in crate::consensus::native) fn fixture() -> (
    NativeStorage,
    FencedTransitionV2Request,
    FencedTransitionOutcome,
) {
    let mut storage = NativeStorage::empty(identity(), members()).unwrap();
    let first = request(1, None);
    let result = apply(
        &mut storage,
        &[formation(), command(1, &first, time(1), true)],
    );
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &result.responses[1].result else {
        panic!("successful activation")
    };
    let outcome = outcome.clone();
    (storage, first, outcome)
}

#[test]
fn native_scratch_worker_accepts_exact_original_log_limit_with_large_conflict_body() {
    let _large_row = scratch::LARGE_ROW_TEST.lock().unwrap();
    let (mut storage, original, _) = fixture();
    #[derive(Serialize)]
    struct Wire<'a> {
        request_id: FencedTransitionV2RequestId,
        lease: &'a FencedTransitionLease,
        mutation: FencedTransitionMutation,
    }
    let changed = |ciphertext_bytes: usize, extra_digit: bool| {
        let mut record = original.mutation().record().unwrap().clone();
        let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(record.payload.as_bytes()).unwrap();
        // Opaque envelope shape remains valid. Its substituted request body
        // must remain representable and classify as RequestConflict before
        // the record-payload size check; no successful mutation is requested.
        envelope.ciphertext_and_tag = vec![0; ciphertext_bytes];
        if extra_digit {
            *envelope.ciphertext_and_tag.last_mut().unwrap() = 10;
        }
        record.payload = EncryptedSessionPayload::try_envelope(envelope.encode().unwrap()).unwrap();
        let wire = Wire {
            request_id: original.request_id(),
            lease: original.lease(),
            mutation: FencedTransitionMutation::create(record),
        };
        let bytes = postcard::to_allocvec(&wire).unwrap();
        postcard::from_bytes::<FencedTransitionV2Request>(&bytes).unwrap()
    };
    let small = changed(16, false);
    let base = serde_json::to_vec(&command(2, &small, time(2), false))
        .unwrap()
        .len();
    let limit = crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES;
    let extra = limit - base;
    let large = changed(16 + extra / 2, extra % 2 != 0);
    assert!(
        large.mutation().record().unwrap().payload.len()
            > crate::fenced_transition::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES
    );
    assert!(matches!(
        large.validate(),
        Err(StoreError::FencedTransitionRequestConflict)
    ));
    let entry = command(2, &large, time(2), false);
    let encoded = serde_json::to_vec(&entry).unwrap();
    assert_eq!(
        encoded.len(),
        limit,
        "exercise the exact original 16MiB row boundary"
    );
    crate::sqlite::consensus::validate_command_for_log(
        match &entry.payload {
            EntryPayload::Normal(command) => command,
            _ => unreachable!(),
        },
        identity(),
    )
    .unwrap();
    storage.begin_changes().unwrap();
    storage
        .log
        .project(
            &Operation::Append(vec![encoded.into()]),
            &storage.business,
            None,
        )
        .unwrap();
    let capture = storage.take_changes().unwrap();
    drop(entry);
    drop(large);
    capture.validate(&|| Ok(())).unwrap();
    storage.validate_image().unwrap();
}

#[test]
fn native_scratch_worker_accepts_full_public_256_request_batch_profile() {
    let (mut storage, _, _) = fixture();
    let count = crate::consensus::types::MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS;
    assert_eq!(count, 256);
    let requests = (0..count)
        .map(|nonce| request(nonce as u64 + 100, None))
        .collect::<Vec<_>>();
    let outer =
        crate::consensus::types::fenced_transition_v2_batch_outer_request_id(&requests).unwrap();
    let entry: Entry<SessionRaftTypeConfig> = Entry {
        log_id: log_id(2),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes(outer),
            logical_time: time(2),
            intent: SessionMutationIntent::FencedTransitionV2Batch(requests),
        }),
    };
    storage.begin_changes().unwrap();
    storage
        .log
        .project(
            &Operation::Append(vec![serde_json::to_vec(&entry).unwrap().into()]),
            &storage.business,
            None,
        )
        .unwrap();
    storage
        .take_changes()
        .unwrap()
        .validate(&|| Ok(()))
        .unwrap();
    storage.validate_image().unwrap();
}

fn ordered_rows<K: Serialize, T: Serialize>(
    rows: impl IntoIterator<Item = (K, T)>,
) -> Vec<Vec<u8>> {
    let mut bytes = rows
        .into_iter()
        .map(|row| serde_json::to_vec(&row).unwrap())
        .collect::<Vec<_>>();
    bytes.sort();
    bytes
}

fn exact_state(state: &NativeState) -> Vec<u8> {
    serde_json::to_vec(&(
        state.identity,
        &state.members,
        &state.frontiers,
        ordered_rows(state.keys.iter()),
        ordered_rows(state.receipts.iter()),
        ordered_rows(state.generic_receipts.iter()),
        &state.notifications,
    ))
    .unwrap()
}

fn exact_storage(storage: &NativeStorage) -> Vec<u8> {
    let rows = storage
        .log
        .entries
        .iter()
        .map(|(index, row)| (*index, row.resident().unwrap().encoded.as_ref()))
        .collect::<Vec<_>>();
    serde_json::to_vec(&(
        exact_state(&storage.business),
        storage.log.vote,
        storage.log.committed,
        storage.log.purged,
        rows,
    ))
    .unwrap()
}

fn reconstruct_rows<K: Clone + Eq + Hash, T: serde::de::DeserializeOwned + Serialize>(
    target: &mut ResidentMap<K, SharedRow<T>>,
    changed: &HashMap<K, RowChange<T>>,
) {
    for (key, change) in changed {
        if let Some(row) = &change.after {
            // Force newly decoded allocations, so full validation cannot rely
            // on pointer identity or the live transition's certificate.
            let decoded = postcard::from_bytes(&postcard::to_allocvec(row).unwrap()).unwrap();
            target.insert(key.clone(), decoded);
        } else {
            target.remove(key);
        }
    }
}

fn reconstruct(base: &NativeState, changed: &BusinessChanges) -> NativeState {
    let mut state = base.clone();
    state.proof = None;
    reconstruct_rows(&mut state.keys, &changed.keys);
    reconstruct_rows(&mut state.receipts, &changed.receipts);
    reconstruct_rows(&mut state.generic_receipts, &changed.generic);
    for row in &changed.notifications {
        state
            .notifications
            .push_back(postcard::from_bytes(&postcard::to_allocvec(row).unwrap()).unwrap());
    }
    state.frontiers = changed.target.frontiers.clone();
    state.validate_full_business().unwrap();
    state.admit_business().unwrap();
    state
}

#[test]
fn native_changes_coalesce_replacements_and_expiry_with_complete_cold_value_parity() {
    let (mut storage, first, first_outcome) = fixture();
    let baseline = storage.business.clone();
    storage.business.begin_changes().unwrap();
    let second = request(2, Some(&first_outcome));
    let applied = apply(&mut storage, &[command(2, &second, time(2), false)]);
    let Ok(SessionMutationOutcome::FencedTransition(second_outcome)) = &applied.responses[0].result
    else {
        panic!("second update")
    };
    let third = request(3, Some(second_outcome));
    apply(&mut storage, &[command(3, &third, time(3), false)]);
    let expiry = retention_deadline(time(1)).unwrap();
    apply(
        &mut storage,
        &[command(4, &first, expiry, false), clock(5, expiry)],
    );
    assert_eq!(
        storage.business.status(&first).unwrap(),
        FencedTransitionV2Status::Expired
    );
    let changed = storage.business.capture_changes().unwrap();
    assert_eq!(
        (
            changed.keys.len(),
            changed.receipts.len(),
            changed.generic.len(),
            changed.notifications.len()
        ),
        (1, 3, 1, 2)
    );
    let key = first.lease().key();
    assert!(changed.keys[key]
        .before
        .as_ref()
        .unwrap()
        .ptr_eq(&baseline.keys[key]));
    assert!(changed.keys[key]
        .after
        .as_ref()
        .unwrap()
        .ptr_eq(&storage.business.keys[key]));
    assert!(changed.receipts[&first.request_id()]
        .before
        .as_ref()
        .unwrap()
        .response
        .is_some());
    assert!(changed.receipts[&first.request_id()]
        .after
        .as_ref()
        .unwrap()
        .response
        .is_none());
    let reconstructed = reconstruct(&baseline, &changed);
    assert_eq!(exact_state(&reconstructed), exact_state(&storage.business));
    assert!(
        reconstructed
            .require_business_proof()
            .unwrap()
            .tables
            .map(|table| (table.count, table.checksum))
            == changed
                .target
                .tables
                .map(|table| (table.count, table.checksum))
    );
    let empty = storage.business.capture_changes().unwrap();
    assert!(
        empty.keys.is_empty()
            && empty.receipts.is_empty()
            && empty.generic.is_empty()
            && empty.notifications.is_empty()
    );
    assert!(Arc::ptr_eq(&empty.base, &changed.target));
}

#[test]
fn native_changes_missing_or_stale_dirty_rows_reject_even_when_live_counts_match() {
    for kind in 0..5 {
        let (mut storage, first, outcome) = fixture();
        let old = storage.business.keys[first.lease().key()].clone();
        storage.business.begin_changes().unwrap();
        let second = request(2, Some(&outcome));
        apply(&mut storage, &[command(2, &second, time(2), false)]);
        let exact = exact_state(&storage.business);
        let dirty = storage.business.changes.as_mut().unwrap();
        match kind {
            0 => {
                dirty.keys.clear();
            }
            1 => {
                dirty.receipts.clear();
            }
            2 => {
                dirty.notifications.clear();
            }
            3 => {
                dirty.keys.get_mut(first.lease().key()).unwrap().after = Some(old);
            }
            _ => {
                dirty
                    .keys
                    .get_mut(first.lease().key())
                    .unwrap()
                    .before_hash
                    .as_mut()
                    .unwrap()
                    .content = [0; 32];
            }
        }
        assert!(
            storage.business.capture_changes().is_err(),
            "omission/stale case {kind}"
        );
        assert_eq!(
            exact_state(&storage.business),
            exact,
            "failed capture cannot mutate live values"
        );
        storage.validate_image().unwrap();
    }
}

#[test]
fn native_changes_complete_changed_row_predicates_run_before_any_publication() {
    for kind in 0..8 {
        let (mut storage, _, outcome) = fixture();
        storage.business.begin_changes().unwrap();
        let second = request(2, Some(&outcome));
        let entries = [command(2, &second, time(2), false), clock(3, time(3))];
        let before = exact_state(&storage.business);
        let proof = Arc::clone(storage.business.require_business_proof().unwrap());
        let mut delta = storage.business.prepare(&entries).unwrap();
        match kind {
            0 => {
                delta.keys.values_mut().next().unwrap().fence = COUNTER_MAX;
            }
            1 => {
                delta.keys.values_mut().next().unwrap().reserved = true;
            }
            2 => {
                delta.receipts.values_mut().next().unwrap().payload_digest[0] ^= 1;
            }
            3 => {
                delta.receipts.values_mut().next().unwrap().ordinal = 1;
            }
            4 => {
                delta
                    .receipts
                    .values_mut()
                    .next()
                    .unwrap()
                    .response
                    .as_mut()
                    .unwrap()
                    .raft_log_index = 99;
            }
            5 => {
                delta.receipts.values_mut().next().unwrap().retained_until = time(1);
            }
            6 => {
                let NativeGenericReceipt::Ordinary(row) =
                    delta.generic_receipts.values_mut().next().unwrap()
                else {
                    panic!("ordinary fixture");
                };
                row.response.sequence = 0;
            }
            _ => {
                delta.notifications[0].sequence += 1;
            }
        }
        assert!(
            Publication::prepare(delta).is_err(),
            "semantic rejection {kind}"
        );
        assert_eq!(exact_state(&storage.business), before);
        assert!(Arc::ptr_eq(
            &proof,
            storage.business.require_business_proof().unwrap()
        ));
        storage
            .business
            .changes
            .as_ref()
            .unwrap()
            .validate(&storage.business)
            .unwrap();
    }
}

#[test]
fn native_changes_reject_context_regression_that_would_invalidate_untouched_rows() {
    for kind in 0..7 {
        let (mut storage, _, _) = fixture();
        storage.business.begin_changes().unwrap();
        let before = exact_state(&storage.business);
        let mut delta = storage.business.prepare(&[clock(2, time(2))]).unwrap();
        match kind {
            0 => {
                delta.frontiers.next_fence = 1;
            }
            1 => {
                delta.frontiers.next_credential = 1;
            }
            2 => {
                delta.frontiers.logical_time = Some(time(0));
            }
            3 => {
                delta.frontiers.watch_sequence = 0;
            }
            4 => {
                delta.frontiers.history = Some(
                    FencedTransitionV2HistoryState::new(
                        Some(FencedTransitionV2HistoryEpoch::new(2).unwrap()),
                        None,
                        None,
                        0,
                        0,
                        1,
                        0,
                    )
                    .unwrap(),
                );
            }
            5 => {
                delta.frontiers.activation.as_mut().unwrap().profile[0] ^= 1;
            }
            _ => {
                delta.frontiers.membership = StoredMembership::default();
            }
        }
        assert!(
            Publication::prepare(delta).is_err(),
            "untouched context rejection {kind}"
        );
        assert_eq!(exact_state(&storage.business), before);
        storage.business.capture_changes().unwrap();
    }
}

#[test]
fn native_changes_late_apply_failure_keeps_all_values_proof_and_dirty_predecessors() {
    let (mut storage, _, outcome) = fixture();
    storage.business.begin_changes().unwrap();
    let second = request(2, Some(&outcome));
    let before = exact_state(&storage.business);
    let proof = Arc::clone(storage.business.require_business_proof().unwrap());
    assert!(storage
        .business
        .apply(&[
            command(2, &second, time(2), false),
            Entry {
                log_id: log_id(4),
                payload: EntryPayload::Blank
            }
        ])
        .is_err());
    assert_eq!(exact_state(&storage.business), before);
    assert!(Arc::ptr_eq(
        &proof,
        storage.business.require_business_proof().unwrap()
    ));
    let changed = storage.business.capture_changes().unwrap();
    assert!(
        changed.keys.is_empty() && changed.receipts.is_empty() && changed.notifications.is_empty()
    );
    assert!(Arc::ptr_eq(&changed.base, &changed.target));
}

#[test]
fn native_changes_snapshot_metadata_at_same_sequence_has_distinct_exact_revision() {
    let (mut storage, _, _) = fixture();
    storage.business.begin_changes().unwrap();
    let first = storage.business.capture_changes().unwrap();
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: storage.business.applied(),
        last_membership: storage.business.membership(),
        snapshot_id: format!("{}change-test", snapshot_prefix([0xAD; 32])),
    };
    let snapshot = (
        meta,
        format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
        [0xAD; 32],
        100,
    );
    storage.validate_snapshot(&snapshot).unwrap();
    storage.business.set_current_snapshot(snapshot).unwrap();
    let next = storage.business.capture_changes().unwrap();
    assert_eq!(
        first.target.frontiers.sequence,
        next.target.frontiers.sequence
    );
    assert_eq!(
        first.target.frontiers.applied,
        next.target.frontiers.applied
    );
    assert!(Arc::ptr_eq(&first.target, &next.base));
    assert!(!Arc::ptr_eq(&first.target, &next.target));
    assert_eq!(next.target.revision, first.target.revision + 1);
    assert!(next.keys.is_empty() && next.receipts.is_empty() && next.notifications.is_empty());
    let before = exact_state(&storage.business);
    let mut invalid = storage.business.current_snapshot().unwrap();
    invalid.3 = 0;
    assert!(storage.business.set_current_snapshot(invalid).is_err());
    assert_eq!(exact_state(&storage.business), before);
    storage.business.capture_changes().unwrap();
}

#[test]
fn native_changes_deserialization_cannot_supply_a_process_certificate() {
    let (storage, _, _) = fixture();
    let bytes = postcard::to_allocvec(&storage.business).unwrap();
    let mut decoded: NativeState = postcard::from_bytes(&bytes).unwrap();
    assert!(decoded.proof.is_none() && decoded.changes.is_none());
    assert!(decoded.apply(&[]).is_err());
    assert!(decoded.begin_changes().is_err());
    decoded.admit_business().unwrap();
    assert_eq!(exact_state(&decoded), exact_state(&storage.business));
    assert!(!Arc::ptr_eq(
        decoded.require_business_proof().unwrap(),
        storage.business.require_business_proof().unwrap()
    ));
    let mut invalid: NativeState = postcard::from_bytes(&bytes).unwrap();
    let key = invalid.keys.keys().next().unwrap().clone();
    let mut value = (*invalid.keys[&key]).clone();
    value.fence = COUNTER_MAX;
    invalid.keys.insert(key, SharedRow::new(value));
    assert!(invalid.admit_business().is_err());
    assert!(invalid.proof.is_none());
}

#[test]
fn native_changes_staged_publication_rejects_a_later_exact_owner_revision() {
    let (mut storage, _, outcome) = fixture();
    storage.business.begin_changes().unwrap();
    let second = request(2, Some(&outcome));
    let publication = Publication::prepare(
        storage
            .business
            .prepare(&[command(2, &second, time(2), false)])
            .unwrap(),
    )
    .unwrap();
    apply(&mut storage, &[clock(2, time(2))]);
    let before = exact_state(&storage.business);
    assert!(publication.publish(&mut storage.business).is_err());
    assert_eq!(exact_state(&storage.business), before);
    storage.business.capture_changes().unwrap();
}

#[test]
fn native_changes_bind_then_expire_in_one_atomic_delivery_retains_the_binding() {
    let mut storage = NativeStorage::empty(identity(), members()).unwrap();
    apply(&mut storage, &[formation()]);
    storage.business.begin_changes().unwrap();
    let baseline = storage.business.clone();
    let first = request(1, None);
    apply(
        &mut storage,
        &[
            command(1, &first, time(1), true),
            command(2, &first, retention_deadline(time(1)).unwrap(), false),
        ],
    );
    assert_eq!(
        storage.business.status(&first).unwrap(),
        FencedTransitionV2Status::Expired
    );
    let changed = storage.business.capture_changes().unwrap();
    let receipt = &changed.receipts[&first.request_id()];
    assert!(receipt.before.is_none() && receipt.after.as_ref().unwrap().response.is_none());
    assert_eq!(receipt.after.as_ref().unwrap().ordinal, 1);
    assert_eq!(
        exact_state(&reconstruct(&baseline, &changed)),
        exact_state(&storage.business)
    );
}

#[test]
fn native_changes_coalescing_keeps_remove_reinsert_and_equal_value_revisions() {
    let original = SharedRow::new(NativeKeyState {
        fence: 7,
        ..NativeKeyState::default()
    });
    let first_hash = stamp(0, &1u64, &original).unwrap();
    let mut current = ResidentMap::new();
    current.insert(1u64, original.clone());
    let mut dirty = HashMap::new();
    let removal = StagedRow {
        key: 1,
        journal_key: Some(1),
        change: RowChange {
            before: Some(original.clone()),
            after: None,
            before_hash: Some(first_hash),
            after_hash: None,
        },
    };
    validate_staged(std::slice::from_ref(&removal), &current, Some(&dirty)).unwrap();
    publish_rows(vec![removal], &mut current, Some(&mut dirty));
    let replacement = SharedRow::new((*original).clone());
    let reinsert = StagedRow {
        key: 1,
        journal_key: Some(1),
        change: RowChange {
            before: None,
            after: Some(replacement.clone()),
            before_hash: None,
            after_hash: Some(stamp(0, &1u64, &replacement).unwrap()),
        },
    };
    validate_staged(std::slice::from_ref(&reinsert), &current, Some(&dirty)).unwrap();
    publish_rows(vec![reinsert], &mut current, Some(&mut dirty));
    assert_eq!(dirty.len(), 1);
    assert!(dirty[&1].before.as_ref().unwrap().ptr_eq(&original));
    assert!(dirty[&1].after.as_ref().unwrap().ptr_eq(&replacement));
    assert!(!dirty[&1]
        .before
        .as_ref()
        .unwrap()
        .ptr_eq(dirty[&1].after.as_ref().unwrap()));
    assert_eq!(
        dirty[&1].before_hash.unwrap().content,
        dirty[&1].after_hash.unwrap().content,
        "equal bytes do not erase a revision change"
    );
    assert_ne!(
        dirty[&1].before_hash.unwrap().revision,
        dirty[&1].after_hash.unwrap().revision
    );
}

#[test]
fn native_changes_omitted_equal_value_replacement_still_fails_the_revision_equation() {
    let (mut storage, first, _) = fixture();
    let expiry = retention_deadline(time(1)).unwrap();
    apply(&mut storage, &[command(2, &first, expiry, false)]);
    storage.business.begin_changes().unwrap();
    let baseline = storage.business.clone();
    let before = storage.business.require_business_proof().unwrap().tables[1];
    apply(&mut storage, &[command(3, &first, expiry, false)]);
    let after = storage.business.require_business_proof().unwrap().tables[1];
    assert_eq!(
        (before.count, before.checksum),
        (after.count, after.checksum)
    );
    assert_ne!(before.revisions, after.revisions);
    let changed = storage.business.changes.as_ref().unwrap();
    changed.validate(&storage.business).unwrap();
    assert_eq!(
        exact_state(&reconstruct(&baseline, changed)),
        exact_state(&storage.business)
    );
    storage.business.changes.as_mut().unwrap().receipts.clear();
    assert!(
        storage.business.capture_changes().is_err(),
        "an equal-valued tombstone replacement cannot disappear"
    );
    storage.validate_image().unwrap();
}

#[test]
fn native_capture_moves_both_journals_and_worker_validates_after_live_expiry_and_drop() {
    let (mut storage, first, outcome) = fixture();
    let baseline = storage.clone();
    storage.begin_changes().unwrap();
    let second = request(2, Some(&outcome));
    apply(&mut storage, &[command(2, &second, time(2), false)]);
    let expected = exact_state(&storage.business);
    let expected_storage = exact_storage(&storage);
    let captured = storage.take_changes().unwrap();
    let (release, ready) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        ready.recv().unwrap();
        captured.validate(&|| Ok(())).unwrap();
        captured
    });
    let expiry = retention_deadline(time(1)).unwrap();
    apply(
        &mut storage,
        &[command(3, &first, expiry, false), clock(4, expiry)],
    );
    assert_eq!(
        storage.business.status(&first).unwrap(),
        FencedTransitionV2Status::Expired
    );
    let suffix = storage.take_changes().unwrap();
    let expected_suffix = exact_state(&storage.business);
    let expected_suffix_storage = exact_storage(&storage);
    drop(storage);
    release.send(()).unwrap();
    let captured = worker.join().unwrap();
    assert!(Arc::ptr_eq(
        &captured.business.target,
        &suffix.business.base
    ));
    let business = reconstruct(&baseline.business, &captured.business);
    assert_eq!(exact_state(&business), expected);
    let log = captured.log.reconstruct_for_test(&baseline.log);
    let mut reconstructed = NativeStorage { business, log };
    reconstructed.log.admit(&reconstructed.business).unwrap();
    reconstructed.validate_image().unwrap();
    assert_eq!(exact_storage(&reconstructed), expected_storage);
    let mut image = Vec::new();
    reconstructed
        .write_image(&mut image, [0xCE; 32], 17)
        .unwrap();
    let cold =
        NativeStorage::read_image(&mut image.as_slice(), [0xCE; 32], 17, identity()).unwrap();
    assert_eq!(exact_state(&cold.business), expected);
    assert_eq!(exact_storage(&cold), expected_storage);
    assert_eq!(
        cold.business.status(&first).unwrap(),
        baseline.business.status(&first).unwrap()
    );
    suffix.validate(&|| Ok(())).unwrap();
    let business = reconstruct(&cold.business, &suffix.business);
    let log = suffix.log.reconstruct_for_test(&cold.log);
    let mut latest = NativeStorage { business, log };
    latest.log.admit(&latest.business).unwrap();
    latest.validate_image().unwrap();
    assert_eq!(exact_storage(&latest), expected_suffix_storage);
    assert_eq!(exact_state(&latest.business), expected_suffix);
    assert_eq!(
        latest.business.status(&first).unwrap(),
        FencedTransitionV2Status::Expired
    );
}

#[test]
fn native_capture_preflight_failure_cannot_partially_start_or_move_journals() {
    let (mut storage, _, _) = fixture();
    storage.log.begin_changes(&storage.business).unwrap();
    assert!(storage.begin_changes().is_err());
    assert!(storage.business.changes.is_none());

    let (mut storage, _, _) = fixture();
    storage.business.begin_changes().unwrap();
    assert!(storage.begin_changes().is_err());
    storage.log.begin_changes(&storage.business).unwrap();
    storage
        .take_changes()
        .unwrap()
        .validate(&|| Ok(()))
        .unwrap();

    for corrupt_log in [false, true] {
        let (mut storage, _, _) = fixture();
        storage.begin_changes().unwrap();
        let baseline = storage.clone();
        apply(&mut storage, &[clock(2, time(2))]);
        let expected = exact_state(&storage.business);
        let expected_storage = exact_storage(&storage);
        let proof = Arc::clone(storage.business.require_business_proof().unwrap());
        let committed = storage.log.committed;
        if corrupt_log {
            storage.log.committed = Some(log_id(99));
        } else {
            let dirty = storage.business.changes.as_mut().unwrap();
            dirty.target = Arc::clone(&dirty.base);
        }
        assert!(storage.take_changes().is_err());
        assert_eq!(exact_state(&storage.business), expected);
        storage.log.committed = committed;
        storage.business.changes.as_mut().unwrap().target = proof;
        let captured = storage.take_changes().unwrap();
        assert_eq!(captured.business.generic.len(), 1);
        captured.validate(&|| Ok(())).unwrap();
        let business = reconstruct(&baseline.business, &captured.business);
        let log = captured.log.reconstruct_for_test(&baseline.log);
        let mut restored = NativeStorage { business, log };
        restored.log.admit(&restored.business).unwrap();
        restored.validate_image().unwrap();
        assert_eq!(
            exact_storage(&restored),
            expected_storage,
            "both original journals must survive failed preflight"
        );
        storage
            .take_changes()
            .unwrap()
            .validate(&|| Ok(()))
            .unwrap();
    }
}

#[test]
fn native_capture_omitted_stale_or_modified_business_rows_fail_in_worker() {
    for kind in 0..7 {
        let (mut storage, first, outcome) = fixture();
        let old = storage.business.keys[first.lease().key()].clone();
        storage.begin_changes().unwrap();
        let second = request(2, Some(&outcome));
        apply(
            &mut storage,
            &[command(2, &second, time(2), false), clock(3, time(3))],
        );
        let expected = exact_state(&storage.business);
        let dirty = storage.business.changes.as_mut().unwrap();
        match kind {
            0 => dirty.keys.clear(),
            1 => dirty.receipts.clear(),
            2 => dirty.generic.clear(),
            3 => dirty.notifications.clear(),
            4 => {
                dirty.keys.get_mut(first.lease().key()).unwrap().after = Some(old);
            }
            5 => {
                dirty
                    .keys
                    .get_mut(first.lease().key())
                    .unwrap()
                    .before_hash
                    .as_mut()
                    .unwrap()
                    .content[0] ^= 1;
            }
            _ => {
                let receipt = dirty.receipts.values_mut().next().unwrap();
                let mut changed = (**receipt.after.as_ref().unwrap()).clone();
                changed.retained_until = time(0);
                receipt.after = Some(SharedRow::new(changed));
            }
        }
        // Transfer deliberately does no serialization or per-row validation.
        // The worker must reject before any persistence path selects this cut.
        let captured = storage.take_changes().unwrap();
        assert!(
            captured.validate(&|| Ok(())).is_err(),
            "detached business corruption {kind}"
        );
        assert_eq!(exact_state(&storage.business), expected);
        storage.validate_image().unwrap();
    }
}

#[test]
fn native_capture_equal_expired_receipt_replacement_cannot_disappear_in_worker() {
    let (mut storage, first, _) = fixture();
    let expiry = retention_deadline(time(1)).unwrap();
    apply(&mut storage, &[command(2, &first, expiry, false)]);
    storage.begin_changes().unwrap();
    let baseline = storage.clone();
    apply(&mut storage, &[command(3, &first, expiry, false)]);
    let mut captured = storage.take_changes().unwrap();
    captured.validate(&|| Ok(())).unwrap();
    assert_eq!(
        exact_state(&reconstruct(&baseline.business, &captured.business)),
        exact_state(&storage.business)
    );
    let before = captured.business.base.tables[1];
    let after = captured.business.target.tables[1];
    assert_eq!(
        (before.count, before.checksum),
        (after.count, after.checksum)
    );
    assert_ne!(before.revisions, after.revisions);
    captured.business.receipts.clear();
    assert!(captured.validate(&|| Ok(())).is_err());
}

#[test]
fn native_capture_cancellation_preserves_exact_capture_and_concurrent_suffix() {
    use std::cell::Cell;
    let (mut storage, _, outcome) = fixture();
    storage.begin_changes().unwrap();
    let second = request(2, Some(&outcome));
    apply(
        &mut storage,
        &[command(2, &second, time(2), false), clock(3, time(3))],
    );
    let captured = storage.take_changes().unwrap();
    let calls = Cell::new(0);
    captured
        .validate(&|| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
    let total = calls.get();
    assert!(total > 10);
    apply(&mut storage, &[clock(4, time(4))]);
    let expected = exact_state(&storage.business);
    for cancel_at in [0, 1, 5, total - 2, total - 1] {
        let calls = Cell::new(0);
        let error = captured
            .validate(&|| {
                let index = calls.get();
                calls.set(index + 1);
                if index == cancel_at {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "capture verification cancelled",
                    ))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        captured.validate(&|| Ok(())).unwrap();
        assert_eq!(exact_state(&storage.business), expected);
    }
    let suffix = storage.take_changes().unwrap();
    assert!(Arc::ptr_eq(
        &suffix.business.base,
        &captured.business.target
    ));
    suffix.validate(&|| Ok(())).unwrap();
}

#[test]
fn native_capture_same_sequence_snapshot_requires_exact_business_log_pair() {
    let (mut storage, _, _) = fixture();
    storage.begin_changes().unwrap();
    let mut first = storage.take_changes().unwrap();
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id: storage.business.applied(),
        last_membership: storage.business.membership(),
        snapshot_id: format!("{}captured", snapshot_prefix([0xCF; 32])),
    };
    storage
        .business
        .set_current_snapshot((
            meta,
            format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
            [0xCF; 32],
            100,
        ))
        .unwrap();
    let mut second = storage.take_changes().unwrap();
    assert_eq!(
        first.business.target.frontiers.sequence,
        second.business.target.frontiers.sequence
    );
    assert_eq!(
        first.business.target.frontiers.applied,
        second.business.target.frontiers.applied
    );
    assert!(Arc::ptr_eq(&first.business.target, &second.business.base));
    first.validate(&|| Ok(())).unwrap();
    second.validate(&|| Ok(())).unwrap();
    std::mem::swap(&mut first.log, &mut second.log);
    assert!(first.validate(&|| Ok(())).is_err());
    assert!(second.validate(&|| Ok(())).is_err());
    std::mem::swap(&mut first.log, &mut second.log);
    drop(storage);
    first.validate(&|| Ok(())).unwrap();
    second.validate(&|| Ok(())).unwrap();
}

// Isolate a complete coalesced epoch without replaying a million application
// commands. Both endpoint images are fully validated, all original 131072
// IDs are represented, and the real journal owns its container reservation.
// This is a capture-contract fixture, not an end-to-end maintenance trace.
pub(in crate::consensus::native) fn transient_history_capture(
    storage: &mut NativeStorage,
) -> NativeChanges {
    let count = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES;
    assert_eq!(count, 131_072);
    let before = Arc::clone(storage.business.require_business_proof().unwrap());
    assert_eq!(before.frontiers.history.unwrap().bound_entries(), 0);
    assert!(storage.business.receipts.is_empty());
    let mut frontiers = before.frontiers.clone();
    frontiers.history = Some(
        FencedTransitionV2HistoryState::new(
            Some(FencedTransitionV2HistoryEpoch::new(2).unwrap()),
            Some(FencedTransitionV2HistoryEpoch::new(1).unwrap()),
            None,
            0,
            1 + (count as u64)
                .div_ceil(crate::fenced_transition::FENCED_TRANSITION_V2_RECLAIM_BATCH as u64),
            0,
            count as u64,
        )
        .unwrap(),
    );
    validate_frontier_transition(&before.frontiers, &frontiers, true).unwrap();
    let mut endpoint = storage.business.clone();
    endpoint.frontiers = frontiers.clone();
    endpoint.admit_business().unwrap();
    let order = endpoint
        .require_business_proof()
        .unwrap()
        .receipt_order
        .clone();
    let target = BusinessProof::new(
        &storage.business,
        &frontiers,
        before.tables,
        before.revision + 1,
        before.expiry.clone(),
        order,
        &storage.business.roster,
    )
    .unwrap();
    let memory = Arc::new(
        VerificationMemory::reserve(
            count * 4 * (size_of::<(FencedTransitionV2RequestId, RowChange<NativeReceipt>)>() + 1),
        )
        .unwrap(),
    );
    let dirty = storage.business.changes.as_mut().unwrap();
    assert!(Arc::ptr_eq(&dirty.base, &before) && Arc::ptr_eq(&dirty.target, &before));
    dirty.receipts.try_reserve(count).unwrap();
    for ordinal in 1..=count as u64 {
        let id = lifecycle_tests::synthetic_id(1, ordinal);
        dirty.receipts.insert(
            id,
            RowChange {
                before: None,
                after: None,
                before_hash: None,
                after_hash: None,
            },
        );
    }
    dirty.memory.push(memory);
    dirty.target = Arc::clone(&target);
    storage.business.frontiers = frontiers;
    storage.business.proof = Some(target);
    storage.validate_image().unwrap();
    let mut captured = storage.take_changes().unwrap();
    captured.validate(&|| Ok(())).unwrap();
    let original_base = Arc::clone(&captured.business.base);
    let original_target = Arc::clone(&captured.business.target);
    let id = lifecycle_tests::synthetic_id(1, count as u64);
    let omitted = captured.business.receipts.remove(&id).unwrap();
    // Every prior row-summary check still passes: this is the concrete R90
    // omission, with the admitted proofs and log/business pairing unchanged.
    let mut summary = captured.business.base.tables[1];
    BusinessChanges::check_rows(1, &captured.business.receipts, &mut summary, &|| Ok(())).unwrap();
    assert!(summary == captured.business.target.tables[1]);
    assert_eq!(
        captured.validate(&|| Ok(())).unwrap_err().to_string(),
        "native history binding and reclamation conservation differs"
    );
    assert!(Arc::ptr_eq(&original_base, &captured.business.base));
    assert!(Arc::ptr_eq(&original_target, &captured.business.target));
    captured.business.receipts.insert(id, omitted);
    captured.validate(&|| Ok(())).unwrap();
    captured
}

pub(in crate::consensus::native) fn omit_transient_history_receipt(captured: &mut NativeChanges) {
    let id = lifecycle_tests::synthetic_id(1, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64);
    let omitted = captured.business.receipts.remove(&id).unwrap();
    assert!(omitted.before.is_none() && omitted.after.is_none());
}
