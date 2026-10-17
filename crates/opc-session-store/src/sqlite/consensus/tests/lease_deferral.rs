use super::*;
use crate::FencedTransitionV2Profile;

const PROFILE: FencedTransitionV2Profile = FencedTransitionV2Profile::V2WithLeaseDeferral;

#[test]
fn review_cohort_sqlite_resolution_expiry_grouped() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    let (pending, _) = fixture(&backend, &conn);
    let defer = fenced_transition_v2_entry(2, pending.clone(), timestamp(2));
    append_logs_sync(&conn, identity(), std::slice::from_ref(&defer)).unwrap();
    save_committed_sync(&conn, identity(), Some(defer.log_id)).unwrap();
    let deferred = apply_entries_sync(&conn, identity(), &backend.caps, vec![defer]).unwrap();
    assert_eq!(
        deferred.responses[0].result,
        Err(StoreError::FencedTransitionLeaseDeferred)
    );
    let now = Timestamp::from_offset_datetime(
        *timestamp(0).as_offset_datetime() + Duration::from_secs(400),
    );
    let expires =
        crate::ttl::checked_session_deadline(now, FENCED_TRANSITION_OUTCOME_RETENTION).unwrap();
    let entries = vec![
        fenced_transition_v2_entry(3, pending.clone(), now),
        fenced_transition_v2_entry(4, pending.clone(), expires),
    ];
    append_logs_sync(&conn, identity(), &entries).unwrap();
    save_committed_sync(&conn, identity(), entries.last().map(|entry| entry.log_id)).unwrap();
    let applied = apply_entries_sync(&conn, identity(), &backend.caps, entries).unwrap();
    assert!(matches!(
        applied.responses[0].result,
        Ok(SessionMutationOutcome::FencedTransition(_))
    ));
    assert_eq!(
        applied.responses[1].result,
        Err(StoreError::FencedTransitionRequestExpired)
    );
    assert_eq!(
        read_fenced_transition_v2_history_row_in_sync(&conn, identity(), false)
            .unwrap()
            .current_bound_count,
        2
    );
    assert_eq!(
        read_fenced_transition_v2_status_sync(&conn, identity(), identity(), &pending).unwrap(),
        FencedTransitionV2Status::Expired
    );
    validate_fenced_transition_v2_receipts_sync(&conn, identity()).unwrap();
}

fn expected_members() -> BTreeSet<SessionConsensusNodeId> {
    [7, 8, 9]
        .into_iter()
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .collect()
}

fn membership_entry() -> Entry<SessionRaftTypeConfig> {
    let mut entry = super::membership_entry();
    entry.payload = EntryPayload::Membership(opc_consensus::engine::Membership::new(
        vec![expected_members()],
        expected_members(),
    ));
    entry
}

#[test]
fn sqlite_lease_deferral_profile_has_an_independent_fixed_digest() {
    let hex = PROFILE
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        hex,
        "9c417cb163de21b72f8862cc8f998076a02d991699b53a34136eb0b8a0f27906"
    );
}

#[test]
fn sqlite_lease_deferral_reopen_refuses_the_profile_without_deletion_witnesses() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("previous-profile.sqlite");
    let backend =
        SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, PROFILE).unwrap();
    {
        let conn = backend.conn.blocking_lock();
        fixture(&backend, &conn);
        let previous =
            hex::decode("ff9fb5a129821261d9ddd2cd1482aedd4e528642fc3f3474ce8580c86a6c3d4a")
                .unwrap();
        assert_eq!(conn.execute(
            "UPDATE consensus_fenced_transition_profile SET profile_digest=?1 WHERE singleton=1",
            [previous.as_slice()],
        ).unwrap(), 1);
    }
    drop(backend);
    assert!(matches!(
        SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, PROFILE),
        Err(StoreError::BackendUnavailable(reason)) if reason == "fenced_transition_store_profile_mismatch"
    ));
}

fn initialize(conn: &Connection) {
    initialize_profile(conn, PROFILE);
}

fn initialize_profile(conn: &Connection, profile: FencedTransitionV2Profile) {
    initialize_schema_with_storage_anchor_and_pending_and_bindings_and_fenced_profile(
        conn,
        None,
        identity(),
        &expected_members(),
        &test_member_bindings(&expected_members()),
        None,
        ConsensusAuthorityProfile::FixedImmutable,
        Some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
        None,
        profile,
    )
    .unwrap();
}

fn activation(
    index: u64,
    request: FencedTransitionV2Request,
    now: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    let mut entry = activating_fenced_transition_v2_entry(index, request, now);
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    let SessionMutationIntent::ActivateFencedTransitionV2 {
        profile_digest,
        voter_set_digest,
        ..
    } = &mut command.intent
    else {
        unreachable!()
    };
    *profile_digest = PROFILE.digest();
    *voter_set_digest = fenced_transition_voter_set_digest(identity(), &expected_members());
    entry
}

fn pending(prior: &FencedTransitionOutcome) -> FencedTransitionV2Request {
    FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
        crate::FencedTransitionV2CallerNonce::from_bytes([0xD1; 16]),
        FencedTransitionLease::acquire(
            prior.lease().key().clone(),
            OwnerId::new("deferred-synthetic-owner").unwrap(),
            prior.lease().fence(),
            Duration::from_secs(60),
        )
        .unwrap(),
        FencedTransitionMutation::delete(prior.committed_generation()),
    )
    .unwrap()
}

fn fixture(
    backend: &SqliteSessionBackend,
    conn: &Connection,
) -> (FencedTransitionV2Request, FencedTransitionV2Request) {
    initialize(conn);
    let first = fenced_transition_v2_request(0xC1, 1, "synthetic-predecessor");
    let entries = [
        membership_entry(),
        activation(1, first.clone(), timestamp(1)),
    ];
    append_logs_sync(conn, identity(), &entries).unwrap();
    save_committed_sync(conn, identity(), entries.last().map(|entry| entry.log_id)).unwrap();
    let result = apply_entries_sync(conn, identity(), &backend.caps, entries.to_vec()).unwrap();
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &result.responses[1].result else {
        panic!("successful original acquisition")
    };
    (pending(outcome), first)
}

#[test]
fn sqlite_lease_deferral_codec_is_profile_closed_and_requires_the_pending_marker() {
    let response = SessionConsensusResponse {
        result: Err(StoreError::FencedTransitionLeaseDeferred),
        sequence: 1,
        digest: Some(SessionConsensusEntryDigest::GENESIS),
        logical_time: Some(timestamp(2)),
        raft_log_index: 2,
    };
    let bytes = encode_fenced_transition_v2_response_with_profile(&response, PROFILE).unwrap();
    assert_eq!(bytes[9], 27);
    assert_eq!(
        decode_fenced_transition_v2_response_with_profile(&bytes, PROFILE).unwrap(),
        response
    );
    for old in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
    ] {
        assert_ne!(PROFILE.digest(), old.digest());
        assert!(encode_fenced_transition_v2_response_with_profile(&response, old).is_err());
        assert!(decode_fenced_transition_v2_response_with_profile(&bytes, old).is_err());
    }
    let marker = crate::fenced_transition::fenced_transition_v2_deferral_retention().unwrap();
    validate_fenced_transition_v2_receipt_metadata(marker, &response, PROFILE).unwrap();
    assert!(
        validate_fenced_transition_v2_receipt_metadata(timestamp(3), &response, PROFILE).is_err()
    );
    let terminal = SessionConsensusResponse {
        result: Err(StoreError::LeaseHeld),
        ..response
    };
    assert!(validate_fenced_transition_v2_receipt_metadata(marker, &terminal, PROFILE).is_err());
}

#[test]
fn sqlite_lease_deferral_status_boundary_is_profile_specific_before_and_after_activation() {
    let marker = crate::fenced_transition::fenced_transition_v2_deferral_retention().unwrap();
    let boundary = Timestamp::from_offset_datetime(
        *marker.as_offset_datetime() - FENCED_TRANSITION_OUTCOME_RETENTION,
    );
    let before = Timestamp::from_offset_datetime(
        *boundary.as_offset_datetime() - time::Duration::seconds(1),
    );
    for profile in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
        PROFILE,
    ] {
        for active in [false, true] {
            let backend = SqliteSessionBackend::in_memory().unwrap();
            let conn = backend.conn.blocking_lock();
            initialize_profile(&conn, profile);
            let mut entries = vec![membership_entry()];
            if active {
                let original = fenced_transition_v2_request(0xC1, 1, "synthetic-predecessor");
                let mut entry = activation(1, original, timestamp(1));
                let EntryPayload::Normal(command) = &mut entry.payload else {
                    unreachable!()
                };
                let SessionMutationIntent::ActivateFencedTransitionV2 { profile_digest, .. } =
                    &mut command.intent
                else {
                    unreachable!()
                };
                *profile_digest = profile.digest();
                entries.push(entry);
            }
            append_logs_sync(&conn, identity(), &entries).unwrap();
            save_committed_sync(&conn, identity(), entries.last().map(|entry| entry.log_id))
                .unwrap();
            let applied = apply_entries_sync(&conn, identity(), &backend.caps, entries).unwrap();
            assert!(applied
                .responses
                .iter()
                .all(|response| response.result.is_ok()));
            assert_eq!(
                fenced_transition_v2_ledger_layout_sync(&conn).unwrap()
                    == FencedTransitionV2LedgerLayout::Absent,
                !active
            );
            let fresh = fenced_transition_v2_request(0xD8, 1, "synthetic-fresh-owner");
            for now in [before, boundary] {
                conn.execute(
                    "UPDATE consensus_machine SET logical_time=?1 WHERE singleton=1",
                    [ops::format_rfc3339_normalized(now)],
                )
                .unwrap();
                assert_eq!(
                    read_fenced_transition_v2_status_sync(&conn, identity(), identity(), &fresh)
                        .unwrap(),
                    if now == boundary && profile.defers_live_leases() {
                        FencedTransitionV2Status::RetentionExhausted
                    } else {
                        FencedTransitionV2Status::NotFound
                    }
                );
            }
        }
    }
}

#[test]
fn sqlite_lease_deferral_reserved_retention_boundary_preserves_pending_and_reports_exhaustion() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    let (pending, _) = fixture(&backend, &conn);
    let first = apply_entries_sync(
        &conn,
        identity(),
        &backend.caps,
        vec![fenced_transition_v2_entry(2, pending.clone(), timestamp(2))],
    )
    .unwrap();
    assert_eq!(
        first.responses[0].result,
        Err(StoreError::FencedTransitionLeaseDeferred)
    );
    let fresh = FencedTransitionV2Request::new(
        pending.request_id().epoch(),
        crate::FencedTransitionV2CallerNonce::from_bytes([0xD4; 16]),
        pending.lease().clone(),
        pending.mutation().clone(),
    )
    .unwrap();
    let marker = crate::fenced_transition::fenced_transition_v2_deferral_retention().unwrap();
    let now = Timestamp::from_offset_datetime(
        *marker.as_offset_datetime() - FENCED_TRANSITION_OUTCOME_RETENTION,
    );
    assert_eq!(
        crate::ttl::checked_session_deadline(now, FENCED_TRANSITION_OUTCOME_RETENTION).unwrap(),
        marker
    );
    let before = read_machine_sync(&conn, identity()).unwrap();
    let result = apply_entries_sync(
        &conn,
        identity(),
        &backend.caps,
        vec![
            fenced_transition_v2_entry(3, pending.clone(), now),
            fenced_transition_v2_entry(4, fresh.clone(), now),
        ],
    )
    .unwrap();
    assert_eq!(
        result.responses[0].result,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    );
    assert_eq!(
        result.responses[1].result,
        Err(StoreError::FencedTransitionRetentionExhausted)
    );
    let after = read_machine_sync(&conn, identity()).unwrap();
    assert_eq!((before.0, before.1, before.3), (after.0, after.1, after.3));
    assert!(result.notifications.is_empty());
    assert_eq!(
        read_fenced_transition_v2_history_row_in_sync(&conn, identity(), false)
            .unwrap()
            .current_bound_count,
        2
    );
    validate_fenced_transition_v2_receipts_sync(&conn, identity()).unwrap();
    assert_eq!(
        read_fenced_transition_v2_status_sync(&conn, identity(), identity(), &pending).unwrap(),
        FencedTransitionV2Status::LeaseDeferred {
            request_id: pending.request_id()
        }
    );
    assert_eq!(
        read_fenced_transition_v2_status_sync(&conn, identity(), identity(), &fresh).unwrap(),
        FencedTransitionV2Status::RetentionExhausted
    );
}

#[test]
fn sqlite_lease_deferral_sequence_exhaustion_resolves_once_without_a_business_effect() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    let (pending, _) = fixture(&backend, &conn);
    let first = apply_entries_sync(
        &conn,
        identity(),
        &backend.caps,
        vec![fenced_transition_v2_entry(2, pending.clone(), timestamp(2))],
    )
    .unwrap();
    assert_eq!(
        first.responses[0].result,
        Err(StoreError::FencedTransitionLeaseDeferred)
    );
    conn.execute(
        "UPDATE consensus_machine SET application_sequence=?1 WHERE singleton=1",
        [i64::MAX],
    )
    .unwrap();
    let record_before = ops::get_raw_sync(&conn, pending.lease().key()).unwrap();
    assert!(record_before.is_some());
    let before = read_machine_sync(&conn, identity()).unwrap();
    let busy = apply_entries_sync(
        &conn,
        identity(),
        &backend.caps,
        vec![fenced_transition_v2_entry(3, pending.clone(), timestamp(3))],
    )
    .unwrap();
    assert_eq!(
        busy.responses[0].result,
        Err(StoreError::FencedTransitionLeaseDeferred)
    );
    let now = Timestamp::from_offset_datetime(
        *timestamp(0).as_offset_datetime() + time::Duration::seconds(400),
    );
    let terminal = apply_entries_sync(
        &conn,
        identity(),
        &backend.caps,
        vec![fenced_transition_v2_entry(4, pending.clone(), now)],
    )
    .unwrap();
    assert_eq!(
        terminal.responses[0].result,
        Err(StoreError::FencedTransitionStorageExhausted)
    );
    assert!(terminal.notifications.is_empty());
    assert_eq!(
        ops::get_raw_sync(&conn, pending.lease().key()).unwrap(),
        record_before
    );
    let after = read_machine_sync(&conn, identity()).unwrap();
    assert_eq!((before.0, before.1, before.3), (after.0, after.1, after.3));
    assert_eq!(
        read_fenced_transition_v2_history_row_in_sync(&conn, identity(), false)
            .unwrap()
            .current_bound_count,
        2
    );
    let row = read_fenced_transition_v2_receipt_sync(&conn, identity(), &pending)
        .unwrap()
        .unwrap();
    assert_eq!(row.ordinal, 2);
    assert_eq!(
        row.retained_until,
        crate::ttl::checked_session_deadline(now, FENCED_TRANSITION_OUTCOME_RETENTION).unwrap()
    );
    validate_fenced_transition_v2_receipts_sync(&conn, identity()).unwrap();
    let replay = apply_entries_sync(
        &conn,
        identity(),
        &backend.caps,
        vec![fenced_transition_v2_entry(5, pending, now)],
    )
    .unwrap();
    assert_eq!(replay.responses[0], terminal.responses[0]);
    assert!(replay.notifications.is_empty());
}

#[test]
fn sqlite_lease_deferral_reopen_refuses_other_profiles_and_preserves_pending_status() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deferral.sqlite");
    let backend =
        SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, PROFILE).unwrap();
    let request = {
        let conn = backend.conn.blocking_lock();
        let (request, _) = fixture(&backend, &conn);
        let entry = fenced_transition_v2_entry(2, request.clone(), timestamp(2));
        append_logs_sync(&conn, identity(), std::slice::from_ref(&entry)).unwrap();
        save_committed_sync(&conn, identity(), Some(entry.log_id)).unwrap();
        let result = apply_entries_sync(&conn, identity(), &backend.caps, vec![entry]).unwrap();
        assert_eq!(
            result.responses[0].result,
            Err(StoreError::FencedTransitionLeaseDeferred)
        );
        validate_fenced_transition_v2_receipts_sync(&conn, identity()).unwrap();
        request
    };
    drop(backend);
    for old in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
    ] {
        assert!(SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, old).is_err());
    }
    let reopened =
        SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, PROFILE).unwrap();
    let conn = reopened.conn.blocking_lock();
    initialize(&conn);
    assert_eq!(
        read_fenced_transition_v2_status_sync(&conn, identity(), identity(), &request).unwrap(),
        FencedTransitionV2Status::LeaseDeferred {
            request_id: request.request_id()
        }
    );
    // A pending marker with no response is never a compacted terminal row.
    conn.execute("UPDATE consensus_fenced_transition_v2_receipts SET response_json=NULL, response_digest=NULL WHERE ordinal=2", []).unwrap();
    assert!(validate_fenced_transition_v2_receipts_sync(&conn, identity()).is_err());
    assert!(matches!(
        read_fenced_transition_v2_status_sync(&conn, identity(), identity(), &request),
        Err(StoreError::BackendUnavailable(_))
    ));
}

#[test]
fn sqlite_lease_deferral_snapshot_restores_pending_then_resolves_the_same_binding() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.sqlite");
    let snapshot = directory.path().join("snapshot.sqlite");
    let source =
        SqliteSessionBackend::open_with_fenced_transition_v2_profile(&source_path, PROFILE)
            .unwrap();
    let (request, meta) = {
        let conn = source.conn.blocking_lock();
        let (request, _) = fixture(&source, &conn);
        let entry = fenced_transition_v2_entry(2, request.clone(), timestamp(2));
        append_logs_sync(&conn, identity(), std::slice::from_ref(&entry)).unwrap();
        save_committed_sync(&conn, identity(), Some(entry.log_id)).unwrap();
        let applied = apply_entries_sync(&conn, identity(), &source.caps, vec![entry]).unwrap();
        assert_eq!(
            applied.responses[0].result,
            Err(StoreError::FencedTransitionLeaseDeferred)
        );
        let (last_log_id, last_membership) =
            build_snapshot_database_sync(&conn, identity(), &snapshot).unwrap();
        (
            request,
            opc_consensus::engine::SnapshotMeta {
                last_log_id,
                last_membership,
                snapshot_id: "lease-deferral".into(),
            },
        )
    };
    drop(source);
    let members = expected_members();
    let bindings = test_member_bindings(&members);
    let install = |conn: &Connection| {
        install_snapshot_database_with_authority_sync(
            conn,
            identity(),
            ConsensusAuthorityProfile::FixedImmutable,
            Some(&members),
            Some(&bindings),
            Some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
            &snapshot,
            &meta,
            "snapshot-00000000-0000-4000-8000-000000001334.opc",
            [0xD3; 32],
            std::fs::metadata(&snapshot).unwrap().len(),
        )
    };
    for (index, profile) in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
    ]
    .into_iter()
    .enumerate()
    {
        let path = directory
            .path()
            .join(format!("incompatible-{index}.sqlite"));
        let target =
            SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, profile).unwrap();
        let conn = target.conn.blocking_lock();
        initialize_profile(&conn, profile);
        let before = read_machine_sync(&conn, identity()).unwrap();
        assert!(install(&conn).is_err());
        assert_eq!(read_machine_sync(&conn, identity()).unwrap(), before);
        assert_eq!(
            fenced_transition_profile_in_sync(&conn, false).unwrap(),
            profile
        );
        assert_eq!(
            fenced_transition_v2_ledger_layout_sync(&conn).unwrap(),
            FencedTransitionV2LedgerLayout::Absent
        );
    }
    let target_path = directory.path().join("target.sqlite");
    let target =
        SqliteSessionBackend::open_with_fenced_transition_v2_profile(&target_path, PROFILE)
            .unwrap();
    {
        let conn = target.conn.blocking_lock();
        initialize(&conn);
        install(&conn).unwrap();
    }
    drop(target);
    let reopened =
        SqliteSessionBackend::open_with_fenced_transition_v2_profile(&target_path, PROFILE)
            .unwrap();
    let conn = reopened.conn.blocking_lock();
    initialize(&conn);
    assert_eq!(
        read_fenced_transition_v2_status_sync(&conn, identity(), identity(), &request).unwrap(),
        FencedTransitionV2Status::LeaseDeferred {
            request_id: request.request_id()
        }
    );
    let pending = read_fenced_transition_v2_receipt_sync(&conn, identity(), &request)
        .unwrap()
        .unwrap();
    assert_eq!(pending.ordinal, 2);
    assert_eq!(
        pending.retained_until,
        crate::fenced_transition::fenced_transition_v2_deferral_retention().unwrap()
    );
    let now = Timestamp::from_offset_datetime(
        *timestamp(0).as_offset_datetime() + time::Duration::seconds(400),
    );
    let entry = fenced_transition_v2_entry(3, request.clone(), now);
    append_logs_sync(&conn, identity(), std::slice::from_ref(&entry)).unwrap();
    save_committed_sync(&conn, identity(), Some(entry.log_id)).unwrap();
    let terminal = apply_entries_sync(&conn, identity(), &reopened.caps, vec![entry]).unwrap();
    assert!(matches!(&terminal.responses[0].result,
        Ok(SessionMutationOutcome::FencedTransition(outcome))
            if outcome.mutation() == FencedTransitionMutationResult::Deleted));
    assert!(ops::get_raw_sync(&conn, request.lease().key())
        .unwrap()
        .is_none());
    assert_eq!(terminal.notifications.len(), 1);
    let completed = read_fenced_transition_v2_receipt_sync(&conn, identity(), &request)
        .unwrap()
        .unwrap();
    assert_eq!(completed.ordinal, pending.ordinal);
    assert_eq!(completed.payload_digest, pending.payload_digest);
    assert_eq!(
        read_fenced_transition_v2_history_row_in_sync(&conn, identity(), false)
            .unwrap()
            .current_bound_count,
        2
    );
    validate_existing_schema(&conn, identity()).unwrap();
    let replay = fenced_transition_v2_entry(4, request, now);
    append_logs_sync(&conn, identity(), std::slice::from_ref(&replay)).unwrap();
    save_committed_sync(&conn, identity(), Some(replay.log_id)).unwrap();
    let replay = apply_entries_sync(&conn, identity(), &reopened.caps, vec![replay]).unwrap();
    assert_eq!(replay.responses[0], terminal.responses[0]);
    assert!(replay.notifications.is_empty());
}

#[test]
fn sqlite_lease_deferral_batch_and_late_projection_keep_one_binding_then_resolve_once() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    let (request, original) = fixture(&backend, &conn);
    let batch = fenced_transition_v2_batch_entry(2, vec![request.clone(), original], timestamp(2));
    let replay = fenced_transition_v2_entry(3, request.clone(), timestamp(3));
    let completed_at = Timestamp::from_offset_datetime(
        *timestamp(0).as_offset_datetime() + time::Duration::seconds(400),
    );
    let completed = activation(4, request.clone(), completed_at);
    let entries = vec![batch, replay, completed];
    // A lagging follower validates all unapplied commands before its pending
    // result exists. Membership authority must not depend on that prediction.
    append_logs_sync(&conn, identity(), &entries).unwrap();
    let applied = apply_entries_sync(&conn, identity(), &backend.caps, entries).unwrap();
    assert!(matches!(&applied.responses[0].result,
        Ok(SessionMutationOutcome::FencedTransitionV2Batch(items)) if items.len() == 2
            && matches!(items[0], Err(StoreError::FencedTransitionLeaseDeferred)) && items[1].is_ok()));
    assert_eq!(
        applied.responses[1].result,
        Err(StoreError::FencedTransitionLeaseDeferred)
    );
    assert!(matches!(
        applied.responses[2].result,
        Ok(SessionMutationOutcome::FencedTransition(_))
    ));
    assert_eq!(applied.notifications.len(), 1);
    assert_eq!(
        read_fenced_transition_v2_history_row_in_sync(&conn, identity(), false)
            .unwrap()
            .current_bound_count,
        2
    );
    assert_eq!(read_machine_sync(&conn, identity()).unwrap().0, 3);
    validate_fenced_transition_v2_receipts_sync(&conn, identity()).unwrap();
    let again = apply_entries_sync(
        &conn,
        identity(),
        &backend.caps,
        vec![fenced_transition_v2_entry(5, request, completed_at)],
    )
    .unwrap();
    assert_eq!(again.responses[0], applied.responses[2]);
    assert!(again.notifications.is_empty());
}

#[test]
fn sqlite_lease_deferral_scope_certification_does_not_authorize_an_unbound_epoch() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    fixture(&backend, &conn);
    let future = fenced_transition_v2_request(0xD7, 2, "future-synthetic-owner");
    let future_entry = activation(2, future.clone(), timestamp(2));
    append_logs_sync(&conn, identity(), std::slice::from_ref(&future_entry)).unwrap();
    let applied = apply_entries_sync(&conn, identity(), &backend.caps, vec![future_entry]).unwrap();
    assert_eq!(
        applied.responses[0].result,
        Err(StoreError::FencedTransitionHistoryEpochNotActive)
    );
    assert_eq!(
        read_fenced_transition_v2_history_row_in_sync(&conn, identity(), false)
            .unwrap()
            .current_bound_count,
        1
    );
    assert!(applied.notifications.is_empty());
    for field in 0..3 {
        let mut wrong = activation(3, future.clone(), timestamp(3));
        let EntryPayload::Normal(command) = &mut wrong.payload else {
            unreachable!()
        };
        let SessionMutationIntent::ActivateFencedTransitionV2 {
            scope_identity,
            voter_set_digest,
            profile_digest,
            ..
        } = &mut command.intent
        else {
            unreachable!()
        };
        match field {
            0 => {
                *scope_identity = SessionConsensusIdentity::new(
                    identity().cluster_id(),
                    identity().configuration_id(),
                    SessionConsensusConfigurationEpoch::new(2).unwrap(),
                )
            }
            1 => voter_set_digest[0] ^= 1,
            _ => *profile_digest = FencedTransitionV2Profile::V2WithVoid.digest(),
        }
        assert!(MembershipLogProjection::load(&conn, identity(), false)
            .unwrap()
            .project(&conn, &wrong, identity())
            .is_err());
    }
}
