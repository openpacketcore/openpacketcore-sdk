use super::*;
use crate::FencedTransitionV2Profile;

const PROFILE: FencedTransitionV2Profile = FencedTransitionV2Profile::V2WithLeaseDeferral;

#[test]
fn sqlite_lease_deferral_profile_has_an_independent_fixed_digest() {
    let hex = PROFILE
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        hex,
        "ff9fb5a129821261d9ddd2cd1482aedd4e528642fc3f3474ce8580c86a6c3d4a"
    );
}

fn initialize(conn: &Connection) {
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
        PROFILE,
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
    let SessionMutationIntent::ActivateFencedTransitionV2 { profile_digest, .. } =
        &mut command.intent
    else {
        unreachable!()
    };
    *profile_digest = PROFILE.digest();
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
