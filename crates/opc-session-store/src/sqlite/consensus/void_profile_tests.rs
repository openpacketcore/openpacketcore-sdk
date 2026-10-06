use super::*;
use crate::FencedTransitionV2Profile;

#[test]
fn void_profile_has_an_independent_fixed_digest() {
    let digest = FencedTransitionV2Profile::V2WithVoid.digest();
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        hex,
        "b8a3a152271de6b0d0acd9f2d5218b0077b348aa7bfd4df580bdb20693966d7e"
    );
    assert_ne!(digest, FencedTransitionV2Profile::V2.digest());
    assert_eq!(
        FencedTransitionV2Profile::V2.digest(),
        fenced_transition_v2_profile_digest()
    );
}

fn identity() -> SessionConsensusIdentity {
    SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::from_bytes([21; 32]),
        SessionConsensusConfigurationId::from_bytes([22; 32]),
        SessionConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn members() -> BTreeSet<SessionConsensusNodeId> {
    [1, 2, 3]
        .into_iter()
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .collect()
}

fn initialize(
    conn: &Connection,
    profile: FencedTransitionV2Profile,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    initialize_schema_with_storage_anchor_and_pending_and_bindings_and_fenced_profile(
        conn,
        None,
        identity(),
        &members(),
        &test_member_bindings(&members()),
        None,
        ConsensusAuthorityProfile::FixedImmutable,
        Some(PlacementResiliencePolicy::RequireIndependentFailureDomains),
        None,
        profile,
    )
}

#[test]
fn void_store_profile_is_selected_atomically_at_creation_and_never_converted() {
    for profile in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
    ] {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        assert_eq!(initialize(&conn, profile), Ok(identity()));
        assert_eq!(
            fenced_transition_profile_in_sync(&conn, false).unwrap(),
            profile
        );
        assert_eq!(initialize(&conn, profile), Ok(identity()));
        let other = if profile == FencedTransitionV2Profile::V2 {
            FencedTransitionV2Profile::V2WithVoid
        } else {
            FencedTransitionV2Profile::V2
        };
        assert_eq!(
            initialize(&conn, other),
            Err(SessionConsensusStorageError::SchemaVersionMismatch)
        );
        assert_eq!(
            fenced_transition_profile_in_sync(&conn, false).unwrap(),
            profile
        );
    }
}

#[test]
fn void_profile_marker_and_scope_survive_other_lane_activation() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    initialize(&conn, FencedTransitionV2Profile::V2WithVoid).unwrap();
    activate_fenced_transition_scope_sync(&conn, identity(), identity(), &members()).unwrap();
    activate_fenced_transition_v2_scope_sync(
        &conn,
        identity(),
        identity(),
        &members(),
        FencedTransitionV2Profile::V2WithVoid.digest(),
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
    )
    .unwrap();
    let format: i64 = conn
        .query_row("SELECT schema_version FROM consensus_identity", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        format, 6,
        "an old reader must still reject the extended store"
    );
    assert_eq!(
        initialize(&conn, FencedTransitionV2Profile::V2WithVoid),
        Ok(identity())
    );
    assert!(fenced_transition_v2_activation_matches_scope_sync(
        &conn,
        identity(),
        identity(),
        &members(),
        FencedTransitionV2Profile::V2WithVoid.digest(),
    )
    .unwrap());
    assert!(!fenced_transition_v2_activation_matches_scope_sync(
        &conn,
        identity(),
        identity(),
        &members(),
        FencedTransitionV2Profile::V2.digest(),
    )
    .unwrap());
}

#[test]
fn void_profile_refuses_missing_marker_and_cannot_be_inferred_from_v2_activation() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    initialize(&conn, FencedTransitionV2Profile::V2).unwrap();
    assert!(activate_fenced_transition_v2_scope_sync(
        &conn,
        identity(),
        identity(),
        &members(),
        FencedTransitionV2Profile::V2WithVoid.digest(),
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
    )
    .is_err());
    conn.execute("UPDATE consensus_identity SET schema_version=6", [])
        .unwrap();
    assert_eq!(
        initialize(&conn, FencedTransitionV2Profile::V2WithVoid),
        Err(SessionConsensusStorageError::SchemaVersionMismatch)
    );
}

#[test]
fn void_receipt_codec_is_closed_under_the_original_profile() {
    let response = SessionConsensusResponse {
        result: Err(StoreError::FencedTransitionVoided),
        sequence: 1,
        digest: Some(SessionConsensusEntryDigest::GENESIS),
        logical_time: Some("2026-07-12T00:00:01Z".parse().unwrap()),
        raft_log_index: 2,
    };
    assert!(encode_fenced_transition_v2_response(&response).is_err());
    let bytes = encode_fenced_transition_v2_response_with_profile(
        &response,
        FencedTransitionV2Profile::V2WithVoid,
    )
    .unwrap();
    assert!(decode_fenced_transition_v2_response(&bytes).is_err());
    assert_eq!(
        decode_fenced_transition_v2_response_with_profile(
            &bytes,
            FencedTransitionV2Profile::V2WithVoid
        )
        .unwrap(),
        response
    );
}

#[test]
fn void_public_open_refuses_the_other_profile_and_tampered_marker() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite");
    for profile in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
    ] {
        let path = path.with_extension(if profile == FencedTransitionV2Profile::V2 {
            "base"
        } else {
            "void"
        });
        let backend =
            SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, profile).unwrap();
        initialize(&backend.conn.blocking_lock(), profile).unwrap();
        drop(backend);
        let other = if profile == FencedTransitionV2Profile::V2 {
            FencedTransitionV2Profile::V2WithVoid
        } else {
            FencedTransitionV2Profile::V2
        };
        assert!(
            SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, other).is_err()
        );
        let reopened =
            SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, profile).unwrap();
        if profile == FencedTransitionV2Profile::V2WithVoid {
            reopened
                .conn
                .blocking_lock()
                .execute(
                    "UPDATE consensus_fenced_transition_profile SET profile_digest=zeroblob(32)",
                    [],
                )
                .unwrap();
            drop(reopened);
            assert!(
                SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, profile)
                    .is_err()
            );
        }
    }
}

#[test]
fn void_snapshot_cannot_convert_a_stores_profile() {
    let directory = tempfile::tempdir().unwrap();
    for local in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
    ] {
        let remote = if local == FencedTransitionV2Profile::V2 {
            FencedTransitionV2Profile::V2WithVoid
        } else {
            FencedTransitionV2Profile::V2
        };
        let path = directory.path().join(format!("incoming-{local:?}.sqlite"));
        let incoming =
            SqliteSessionBackend::open_with_fenced_transition_v2_profile(&path, remote).unwrap();
        initialize(&incoming.conn.blocking_lock(), remote).unwrap();
        drop(incoming);
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        initialize(&conn, local).unwrap();
        conn.execute(
            "ATTACH DATABASE ?1 AS consensus_incoming",
            [path.to_str().unwrap()],
        )
        .unwrap();
        assert!(void_profile::copy_snapshot_layout(&conn).is_err());
        assert_eq!(
            fenced_transition_profile_in_sync(&conn, false).unwrap(),
            local
        );
    }
}

#[test]
fn void_profile_with_both_rosters_builds_a_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    initialize(&conn, FencedTransitionV2Profile::V2WithVoid).unwrap();
    activate_protected_roster_schema_sync(&conn).unwrap();
    activate_fenced_transition_v2_scope_sync(
        &conn,
        identity(),
        identity(),
        &members(),
        FencedTransitionV2Profile::V2WithVoid.digest(),
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
    )
    .unwrap();
    activate_protected_roster_profile_v2_scope_sync(
        &conn,
        identity(),
        identity(),
        &members(),
        crate::fenced_mutation_roster::Profile::v2().digest(),
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get::<_, usize>(0),
        )
        .unwrap(),
        45,
    );
    build_snapshot_database_sync(&conn, identity(), &directory.path().join("snapshot.sqlite"))
        .unwrap();
}

#[test]
fn roster_activation_refuses_to_downgrade_either_store_profile() {
    for profile in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
    ] {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        initialize(&conn, profile).unwrap();
        activate_protected_roster_profile_v2_scope_sync(
            &conn,
            identity(),
            identity(),
            &members(),
            crate::fenced_mutation_roster::Profile::v2().digest(),
        )
        .unwrap();
        activate_fenced_transition_v2_scope_sync(
            &conn,
            identity(),
            identity(),
            &members(),
            profile.digest(),
            FencedTransitionV2HistoryEpoch::new(1).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted_schema_version_in_sync(&conn, false).unwrap(), 5);
        assert!(activate_protected_roster_schema_sync(&conn).is_err());
        assert_eq!(persisted_schema_version_in_sync(&conn, false).unwrap(), 5);
        assert_eq!(
            fenced_transition_profile_in_sync(&conn, false).unwrap(),
            profile
        );
    }
}
