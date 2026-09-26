//! Stored result corruption must not become authenticated operation recovery.

use super::*;

const REQUEST: [u8; 16] = [0xA7; 16];

async fn fixture(profile: ConfigCapacityProfile) -> SqliteBackend {
    let backend = SqliteBackend::in_memory_for_test().await.unwrap();
    let shared = backend.conn();
    let conn = shared.lock().await;
    initialize_schema_for_profile(
        &conn,
        identity(),
        &expected_members(),
        backend.audit_key(),
        profile,
        None,
        &Arc::new(SqliteWorkCancellation::new()),
        None,
    )
    .unwrap();
    let response = apply_entries_cancellable_sync(
        &conn,
        identity(),
        &expected_members(),
        vec![membership_entry(), missing_entry(1, REQUEST, profile)],
        &SqliteWorkCancellation::new(),
        backend.audit_key(),
        None,
        profile,
    )
    .unwrap();
    assert_eq!(response[1].result, Err(ConfigMutationFailure::NotFound));
    drop(conn);
    backend
}

fn missing_entry(
    index: u64,
    request: [u8; 16],
    profile: ConfigCapacityProfile,
) -> Entry<ConfigRaftTypeConfig> {
    mark_confirmed_entry_with_version(
        1,
        index,
        request,
        TxId::from_uuid(uuid::Uuid::from_bytes([0xA8; 16])),
        crate::consensus::types::config_command_revision(profile),
    )
}

async fn lookup(
    backend: &SqliteBackend,
    profile: ConfigCapacityProfile,
) -> io::Result<Option<([u8; 32], ConfigConsensusResponse)>> {
    read_commit_outcome_until(
        backend,
        identity(),
        ConfigConsensusRequestId::from_bytes(REQUEST),
        profile,
        tokio::time::Instant::now() + Duration::from_secs(30),
    )
    .await
}

fn original_row(conn: &Connection) -> (Vec<u8>, Vec<u8>) {
    conn.query_row(
        "SELECT payload_digest, response_json FROM config_raft_request_outcomes WHERE request_id = ?1",
        [REQUEST.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

#[tokio::test]
async fn config_capacity_957_recovery_bounds_result_before_decoding() {
    let profile = ConfigCapacityProfile::BoundedV1;
    let backend = fixture(profile).await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    let (_, mut encoded) = original_row(&conn);
    // Trailing JSON whitespace does not change the authenticated value. Only
    // the borrowed-row size gate can reject this otherwise valid encoding.
    encoded.extend(std::iter::repeat_n(b' ', 16 * 1024));
    conn.execute(
        "UPDATE config_raft_request_outcomes SET response_json = ?1",
        [encoded],
    )
    .unwrap();
    drop(conn);
    assert!(
        lookup(&backend, profile).await.is_err(),
        "CONFIG_RECOVERY_ROW_BOUND: oversized valid JSON bypassed the row bound"
    );
}

#[tokio::test]
async fn config_capacity_957_recovery_reads_only_scalar_retention_metadata() {
    let profile = ConfigCapacityProfile::BoundedV1;
    let backend = fixture(profile).await;
    let shared = backend.conn();
    let conn = shared.lock().await;
    conn.execute(
        "UPDATE config_raft_machine SET logical_time = ?1",
        ["x".repeat(1024 * 1024)],
    )
    .unwrap();
    drop(conn);
    // The result's own logical time is authenticated in its proof. Reading
    // the retention sequence must not materialize unrelated machine text.
    assert_eq!(
        lookup(&backend, profile).await.unwrap().unwrap().1.result,
        Err(ConfigMutationFailure::NotFound)
    );
}

#[tokio::test]
async fn config_capacity_957_recovery_rejects_forged_retained_results() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let backend = fixture(profile).await;
        assert_eq!(
            lookup(&backend, profile).await.unwrap().unwrap().1.result,
            Err(ConfigMutationFailure::NotFound)
        );
        let shared = backend.conn();
        let conn = shared.lock().await;
        let (_, original) = original_row(&conn);
        drop(conn);
        for (field, changed) in [
            ("result", serde_json::json!({"Ok": null})),
            ("raft_log_index", serde_json::json!(2)),
            ("logical_time", serde_json::json!("2026-01-02T00:00:00Z")),
        ] {
            let mut response: serde_json::Value = serde_json::from_slice(&original).unwrap();
            response[field] = changed;
            let conn = shared.lock().await;
            conn.execute(
                "UPDATE config_raft_request_outcomes SET response_json = ?1 WHERE request_id = ?2",
                params![serde_json::to_vec(&response).unwrap(), REQUEST.as_slice()],
            )
            .unwrap();
            assert!(
                validate_sealed_state_for_profile_sync(
                    &conn,
                    identity(),
                    backend.audit_key(),
                    profile,
                    &SqliteWorkCancellation::new(),
                )
                .is_err(),
                "CONFIG_RECOVERY_RESULT_AUTH: retained admission accepted forged {field}"
            );
            drop(conn);
            assert!(
                lookup(&backend, profile).await.is_err(),
                "CONFIG_RECOVERY_RESULT_AUTH: lookup accepted forged {field}"
            );
        }
    }
}

#[tokio::test]
async fn config_capacity_957_recovery_proof_binds_request_payload_and_scope() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let backend = fixture(profile).await;
        let shared = backend.conn();
        let conn = shared.lock().await;
        let (digest, original) = original_row(&conn);
        let request = ConfigConsensusRequestId::from_bytes(REQUEST);
        let changed_request = ConfigConsensusRequestId::from_bytes([0xA9; 16]);
        conn.execute(
            "UPDATE config_raft_request_outcomes SET request_id = ?1",
            [changed_request.as_bytes().as_slice()],
        )
        .unwrap();
        assert!(outcome_authentication::read(
            &conn,
            identity(),
            backend.audit_key(),
            profile,
            changed_request,
            true
        )
        .is_err());
        conn.execute(
            "UPDATE config_raft_request_outcomes SET request_id = ?1, payload_digest = ?2",
            params![REQUEST.as_slice(), [0xAA_u8; 32].as_slice()],
        )
        .unwrap();
        assert!(outcome_authentication::read(
            &conn,
            identity(),
            backend.audit_key(),
            profile,
            request,
            true
        )
        .is_err());
        conn.execute(
            "UPDATE config_raft_request_outcomes SET payload_digest = ?1",
            [digest],
        )
        .unwrap();
        let other_key = AuditKey::new_with_epoch(
            *backend.audit_key().as_bytes(),
            backend.audit_key().epoch() + 1,
        )
        .unwrap();
        assert!(outcome_authentication::read(
            &conn,
            identity(),
            &other_key,
            profile,
            request,
            true
        )
        .is_err());
        let other_identity = ConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0xAB; 32]),
            identity().configuration_id(),
            identity().configuration_epoch(),
        );
        assert!(outcome_authentication::read(
            &conn,
            other_identity,
            backend.audit_key(),
            profile,
            request,
            true
        )
        .is_err());
        let other_profile = if profile == ConfigCapacityProfile::Legacy {
            ConfigCapacityProfile::BoundedV1
        } else {
            ConfigCapacityProfile::Legacy
        };
        assert!(outcome_authentication::read(
            &conn,
            identity(),
            backend.audit_key(),
            other_profile,
            request,
            true
        )
        .is_err());
        let mut response: serde_json::Value = serde_json::from_slice(&original).unwrap();
        response["sequence"] = serde_json::json!(2);
        conn.execute(
            "UPDATE config_raft_request_outcomes SET applied_sequence = 2, response_json = ?1",
            [serde_json::to_vec(&response).unwrap()],
        )
        .unwrap();
        assert!(outcome_authentication::read(
            &conn,
            identity(),
            backend.audit_key(),
            profile,
            request,
            true
        )
        .is_err());
    }
}

#[tokio::test]
async fn config_capacity_957_raw_legacy_results_never_prove_recovery() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let backend = fixture(profile).await;
        let shared = backend.conn();
        let conn = shared.lock().await;
        let (_, original) = original_row(&conn);
        let mut response: serde_json::Value = serde_json::from_slice(&original).unwrap();
        response.as_object_mut().unwrap().remove("recovery_proof");
        conn.execute(
            "UPDATE config_raft_request_outcomes SET response_json = ?1",
            [serde_json::to_vec(&response).unwrap()],
        )
        .unwrap();
        let replay = read_outcome_sync(
            &conn,
            identity(),
            backend.audit_key(),
            profile,
            ConfigConsensusRequestId::from_bytes(REQUEST),
        );
        if profile == ConfigCapacityProfile::Legacy {
            assert_eq!(
                replay.unwrap().unwrap().1.result,
                Err(ConfigMutationFailure::NotFound)
            );
        } else {
            assert!(replay.is_err());
        }
        drop(conn);
        let recovered = lookup(&backend, profile).await;
        if profile == ConfigCapacityProfile::Legacy {
            assert!(
                recovered.unwrap().is_none(),
                "CONFIG_RECOVERY_PROOF_REQUIRED: raw Legacy result proved recovery"
            );
        } else {
            assert!(recovered.is_err());
        }
    }
}

#[tokio::test]
async fn config_capacity_957_expired_authentic_result_cannot_be_replayed() {
    for profile in [
        ConfigCapacityProfile::Legacy,
        ConfigCapacityProfile::BoundedV1,
    ] {
        let backend = fixture(profile).await;
        let shared = backend.conn();
        let conn = shared.lock().await;
        let (digest, response) = original_row(&conn);
        for start in (2..=4097).step_by(1024) {
            let entries = (start..start + 1024)
                .map(|index| missing_entry(index, u128::from(index).to_be_bytes(), profile))
                .collect();
            apply_entries_cancellable_sync(
                &conn,
                identity(),
                &expected_members(),
                entries,
                &SqliteWorkCancellation::new(),
                backend.audit_key(),
                None,
                profile,
            )
            .unwrap();
        }
        assert!(read_outcome_sync(
            &conn,
            identity(),
            backend.audit_key(),
            profile,
            ConfigConsensusRequestId::from_bytes(REQUEST)
        )
        .unwrap()
        .is_none());
        conn.execute(
            "INSERT INTO config_raft_request_outcomes(request_id, configuration_epoch, applied_sequence, payload_digest, response_json) VALUES (?1, ?2, 1, ?3, ?4)",
            params![REQUEST.as_slice(), epoch_i64(identity()).unwrap(), digest, response],
        ).unwrap();
        // Keep the count within the old bound: the replay is stale even if a
        // corrupting writer also removes a different, still-retained outcome.
        conn.execute(
            "DELETE FROM config_raft_request_outcomes WHERE applied_sequence = 2",
            [],
        )
        .unwrap();
        assert!(validate_sealed_state_for_profile_sync(
            &conn,
            identity(),
            backend.audit_key(),
            profile,
            &SqliteWorkCancellation::new()
        )
        .is_err());
        drop(conn);
        assert!(
            lookup(&backend, profile).await.unwrap().is_none(),
            "CONFIG_RECOVERY_RETENTION: an expired authentic result proved recovery"
        );
    }
}
