//! Native capacity8 component evidence only: the caller supplies independent
//! identity/profile/caller context and owns transaction rollback. This does not
//! exercise target Intent, checkpoint, lock reduction or joint-mode opening.

use super::joint_running::CapacityRunningAuthority;
use super::joint_running_gate_tests::{authority_digest, context, fixture, Fixture};
use super::*;
use crate::audit_authority::{
    AuditCaller, AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey,
};
use crate::consensus::audit_mutation::joint_running::{
    tests::prepared_for_store, BoundedRunningPayload,
};
use crate::consensus::audit_mutation::{PreparedTargetMutation, TargetPayloadV1};
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::{CommitRecord, ConfigStore};
use opc_crypto::ConfigPreparationPool;
use rusqlite::hooks::{Action, AuthAction, AuthContext, Authorization};
use std::sync::atomic::AtomicUsize;

fn authority(fixture: &Fixture) -> CapacityRunningAuthority {
    // Recreate the authenticated fixture principal from its independent input,
    // not the command's caller/identity fields or a stored capacity-profile row.
    let caller = AuditCaller::project(
        &AuditPrivacyKey::new([0x75; 32]).expect("fixture privacy key"),
        "synthetic",
        "synthetic-principal",
    )
    .expect("independent fixture caller");
    CapacityRunningAuthority {
        identity: fixture.identity,
        caller,
        mode: RetainedConfigMode::BoundedV1,
    }
}

type Writes = Arc<[AtomicUsize; 2]>;

fn observe_writes(
    conn: &Connection,
    cancel_after_proof: Option<Arc<SqliteWorkCancellation>>,
) -> Writes {
    let writes = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let observed = Arc::clone(&writes);
    conn.update_hook(Some(
        move |action: Action, database: &str, table: &str, _: i64| {
            if database != "main" || action != Action::SQLITE_INSERT {
                return;
            }
            match table {
                "config_history" => {
                    observed[0].fetch_add(1, Ordering::SeqCst);
                }
                "config_raft_capacity_records" => {
                    observed[1].fetch_add(1, Ordering::SeqCst);
                    if let Some(cancellation) = &cancel_after_proof {
                        assert!(
                            cancellation.cancel_before_commit(),
                            "actual proof insert precedes cancellation"
                        );
                    }
                }
                _ => {}
            }
        },
    ))
    .expect("actual native write observation");
    writes
}

fn counts(writes: &Writes) -> [usize; 2] {
    writes.each_ref().map(|value| value.load(Ordering::SeqCst))
}

fn clear_observation(conn: &Connection) {
    conn.update_hook(None::<fn(Action, &str, &str, i64)>)
        .expect("remove native observation");
}

fn commit_component(conn: &Connection, fixture: &Fixture, prepared: &PreparedTargetMutation) {
    let cancellation = SqliteWorkCancellation::new();
    conn.execute_batch("BEGIN IMMEDIATE; SAVEPOINT audited_target_effect")
        .expect("authority savepoint");
    let result = apply_target_running_with_authority_sync(
        conn,
        &fixture.key,
        prepared.command(),
        None,
        &context(&cancellation),
        Some(&authority(fixture)),
    )
    .expect("native component I/O");
    assert!(
        result.is_ok(),
        "JOINT_NATIVE_RUNNING_REAL_COMPONENT_WRITE: {result:?}"
    );
    conn.execute_batch("RELEASE audited_target_effect")
        .expect("release authority savepoint");
    cancellation
        .authorize_commit()
        .expect("native commit authorization");
    conn.execute_batch("COMMIT").expect("Durable native commit");
}

async fn assert_native_readback(
    backend: &SqliteBackend,
    identity: ConsensusIdentity,
    key: &AuditKey,
    expected: &CommitRecord,
    proof: &[u8],
) {
    let actual = backend
        .load_latest()
        .await
        .expect("authenticated native read")
        .expect("native head");
    assert!(
        actual.record == *expected,
        "JOINT_NATIVE_RUNNING_EXACT_RECORD"
    );
    let shared = backend.conn();
    let conn = shared.lock().await;
    super::super::history::validate_access_for_profile_sync(
        &conn,
        key,
        true,
        Some(identity),
        RetainedConfigMode::BoundedV1,
        &SqliteWorkCancellation::new(),
    )
    .expect("JOINT_NATIVE_RUNNING_AUTHENTICATED_HISTORY");
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT binding FROM config_raft_capacity_records WHERE tx_id = ?1",
            [expected.tx_id.as_uuid().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("actual retained capacity proof");
    assert_eq!(stored, proof, "JOINT_NATIVE_RUNNING_ORIGINAL_PROOF_BYTES");
    CapacityRecordBinding::decode(&stored)
        .expect("proof representation")
        .verify(
            &actual.record,
            identity,
            key,
            ConfigCapacityProfile::BoundedV1,
        )
        .expect("exact scoped retained proof authenticates original ciphertext");
    assert!(crate::schema::verify_wal_mode(&conn).expect("native WAL"));
    assert!(crate::schema::verify_synchronous_extra(&conn).expect("native Durable"));
    drop(conn);
    drop(shared);
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("joint-payload-test").expect("synthetic key ID"),
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("synthetic"),
            opc_key::Zeroizing::new([0x71; 32]),
        )
        .expect("synthetic Config key");
    let envelope = opc_crypto::CryptoEnvelopeRef::decode(&actual.record.encrypted_blob)
        .expect("exact encrypted record");
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).expect("bound AAD");
    let plaintext = opc_crypto::decrypt_envelope(&provider, &aad, &actual.record.encrypted_blob)
        .await
        .expect("retained AEAD readback");
    assert_eq!(
        plaintext.as_slice(),
        br#"{"enabled":true}"#,
        "real configuration readback"
    );
}

async fn close_reopen(fixture: Fixture, expected: CommitRecord, proof: Vec<u8>) {
    assert_native_readback(
        &fixture.backend,
        fixture.identity,
        &fixture.key,
        &expected,
        &proof,
    )
    .await;
    let Fixture {
        backend,
        options,
        identity,
        key,
        root,
    } = fixture;
    drop(backend);
    let reopened = SqliteBackend::reopen_config_authority(options, key.clone())
        .await
        .expect("JOINT_NATIVE_RUNNING_RETAINED_REOPEN");
    assert_native_readback(&reopened, identity, &key, &expected, &proof).await;
    drop(reopened);
    drop(root);
}

fn expected(prepared: &PreparedTargetMutation) -> (CommitRecord, Vec<u8>) {
    let payload = prepared
        .bounded_running()
        .expect("real bounded preparation");
    (
        payload.commit().record.clone(),
        payload.binding().encode().to_vec(),
    )
}

#[tokio::test]
async fn joint_native_running_component_retains_exact_authenticated_record() {
    let fixture = fixture().await;
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = prepared_for_store(&pool, fixture.identity, &fixture.key).await;
    let original = prepared.encode().expect("exact original representation");
    let (record, proof) = expected(&prepared);
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let writes = observe_writes(&conn, None);
        commit_component(&conn, &fixture, &prepared);
        clear_observation(&conn);
        assert_eq!(
            counts(&writes),
            [1, 1],
            "JOINT_NATIVE_RUNNING_RECORD_AND_PROOF_INSERTS"
        );
        assert_eq!(
            prepared.encode().expect("unchanged representation"),
            original
        );
    }
    // Read the committed record before duplicate validation can reject stale
    // history. Both the SQL guard and shared connection owner are out of scope.
    assert_native_readback(
        &fixture.backend,
        fixture.identity,
        &fixture.key,
        &record,
        &proof,
    )
    .await;
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let before = authority_digest(&conn);
        conn.execute_batch("BEGIN IMMEDIATE; SAVEPOINT audited_target_effect")
            .expect("duplicate transaction");
        let cancellation = SqliteWorkCancellation::new();
        let duplicate = apply_target_running_with_authority_sync(
            &conn,
            &fixture.key,
            prepared.command(),
            None,
            &context(&cancellation),
            Some(&authority(&fixture)),
        )
        .expect("typed duplicate refusal");
        conn.execute_batch("ROLLBACK").expect("duplicate rollback");
        assert!(
            matches!(duplicate, Err(ConfigMutationFailure::Conflict)),
            "same exact component record is not inserted twice"
        );
        assert_eq!(authority_digest(&conn), before);
    }
    drop(prepared);
    // No original preparation remains when retained reopening occurs.
    let slots: Vec<_> = (0..8)
        .map(|_| pool.try_reserve().expect("released original preparation"))
        .collect();
    assert!(
        pool.try_reserve().is_err(),
        "same eight-slot preparation bound"
    );
    drop(slots);
    close_reopen(fixture, record, proof).await;
}

fn resign(prepared: &mut PreparedTargetMutation, key: &AuditKey) {
    let digest = prepared
        .command()
        .effect
        .digest(key)
        .expect("changed effect digest");
    let mut body = prepared.command().handle.body.clone();
    body.mutation = Some(digest);
    body.binding = AuditOperationBinding::project(
        &AuditPrivacyKey::new([0x75; 32]).expect("fixture privacy key"),
        &body.event,
        0,
        &digest,
    )
    .expect("changed exact operation binding");
    prepared.command_mut().handle =
        AuditOperationHandle::issue(body, key).expect("authentic enclosing handle");
}

fn tamper_payload(
    prepared: &PreparedTargetMutation,
    key: &AuditKey,
    ciphertext: bool,
) -> PreparedTargetMutation {
    let mut changed = prepared.clone();
    let mut value = serde_json::to_value(changed.bounded_running().expect("bounded payload"))
        .expect("payload representation");
    let bytes = if ciphertext {
        value["commit"]["record"]["encrypted_blob"]
            .as_array_mut()
            .expect("real ciphertext bytes")
    } else {
        value["binding"]["tag"]
            .as_array_mut()
            .expect("proof tag bytes")
    };
    let last = bytes.last_mut().expect("nonempty authenticated bytes");
    *last = serde_json::json!(last.as_u64().expect("byte") ^ 1);
    let payload: BoundedRunningPayload =
        serde_json::from_value(value).expect("well-framed unauthenticated representation");
    changed.command_mut().effect.encrypted_payload = Some(TargetPayloadV1::BoundedRunning(payload));
    // The enclosing effect and handle are valid, so rejection must not rely
    // only on a stale effect MAC. The original capacity binding is not reminted.
    resign(&mut changed, key);
    changed
}

#[tokio::test]
async fn joint_native_running_component_authentication_refuses_before_writes() {
    let fixture = fixture().await;
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = prepared_for_store(&pool, fixture.identity, &fixture.key).await;
    let (record, proof) = expected(&prepared);
    let wrong_caller = AuditCaller::project(
        &AuditPrivacyKey::new([0x75; 32]).expect("privacy key"),
        "other",
        "synthetic-principal",
    )
    .expect("foreign caller");
    let foreign = ConsensusIdentity::new(
        fixture.identity.cluster_id(),
        crate::consensus::ConfigConsensusConfigurationId::from_bytes([0xD1; 32]),
        fixture.identity.configuration_epoch(),
    );
    let bad_proof = tamper_payload(&prepared, &fixture.key, false);
    let bad_ciphertext = tamper_payload(&prepared, &fixture.key, true);
    let mut bad_effect = prepared.clone();
    bad_effect.command_mut().effect.expires_at -= 1;
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let before = authority_digest(&conn);
        let writes = observe_writes(&conn, None);
        let cancellation = SqliteWorkCancellation::new();
        let outside = apply_target_running_with_authority_sync(
            &conn,
            &fixture.key,
            prepared.command(),
            None,
            &context(&cancellation),
            Some(&authority(&fixture)),
        )
        .expect_err("caller transaction is required");
        assert_eq!(outside.kind(), io::ErrorKind::InvalidData);
        for (command, supplied, key, pending) in [
            (&bad_proof, authority(&fixture), fixture.key.clone(), None),
            (
                &bad_ciphertext,
                authority(&fixture),
                fixture.key.clone(),
                None,
            ),
            (&bad_effect, authority(&fixture), fixture.key.clone(), None),
            (
                &prepared,
                CapacityRunningAuthority {
                    caller: wrong_caller,
                    ..authority(&fixture)
                },
                fixture.key.clone(),
                None,
            ),
            (
                &prepared,
                CapacityRunningAuthority {
                    identity: foreign,
                    ..authority(&fixture)
                },
                fixture.key.clone(),
                None,
            ),
            (
                &prepared,
                CapacityRunningAuthority {
                    mode: RetainedConfigMode::Legacy,
                    ..authority(&fixture)
                },
                fixture.key.clone(),
                None,
            ),
            (
                &prepared,
                authority(&fixture),
                AuditKey::new([0xD2; 32]).expect("foreign key"),
                None,
            ),
            (
                &prepared,
                authority(&fixture),
                fixture.key.clone(),
                Some(record.tx_id),
            ),
        ] {
            conn.execute_batch("BEGIN IMMEDIATE; SAVEPOINT audited_target_effect")
                .expect("refusal savepoint");
            let result = apply_target_running_with_authority_sync(
                &conn,
                &key,
                command.command(),
                pending,
                &context(&cancellation),
                Some(&supplied),
            )
            .expect("typed authentication refusal");
            conn.execute_batch("ROLLBACK").expect("refusal rollback");
            assert!(
                matches!(result, Err(ConfigMutationFailure::InvalidInput)),
                "JOINT_NATIVE_RUNNING_AUTHENTICATION_REFUSAL"
            );
            assert_eq!(
                counts(&writes),
                [0, 0],
                "JOINT_NATIVE_RUNNING_INVALID_HAS_NO_WRITES"
            );
            assert_eq!(authority_digest(&conn), before);
        }
        clear_observation(&conn);
        commit_component(&conn, &fixture, &prepared);
    }
    drop(bad_effect);
    drop(bad_ciphertext);
    drop(bad_proof);
    drop(prepared);
    close_reopen(fixture, record, proof).await;
}

#[tokio::test]
async fn joint_native_running_component_io_rolls_back_record_proof_and_history() {
    let fixture = fixture().await;
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = prepared_for_store(&pool, fixture.identity, &fixture.key).await;
    let (record, proof) = expected(&prepared);
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let before = authority_digest(&conn);
        let writes = observe_writes(&conn, None);
        let denied = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&writes);
        let denials = Arc::clone(&denied);
        conn.authorizer(Some(move |event: AuthContext<'_>| {
            if matches!(event.action, AuthAction::Update { table_name, .. } if table_name == "config_raft_history_retention")
                && counts(&observed) == [1, 1] {
                denials.fetch_add(1, Ordering::SeqCst);
                return Authorization::Deny;
            }
            Authorization::Allow
        })).expect("real SQLite authorizer fault");
        conn.execute_batch("BEGIN IMMEDIATE; SAVEPOINT audited_target_effect")
            .expect("authority savepoint");
        let cancellation = SqliteWorkCancellation::new();
        let result = apply_target_running_with_authority_sync(
            &conn,
            &fixture.key,
            prepared.command(),
            None,
            &context(&cancellation),
            Some(&authority(&fixture)),
        );
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
            .expect("remove actual fault");
        clear_observation(&conn);
        assert_eq!(
            counts(&writes),
            [1, 1],
            "JOINT_NATIVE_RUNNING_IO_AFTER_REAL_WRITES"
        );
        assert!(
            denied.load(Ordering::SeqCst) > 0,
            "JOINT_NATIVE_RUNNING_REAL_HISTORY_UPDATE_DENIAL"
        );
        assert!(
            result.is_err(),
            "authorizer error reaches authoritative outer rollback"
        );
        conn.execute_batch("ROLLBACK")
            .expect("caller rolls back I/O");
        assert!(conn.is_autocommit());
        assert_eq!(
            authority_digest(&conn),
            before,
            "JOINT_NATIVE_RUNNING_IO_OUTER_ROLLBACK"
        );
        commit_component(&conn, &fixture, &prepared);
    }
    drop(prepared);
    close_reopen(fixture, record, proof).await;
}

#[tokio::test]
async fn joint_native_running_component_cancel_after_proof_rolls_back() {
    let fixture = fixture().await;
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = prepared_for_store(&pool, fixture.identity, &fixture.key).await;
    let (record, proof) = expected(&prepared);
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let before = authority_digest(&conn);
        let cancellation = Arc::new(SqliteWorkCancellation::new());
        let writes = observe_writes(&conn, Some(Arc::clone(&cancellation)));
        conn.execute_batch("BEGIN IMMEDIATE; SAVEPOINT audited_target_effect")
            .expect("authority savepoint");
        let result = apply_target_running_with_authority_sync(
            &conn,
            &fixture.key,
            prepared.command(),
            None,
            &context(&cancellation),
            Some(&authority(&fixture)),
        );
        clear_observation(&conn);
        assert_eq!(
            counts(&writes),
            [1, 1],
            "JOINT_NATIVE_RUNNING_CANCEL_AFTER_REAL_PROOF"
        );
        let error = result.expect_err("JOINT_NATIVE_RUNNING_ORIGINAL_CANCELLATION");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            cancellation.authorize_commit().is_err(),
            "cancelled original cannot authorize commit"
        );
        conn.execute_batch("ROLLBACK")
            .expect("caller rolls back cancellation");
        assert_eq!(
            authority_digest(&conn),
            before,
            "JOINT_NATIVE_RUNNING_CANCEL_OUTER_ROLLBACK"
        );
        commit_component(&conn, &fixture, &prepared);
    }
    drop(prepared);
    close_reopen(fixture, record, proof).await;
}

#[tokio::test]
async fn joint_native_running_component_selected_history_is_validated_before_writes() {
    let fixture = fixture().await;
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = prepared_for_store(&pool, fixture.identity, &fixture.key).await;
    let (record, proof) = expected(&prepared);
    {
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let original: Vec<u8> = conn
            .query_row(
                "SELECT state_hmac FROM config_raft_history_retention",
                [],
                |row| row.get(0),
            )
            .expect("real history authenticator");
        conn.execute(
            "UPDATE config_raft_history_retention SET state_hmac = zeroblob(32)",
            [],
        )
        .expect("malformed retained state");
        let tampered = authority_digest(&conn);
        let writes = observe_writes(&conn, None);
        conn.execute_batch("BEGIN IMMEDIATE; SAVEPOINT audited_target_effect")
            .expect("authority savepoint");
        let cancellation = SqliteWorkCancellation::new();
        let result = apply_target_running_with_authority_sync(
            &conn,
            &fixture.key,
            prepared.command(),
            None,
            &context(&cancellation),
            Some(&authority(&fixture)),
        );
        clear_observation(&conn);
        conn.execute_batch("ROLLBACK").expect("caller rollback");
        assert!(
            result.is_err(),
            "corrupt retained state remains an I/O refusal"
        );
        assert_eq!(
            counts(&writes),
            [0, 0],
            "JOINT_NATIVE_RUNNING_HISTORY_BEFORE_MUTATION"
        );
        assert_eq!(
            authority_digest(&conn),
            tampered,
            "no apparent repair or overwrite"
        );
        conn.execute(
            "UPDATE config_raft_history_retention SET state_hmac = ?1",
            [original],
        )
        .expect("restore exact fixture bytes");
        commit_component(&conn, &fixture, &prepared);
    }
    drop(prepared);
    close_reopen(fixture, record, proof).await;
}
