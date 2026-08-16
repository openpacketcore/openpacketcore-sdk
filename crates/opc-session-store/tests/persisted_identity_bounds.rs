use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use opc_session_store::{
    EncryptedSessionPayload, Generation, OwnerId, ReplicationEntry, ReplicationOp, SessionBackend,
    SessionKey, SessionKeyType, SessionLeaseManager, SqliteSessionBackend, StateClass, StateType,
    StoreError, StoredSessionRecord, OWNER_ID_MAX_BYTES, SESSION_KEY_TYPE_MAX_BYTES,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use rusqlite::{params, types::Value, Connection};
use serde_json::Value as JsonValue;
use tempfile::TempDir;

const TENANT: &str = "tenant-persistence-test";
const NF_KIND: &str = "smf";
const VALID_CUSTOM_KEY_TYPE: &str = "legacy-custom-session";
const VALID_OWNER: &str = "legacy-owner";
const FUTURE_GUARD_EXPIRY: &str = "2999-01-01T00:00:00.000000000Z";
const FUTURE_GUARD_EXPIRY_UNIX_MS: i64 = 32_471_137_600_000;

#[derive(Debug, PartialEq)]
struct DatabaseSnapshot {
    session_records: Vec<Vec<Value>>,
    leases: Vec<Vec<Value>>,
    key_fences: Vec<Vec<Value>>,
    lease_globals: Vec<Vec<Value>>,
    replication_log: Vec<Vec<Value>>,
}

struct InitializedDatabase {
    _directory: TempDir,
    path: PathBuf,
}

impl InitializedDatabase {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn initialized_database() -> InitializedDatabase {
    let directory = tempfile::tempdir().expect("temporary SQLite directory");
    let path = directory.path().join("session.sqlite");
    let backend = SqliteSessionBackend::open(&path).expect("initialize SQLite schema");
    drop(backend);
    InitializedDatabase {
        _directory: directory,
        path,
    }
}

fn query_values(connection: &Connection, sql: &str) -> Vec<Vec<Value>> {
    let mut statement = connection.prepare(sql).expect("prepare snapshot query");
    let column_count = statement.column_count();
    statement
        .query_map([], |row| {
            (0..column_count)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })
        .expect("query snapshot rows")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("decode snapshot rows")
}

fn snapshot(path: &Path) -> DatabaseSnapshot {
    let connection = Connection::open(path).expect("open SQLite snapshot connection");
    DatabaseSnapshot {
        session_records: query_values(
            &connection,
            "SELECT tenant, nf_kind, key_type, stable_id, generation, owner, fence, \
                    state_class, state_type, expires_at, payload, encoding \
             FROM session_records \
             ORDER BY tenant, nf_kind, key_type, stable_id",
        ),
        leases: query_values(
            &connection,
            "SELECT tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, \
                    expires_at_unix_ms, guard_expires_at \
             FROM leases \
             ORDER BY tenant, nf_kind, key_type, stable_id",
        ),
        key_fences: query_values(
            &connection,
            "SELECT tenant, nf_kind, key_type, stable_id, fence \
             FROM key_fences \
             ORDER BY tenant, nf_kind, key_type, stable_id",
        ),
        lease_globals: query_values(
            &connection,
            "SELECT key, val FROM lease_globals ORDER BY key",
        ),
        replication_log: query_values(
            &connection,
            "SELECT sequence, tx_id, entry_json, timestamp \
             FROM session_replication_log \
             ORDER BY sequence",
        ),
    }
}

fn key(key_type: SessionKeyType, stable_id: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new(TENANT).expect("valid tenant"),
        nf_kind: NetworkFunctionKind::from_static(NF_KIND),
        key_type,
        stable_id: Bytes::from_static(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

fn legacy_key(stable_id: &'static [u8]) -> SessionKey {
    key(
        SessionKeyType::other(VALID_CUSTOM_KEY_TYPE).expect("valid custom key type"),
        stable_id,
    )
}

fn invalid_owner() -> String {
    format!("HOSTILE_OWNER_{}", "o".repeat(OWNER_ID_MAX_BYTES))
}

fn invalid_key_type() -> String {
    format!(
        "HOSTILE_KEY_TYPE_{}",
        "k".repeat(SESSION_KEY_TYPE_MAX_BYTES)
    )
}

fn insert_raw_record(connection: &Connection, key_type: &str, stable_id: &[u8], owner: &str) {
    connection
        .execute(
            "INSERT INTO session_records (\
                 tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, \
                 state_type, expires_at, payload, encoding\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                TENANT,
                NF_KIND,
                key_type,
                stable_id,
                7_i64,
                owner,
                5_i64,
                "authoritative-session",
                "legacy-session-state",
                Option::<String>::None,
                b"legacy-payload".as_slice(),
                1_i64,
            ],
        )
        .expect("insert raw session record");
}

fn insert_unrelated_expired_record(connection: &Connection, stable_id: &[u8]) {
    insert_raw_record(connection, VALID_CUSTOM_KEY_TYPE, stable_id, VALID_OWNER);
    connection
        .execute(
            "UPDATE session_records SET expires_at = ?1 WHERE stable_id = ?2",
            params!["2000-01-01T00:00:00.000000000Z", stable_id],
        )
        .expect("expire unrelated raw record");
}

fn insert_raw_active_lease(connection: &Connection, session_key: &SessionKey, owner: &str) {
    connection
        .execute(
            "INSERT INTO leases (\
                 tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, \
                    expires_at_unix_ms, guard_expires_at\
             ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9)",
            params![
                session_key.tenant.as_str(),
                session_key.nf_kind.as_str(),
                session_key.key_type.as_str(),
                session_key.stable_id.as_ref(),
                41_i64,
                owner,
                29_i64,
                FUTURE_GUARD_EXPIRY_UNIX_MS,
                FUTURE_GUARD_EXPIRY,
            ],
        )
        .expect("insert raw active lease");
    connection
        .execute(
            "INSERT INTO key_fences (tenant, nf_kind, key_type, stable_id, fence) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session_key.tenant.as_str(),
                session_key.nf_kind.as_str(),
                session_key.key_type.as_str(),
                session_key.stable_id.as_ref(),
                29_i64,
            ],
        )
        .expect("insert raw key fence");
}

fn stored_record(
    session_key: SessionKey,
    owner: &OwnerId,
    fence: opc_session_store::FenceToken,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key: session_key,
        generation: Generation::new(1),
        owner: owner.clone(),
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("persistence-hostile-test").expect("valid state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"record-to-preserve"),
    }
}

fn nested_delete_entry(sequence: u64, session_key: SessionKey, owner: OwnerId) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: format!("persistence-test-tx-{sequence}")
            .try_into()
            .expect("valid transaction ID"),
        op: ReplicationOp::Batch {
            ops: vec![ReplicationOp::Batch {
                ops: vec![ReplicationOp::DeleteFenced {
                    key: session_key,
                    owner,
                    fence: opc_session_store::FenceToken::new(5),
                }],
            }],
        },
        timestamp: Timestamp::now_utc(),
    }
}

fn insert_raw_replication_json(connection: &Connection, sequence: u64, tx_id: &str, json: &str) {
    connection
        .execute(
            "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) \
             VALUES (?1, ?2, ?3, ?4)",
            params![sequence as i64, tx_id, json, "2026-01-01T00:00:00Z"],
        )
        .expect("insert raw replication log entry");
}

fn replace_json_string(value: &mut JsonValue, needle: &str, replacement: &str) -> usize {
    match value {
        JsonValue::String(current) if current == needle => {
            *current = replacement.to_string();
            1
        }
        JsonValue::Array(values) => values
            .iter_mut()
            .map(|value| replace_json_string(value, needle, replacement))
            .sum(),
        JsonValue::Object(values) => values
            .values_mut()
            .map(|value| replace_json_string(value, needle, replacement))
            .sum(),
        _ => 0,
    }
}

fn replace_json_field(value: &mut JsonValue, field: &str, replacement: &JsonValue) -> usize {
    match value {
        JsonValue::Object(values) => {
            let mut replaced = 0;
            if let Some(value) = values.get_mut(field) {
                *value = replacement.clone();
                replaced += 1;
            }
            replaced
                + values
                    .values_mut()
                    .map(|value| replace_json_field(value, field, replacement))
                    .sum::<usize>()
        }
        JsonValue::Array(values) => values
            .iter_mut()
            .map(|value| replace_json_field(value, field, replacement))
            .sum(),
        _ => 0,
    }
}

fn assert_redacted_serialization_error(
    error: StoreError,
    fixed_message: &str,
    forbidden_value: &str,
) {
    let StoreError::Serialization(message) = error else {
        panic!("expected serialization error, got {error:?}");
    };
    assert!(
        message == fixed_message,
        "unexpected serialization error: {message}"
    );
    assert!(
        !message.contains(forbidden_value),
        "serialization error exposed hostile persisted input"
    );
}

fn reopen_rejects_invalid_persisted_state(path: &Path) -> StoreError {
    match SqliteSessionBackend::open(path) {
        Ok(_) => panic!("invalid persisted state must reject during construction"),
        Err(error) => error,
    }
}

fn assert_reopen_rejects_invalid_lease_authority(path: &Path) {
    let Err(error) = SqliteSessionBackend::open(path) else {
        panic!("invalid persisted authority must reject at reopen");
    };
    assert_eq!(
        error,
        StoreError::Serialization("persisted session lease authority is invalid".to_string())
    );
}

#[tokio::test]
async fn incomplete_raw_legacy_record_and_log_reject_without_rewrite() {
    let file = initialized_database();
    let session_key = legacy_key(b"valid-legacy-row");
    let owner = OwnerId::new(VALID_OWNER).expect("valid owner");
    let entry = nested_delete_entry(1, session_key.clone(), owner.clone());
    entry.validate().expect("valid replication entry");

    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        insert_raw_record(
            &connection,
            VALID_CUSTOM_KEY_TYPE,
            session_key.stable_id.as_ref(),
            VALID_OWNER,
        );
        insert_raw_replication_json(
            &connection,
            entry.sequence,
            entry.tx_id.as_str(),
            &serde_json::to_string(&entry).expect("serialize legacy entry"),
        );
    }
    let before = snapshot(file.path());

    assert_eq!(
        reopen_rejects_invalid_persisted_state(file.path()),
        StoreError::Serialization("persisted standalone session state is invalid".to_string())
    );

    assert_eq!(snapshot(file.path()), before);
}

#[tokio::test]
async fn invalid_persisted_record_owner_is_redacted_and_read_only() {
    let file = initialized_database();
    let session_key = legacy_key(b"invalid-record-owner");
    let hostile_owner = invalid_owner();
    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        insert_raw_record(
            &connection,
            VALID_CUSTOM_KEY_TYPE,
            session_key.stable_id.as_ref(),
            &hostile_owner,
        );
        insert_unrelated_expired_record(&connection, b"expired-before-owner-error");
    }
    let before = snapshot(file.path());

    assert_redacted_serialization_error(
        reopen_rejects_invalid_persisted_state(file.path()),
        "persisted standalone session state is invalid",
        &hostile_owner,
    );
    assert_eq!(snapshot(file.path()), before);
}

#[tokio::test]
async fn invalid_persisted_record_key_type_is_redacted_and_read_only() {
    let file = initialized_database();
    let hostile_key_type = invalid_key_type();
    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        insert_raw_record(
            &connection,
            &hostile_key_type,
            b"invalid-record-key-type",
            VALID_OWNER,
        );
        insert_unrelated_expired_record(&connection, b"expired-before-key-error");
    }
    let before = snapshot(file.path());

    assert_redacted_serialization_error(
        reopen_rejects_invalid_persisted_state(file.path()),
        "persisted standalone session state is invalid",
        &hostile_key_type,
    );
    assert_eq!(snapshot(file.path()), before);
}

#[tokio::test]
async fn invalid_active_lease_owner_rejects_reopen_without_mutation() {
    let file = initialized_database();
    let session_key = legacy_key(b"invalid-acquire-owner");
    let hostile_owner = invalid_owner();
    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        insert_raw_active_lease(&connection, &session_key, &hostile_owner);
    }
    let before = snapshot(file.path());

    assert_reopen_rejects_invalid_lease_authority(file.path());
    assert_eq!(snapshot(file.path()), before);
}

#[tokio::test]
async fn invalid_active_lease_owner_rejects_renew_reopen_without_mutation() {
    let file = initialized_database();
    let session_key = legacy_key(b"invalid-renew-owner");
    let backend = SqliteSessionBackend::open(file.path()).expect("open SQLite backend");
    let _lease = backend
        .acquire(
            &session_key,
            OwnerId::new("renew-owner").expect("valid owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("acquire valid lease");
    drop(backend);

    let hostile_owner = invalid_owner();
    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        let changed = connection
            .execute(
                "UPDATE leases SET owner = ?1 \
                 WHERE tenant = ?2 AND nf_kind = ?3 AND key_type = ?4 AND stable_id = ?5",
                params![
                    hostile_owner,
                    session_key.tenant.as_str(),
                    session_key.nf_kind.as_str(),
                    session_key.key_type.as_str(),
                    session_key.stable_id.as_ref(),
                ],
            )
            .expect("corrupt persisted lease owner");
        assert_eq!(changed, 1);
    }
    let before = snapshot(file.path());

    assert_reopen_rejects_invalid_lease_authority(file.path());
    assert_eq!(snapshot(file.path()), before);
}

#[tokio::test]
async fn invalid_active_lease_owner_rejects_fenced_mutation_reopen_without_mutation() {
    let file = initialized_database();
    let session_key = legacy_key(b"invalid-mutation-owner");
    let owner = OwnerId::new("mutation-owner").expect("valid owner");
    let backend = SqliteSessionBackend::open(file.path()).expect("open SQLite backend");
    let lease = backend
        .acquire(&session_key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("acquire valid lease");
    let record = stored_record(session_key.clone(), &owner, lease.fence());
    backend
        .compare_and_set(opc_session_store::CompareAndSet {
            key: session_key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await
        .expect("seed record under valid lease");
    drop(backend);

    let hostile_owner = invalid_owner();
    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        let changed = connection
            .execute(
                "UPDATE leases SET owner = ?1 \
                 WHERE tenant = ?2 AND nf_kind = ?3 AND key_type = ?4 AND stable_id = ?5",
                params![
                    hostile_owner,
                    session_key.tenant.as_str(),
                    session_key.nf_kind.as_str(),
                    session_key.key_type.as_str(),
                    session_key.stable_id.as_ref(),
                ],
            )
            .expect("corrupt persisted lease owner");
        assert_eq!(changed, 1);
    }
    let before = snapshot(file.path());

    assert_reopen_rejects_invalid_lease_authority(file.path());
    assert_eq!(snapshot(file.path()), before);
}

#[tokio::test]
async fn invalid_key_fence_identity_rejects_reopen_without_mutation() {
    let file = initialized_database();
    let valid_key_type = "k".repeat(SESSION_KEY_TYPE_MAX_BYTES);
    let hostile_key_type = format!("{valid_key_type}k");
    let stable_id = b"key-fence-no-alias";
    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        connection
            .execute(
                "INSERT INTO key_fences (tenant, nf_kind, key_type, stable_id, fence) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    TENANT,
                    NF_KIND,
                    hostile_key_type,
                    stable_id.as_slice(),
                    777_i64
                ],
            )
            .expect("insert inaccessible key fence identity");
    }

    assert_eq!(
        SessionKeyType::other(hostile_key_type.clone()),
        Err("custom session key type must be at most 128 bytes".to_string())
    );
    let before = snapshot(file.path());
    assert_reopen_rejects_invalid_lease_authority(file.path());
    assert_eq!(snapshot(file.path()), before);
}

#[tokio::test]
async fn invalid_nested_replication_log_owner_is_redacted_and_read_only() {
    let file = initialized_database();
    let valid_owner = OwnerId::new("nested-log-owner").expect("valid owner");
    let entry = nested_delete_entry(1, legacy_key(b"nested-invalid-owner"), valid_owner.clone());
    let hostile_owner = invalid_owner();
    let mut json = serde_json::to_value(&entry).expect("serialize replication entry");
    assert_eq!(
        replace_json_string(&mut json, valid_owner.as_str(), &hostile_owner),
        1
    );
    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        insert_raw_replication_json(
            &connection,
            entry.sequence,
            entry.tx_id.as_str(),
            &serde_json::to_string(&json).expect("serialize hostile entry"),
        );
    }
    let before = snapshot(file.path());

    assert_redacted_serialization_error(
        reopen_rejects_invalid_persisted_state(file.path()),
        "persisted standalone session state is invalid",
        &hostile_owner,
    );
    assert_eq!(snapshot(file.path()), before);
}

#[tokio::test]
async fn invalid_nested_replication_log_key_type_is_redacted_and_read_only() {
    let file = initialized_database();
    let entry = nested_delete_entry(
        1,
        legacy_key(b"nested-invalid-key-type"),
        OwnerId::new("nested-key-type-owner").expect("valid owner"),
    );
    let hostile_key_type = invalid_key_type();
    let mut json = serde_json::to_value(&entry).expect("serialize replication entry");
    assert_eq!(
        replace_json_string(&mut json, VALID_CUSTOM_KEY_TYPE, &hostile_key_type),
        1
    );
    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        insert_raw_replication_json(
            &connection,
            entry.sequence,
            entry.tx_id.as_str(),
            &serde_json::to_string(&json).expect("serialize hostile entry"),
        );
    }
    let before = snapshot(file.path());

    assert_redacted_serialization_error(
        reopen_rejects_invalid_persisted_state(file.path()),
        "persisted standalone session state is invalid",
        &hostile_key_type,
    );
    assert_eq!(snapshot(file.path()), before);
}

#[tokio::test]
async fn invalid_nested_replication_log_stable_id_is_redacted_and_read_only() {
    let file = initialized_database();
    let entry = nested_delete_entry(
        1,
        legacy_key(b"nested-invalid-stable-id"),
        OwnerId::new("nested-stable-id-owner").expect("valid owner"),
    );
    let mut json = serde_json::to_value(&entry).expect("serialize replication entry");
    assert!(
        replace_json_field(
            &mut json,
            "stable_id",
            &serde_json::json!(vec![0x5a_u8; opc_session_store::STABLE_ID_MAX_BYTES + 1]),
        ) > 0
    );
    {
        let connection = Connection::open(file.path()).expect("open raw SQLite connection");
        insert_raw_replication_json(
            &connection,
            entry.sequence,
            entry.tx_id.as_str(),
            &serde_json::to_string(&json).expect("serialize hostile entry"),
        );
    }
    let before = snapshot(file.path());

    assert_redacted_serialization_error(
        reopen_rejects_invalid_persisted_state(file.path()),
        "persisted standalone session state is invalid",
        "[90,90,90",
    );
    assert_eq!(snapshot(file.path()), before);
}
