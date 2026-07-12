use bytes::Bytes;
use opc_key::Zeroizing;
use opc_types::Timestamp;
use rand::{rngs::SysRng, TryRng};
use rusqlite::{named_params, params, types::ValueRef, Connection, OptionalExtension, Row};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::{
    backend::{CompareAndSet, CompareAndSetResult},
    capability::BackendCapabilities,
    error::StoreError,
    lease::LeaseGuard,
    model::{
        FenceToken, Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType,
        OWNER_ID_MAX_BYTES, SESSION_KEY_TYPE_MAX_BYTES, STATE_TYPE_MAX_BYTES,
    },
    record::{EncryptedSessionPayload, SessionPayloadEncoding, StoredSessionRecord},
    restore::{
        restore_record_retained_bytes_from_lengths, RestoreScanCursor, RestoreScanPage,
        RestoreScanRequest, RestoreScanScope, RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES,
        RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE, RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES,
        RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES, RESTORE_SCAN_MAX_SQLITE_VM_STEPS,
        RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS,
    },
    ttl::checked_session_deadline,
};

const RESTORE_SCAN_SQLITE_PROGRESS_INTERVAL: i32 = 1_000;
const RESTORE_SCAN_TENANT_MAX_BYTES: usize = 128;
const RESTORE_SCAN_NF_KIND_MAX_BYTES: usize = 64;
type RestoreScanState = ([u8; 16], u64, Zeroizing<[u8; 32]>);

const RESTORE_SCAN_FIRST_PAGE_SQL: &str = r#"
    SELECT tenant, nf_kind, key_type, stable_id, generation, owner, fence,
           state_class, state_type, expires_at, length(payload), encoding
    FROM session_records
    WHERE expires_at IS NULL OR expires_at > :snapshot_time
    ORDER BY tenant ASC, nf_kind ASC, key_type ASC, stable_id ASC
    LIMIT :query_limit
"#;

const RESTORE_SCAN_SEEK_PAGE_SQL: &str = r#"
    SELECT tenant, nf_kind, key_type, stable_id, generation, owner, fence,
           state_class, state_type, expires_at, length(payload), encoding
    FROM session_records
    WHERE (tenant, nf_kind, key_type, stable_id)
              > (:seek_tenant, :seek_nf_kind, :seek_key_type, :seek_stable_id)
      AND (expires_at IS NULL OR expires_at > :snapshot_time)
    ORDER BY tenant ASC, nf_kind ASC, key_type ASC, stable_id ASC
    LIMIT :query_limit
"#;

const RESTORE_SCAN_PAYLOAD_SQL: &str = r#"
    SELECT payload
    FROM session_records
    WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
"#;

struct RestoreScanProgressGuard<'a>(&'a Connection);

impl Drop for RestoreScanProgressGuard<'_> {
    fn drop(&mut self) {
        self.0.progress_handler(0, None::<fn() -> bool>);
    }
}

fn restore_scan_sqlite_error(error: rusqlite::Error) -> StoreError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::OperationInterrupted =>
        {
            StoreError::RestoreScanWorkBudgetExceeded
        }
        _ => StoreError::BackendUnavailable("session restore scan failed".into()),
    }
}

fn restore_scan_callback_limit_reached(previous_callbacks: usize, max_callbacks: usize) -> bool {
    previous_callbacks.saturating_add(1) >= max_callbacks
}

fn install_restore_scan_progress_budget(
    conn: &Connection,
    cancellation: Arc<AtomicBool>,
    operation_deadline: std::time::Instant,
) -> RestoreScanProgressGuard<'_> {
    let callbacks = Arc::new(AtomicUsize::new(0));
    let callback_count = Arc::clone(&callbacks);
    let started = std::time::Instant::now();
    // The configured interval is a small positive compile-time constant.
    let progress_interval = RESTORE_SCAN_SQLITE_PROGRESS_INTERVAL as usize;
    let max_callbacks = (RESTORE_SCAN_MAX_SQLITE_VM_STEPS / progress_interval).max(1);
    let sqlite_deadline = started
        .checked_add(Duration::from_millis(RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS))
        .map_or(operation_deadline, |deadline| {
            deadline.min(operation_deadline)
        });
    conn.progress_handler(
        RESTORE_SCAN_SQLITE_PROGRESS_INTERVAL,
        Some(move || {
            cancellation.load(Ordering::Acquire)
                || restore_scan_callback_limit_reached(
                    callback_count.fetch_add(1, Ordering::Relaxed),
                    max_callbacks,
                )
                || std::time::Instant::now() >= sqlite_deadline
        }),
    );
    RestoreScanProgressGuard(conn)
}

pub(crate) fn persisted_owner_id(value: String) -> Result<OwnerId, StoreError> {
    OwnerId::new(value)
        .map_err(|_| StoreError::Serialization("persisted session owner is invalid".to_string()))
}

pub(crate) fn persisted_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value)
        .map_err(|_| StoreError::Serialization("persisted session integer is negative".to_string()))
}

pub(crate) fn sqlite_u64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::Serialization("session integer exceeds SQLite range".to_string()))
}

pub(crate) fn timestamp_unix_millis(value: Timestamp) -> Result<i64, StoreError> {
    let millis = value.as_offset_datetime().unix_timestamp_nanos() / 1_000_000;
    i64::try_from(millis).map_err(|_| {
        StoreError::Serialization("session timestamp exceeds SQLite range".to_string())
    })
}

pub(crate) fn format_rfc3339_normalized(ts: Timestamp) -> String {
    let odt = ts.as_offset_datetime();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        odt.year(),
        odt.month() as u8,
        odt.day(),
        odt.hour(),
        odt.minute(),
        odt.second(),
        odt.nanosecond()
    )
}

pub(crate) fn initialize_restore_scan_metadata_sync(conn: &Connection) -> Result<(), StoreError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    let has_cursor_key = {
        let mut stmt = tx
            .prepare("PRAGMA table_info(restore_scan_state)")
            .map_err(|_| {
                StoreError::BackendUnavailable("session restore metadata failed".into())
            })?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|_| {
                StoreError::BackendUnavailable("session restore metadata failed".into())
            })?;
        let mut found = false;
        for column in columns {
            if column.map_err(|_| {
                StoreError::BackendUnavailable("session restore metadata failed".into())
            })? == "cursor_key"
            {
                found = true;
            }
        }
        found
    };
    if !has_cursor_key {
        tx.execute(
            "ALTER TABLE restore_scan_state ADD COLUMN cursor_key BLOB CHECK (cursor_key IS NULL OR length(cursor_key) = 32)",
            [],
        )
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    }

    let mut cursor_key = Zeroizing::new([0_u8; 32]);
    SysRng
        .try_fill_bytes(cursor_key.as_mut())
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    let restore_epoch = *uuid::Uuid::new_v4().as_bytes();
    tx.execute(
        "INSERT OR IGNORE INTO restore_scan_state (singleton, epoch, revision, cursor_key) VALUES (1, ?1, 0, ?2)",
        params![restore_epoch.as_slice(), cursor_key.as_slice()],
    )
    .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    tx.execute(
        "UPDATE restore_scan_state SET cursor_key = ?1 WHERE singleton = 1 AND cursor_key IS NULL",
        [cursor_key.as_slice()],
    )
    .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    read_restore_scan_state_sync(&tx)?;
    tx.commit()
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))
}

pub(crate) fn read_restore_scan_state_sync(
    conn: &Connection,
) -> Result<RestoreScanState, StoreError> {
    let (epoch, revision, cursor_key) = conn
        .query_row(
            "SELECT epoch, revision, cursor_key FROM restore_scan_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    let epoch = epoch.try_into().map_err(|_| {
        StoreError::Serialization("session restore metadata is invalid".to_string())
    })?;
    let revision = persisted_u64(revision)?;
    let cursor_key = Zeroizing::new(cursor_key);
    let cursor_key: Zeroizing<[u8; 32]> =
        Zeroizing::new(cursor_key.as_slice().try_into().map_err(|_| {
            StoreError::Serialization("session restore metadata is invalid".to_string())
        })?);
    if epoch == [0; 16] || *cursor_key == [0; 32] {
        return Err(StoreError::Serialization(
            "session restore metadata is invalid".to_string(),
        ));
    }
    Ok((epoch, revision, cursor_key))
}

pub(crate) fn advance_restore_scan_revision_sync(conn: &Connection) -> Result<(), StoreError> {
    let (_, revision, _) = read_restore_scan_state_sync(conn)?;
    let next = revision.checked_add(1).ok_or_else(|| {
        StoreError::BackendUnavailable("session restore metadata exhausted".into())
    })?;
    let changed = conn
        .execute(
            "UPDATE restore_scan_state SET revision = ?1 WHERE singleton = 1 AND revision = ?2",
            params![sqlite_u64(next)?, sqlite_u64(revision)?],
        )
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    if changed != 1 {
        return Err(StoreError::BackendUnavailable(
            "session restore metadata failed".into(),
        ));
    }
    Ok(())
}

pub(crate) fn rotate_restore_scan_epoch_sync(conn: &Connection) -> Result<(), StoreError> {
    let epoch = *uuid::Uuid::new_v4().as_bytes();
    let changed = conn
        .execute(
            "UPDATE restore_scan_state SET epoch = ?1, revision = revision + 1 WHERE singleton = 1 AND revision < ?2",
            params![epoch.as_slice(), i64::MAX],
        )
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    if changed != 1 {
        return Err(StoreError::BackendUnavailable(
            "session restore metadata exhausted".into(),
        ));
    }
    Ok(())
}

pub(crate) fn rotate_restore_scan_incarnation_sync(conn: &Connection) -> Result<(), StoreError> {
    let epoch = *uuid::Uuid::new_v4().as_bytes();
    let mut cursor_key = Zeroizing::new([0_u8; 32]);
    SysRng
        .try_fill_bytes(cursor_key.as_mut())
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    let changed = conn
        .execute(
            "UPDATE restore_scan_state SET epoch = ?1, cursor_key = ?2, revision = revision + 1 WHERE singleton = 1 AND revision < ?3",
            params![epoch.as_slice(), cursor_key.as_slice(), i64::MAX],
        )
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
    if changed != 1 {
        return Err(StoreError::BackendUnavailable(
            "session restore metadata exhausted".into(),
        ));
    }
    Ok(())
}

pub(crate) fn prune_sync(conn: &Connection, now: Timestamp) -> Result<(), StoreError> {
    let now_str = format_rfc3339_normalized(now);
    // 1. Delete expired session records
    let removed_records = conn
        .execute(
            "DELETE FROM session_records WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now_str],
        )
        .map_err(restore_scan_sqlite_error)?;
    if removed_records > 0 {
        advance_restore_scan_revision_sync(conn)?;
    }

    // 2. Delete expired or released leases
    conn.execute(
        "DELETE FROM leases WHERE active = 0 OR guard_expires_at <= ?1",
        params![now_str],
    )
    .map_err(restore_scan_sqlite_error)?;

    Ok(())
}

pub(crate) fn validate_fenced_mutation_sync(
    conn: &Connection,
    lease: &LeaseGuard,
    now: Timestamp,
) -> Result<(), StoreError> {
    if lease.expires_at() <= now {
        return Err(StoreError::LeaseExpired);
    }

    let mut stmt = conn
        .prepare(
            r#"
            SELECT active, credential_id, owner, fence, guard_expires_at
            FROM leases
            WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
            "#,
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    let row = stmt
        .query_row(
            params![
                lease.key().tenant.as_str(),
                lease.key().nf_kind.as_str(),
                lease.key().key_type.to_string(),
                lease.key().stable_id.as_ref(),
            ],
            |row| {
                Ok((
                    row.get::<_, i32>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    let Some((active, credential_id, owner_str, fence, guard_expires_at_str)) = row else {
        return Err(StoreError::StaleFence);
    };

    if active == 0 {
        return Err(StoreError::StaleFence);
    }

    if persisted_u64(credential_id)? != lease.credential_id() {
        return Err(StoreError::StaleFence);
    }

    if persisted_owner_id(owner_str)? != *lease.owner() {
        return Err(StoreError::StaleFence);
    }

    if persisted_u64(fence)? != lease.fence().get() {
        return Err(StoreError::StaleFence);
    }

    let guard_expires_at = opc_types::Timestamp::from_str(guard_expires_at_str.as_str())
        .map_err(|e| StoreError::Serialization(e.to_string()))?;

    if guard_expires_at != lease.expires_at() {
        return Err(StoreError::StaleFence);
    }

    if lease.expires_at() <= now {
        return Err(StoreError::LeaseExpired);
    }

    if guard_expires_at <= now {
        return Err(StoreError::LeaseExpired);
    }

    Ok(())
}

pub(crate) fn current_fence_sync(conn: &Connection, key: &SessionKey) -> Result<u64, StoreError> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT fence
            FROM key_fences
            WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
            "#,
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    let row = stmt
        .query_row(
            params![
                key.tenant.as_str(),
                key.nf_kind.as_str(),
                key.key_type.to_string(),
                key.stable_id.as_ref(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    row.map(persisted_u64)
        .transpose()
        .map(Option::unwrap_or_default)
}

pub(crate) fn get_sync(
    conn: &Connection,
    key: &SessionKey,
    now: Timestamp,
) -> Result<Option<StoredSessionRecord>, StoreError> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT generation, owner, fence, state_class, state_type, expires_at, payload, encoding
            FROM session_records
            WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
            "#,
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    let row = stmt
        .query_row(
            params![
                key.tenant.as_str(),
                key.nf_kind.as_str(),
                key.key_type.to_string(),
                key.stable_id.as_ref(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    let Some((
        generation,
        owner_str,
        fence,
        state_class_str,
        state_type_str,
        expires_at_str,
        payload_bytes,
        encoding,
    )) = row
    else {
        return Ok(None);
    };

    let owner = persisted_owner_id(owner_str)?;
    let state_class = match state_class_str.as_str() {
        "authoritative-session" => StateClass::AuthoritativeSession,
        "dataplane-lookup" => StateClass::DataplaneLookup,
        "replicated-dr" => StateClass::ReplicatedDr,
        "telemetry-derived" => StateClass::TelemetryDerived,
        "ephemeral-procedure" => StateClass::EphemeralProcedure,
        _ => {
            return Err(StoreError::Serialization(format!(
                "unknown state class: {state_class_str}"
            )))
        }
    };
    let state_type = StateType::new(state_type_str).map_err(StoreError::Serialization)?;
    let expires_at = match &expires_at_str {
        Some(s) => Some(
            opc_types::Timestamp::from_str(s.as_str())
                .map_err(|e| StoreError::Serialization(e.to_string()))?,
        ),
        None => None,
    };
    let payload = match encoding {
        0 => EncryptedSessionPayload::try_from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::Plaintext,
        )?,
        1 => EncryptedSessionPayload::try_from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::LegacyPlaintext,
        )?,
        2 => EncryptedSessionPayload::try_from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::EnvelopeV1,
        )?,
        3 => EncryptedSessionPayload::try_from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::Unclassified,
        )?,
        _ => {
            return Err(StoreError::Serialization(format!(
                "unknown payload encoding: {encoding}"
            )))
        }
    };

    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(persisted_u64(generation)?),
        owner,
        fence: FenceToken::new(persisted_u64(fence)?),
        state_class,
        state_type,
        expires_at,
        payload,
    };

    let result = if record.is_expired_at(now) {
        None
    } else {
        Some(record)
    };
    Ok(result)
}

#[derive(Debug, Clone, Copy)]
struct RestoreScanRowBudget {
    examined_metadata_bytes: usize,
    retained_record_bytes: usize,
    payload_bytes: usize,
}

struct RestoreScanCandidate {
    key: SessionKey,
    generation: Generation,
    owner: OwnerId,
    fence: FenceToken,
    state_class: StateClass,
    state_type: StateType,
    expires_at: Option<Timestamp>,
    payload_bytes: usize,
    encoding: i64,
}

impl RestoreScanCandidate {
    fn from_row(row: &Row<'_>, budget: RestoreScanRowBudget) -> Result<Self, StoreError> {
        let tenant = restore_scan_text(row, 0)?;
        let nf_kind = restore_scan_text(row, 1)?;
        let key_type = restore_scan_text(row, 2)?;
        let stable_id = restore_scan_blob(row, 3)?;
        let owner = restore_scan_text(row, 5)?;
        let state_class = restore_scan_text(row, 7)?;
        let state_type = restore_scan_text(row, 8)?;
        let expires_at = match row.get_ref(9).map_err(|_| restore_scan_failed())? {
            ValueRef::Null => None,
            ValueRef::Text(value) => Some(
                Timestamp::from_str(std::str::from_utf8(value).map_err(|_| {
                    StoreError::Serialization("persisted session timestamp is invalid".into())
                })?)
                .map_err(|_| {
                    StoreError::Serialization("persisted session timestamp is invalid".into())
                })?,
            ),
            _ => {
                return Err(StoreError::Serialization(
                    "persisted session timestamp is invalid".into(),
                ))
            }
        };
        Ok(Self {
            key: SessionKey {
                tenant: opc_types::TenantId::new(tenant.to_owned()).map_err(|_| {
                    StoreError::Serialization("persisted session key is invalid".into())
                })?,
                nf_kind: opc_types::NetworkFunctionKind::new(nf_kind.to_owned()).map_err(|_| {
                    StoreError::Serialization("persisted session key is invalid".into())
                })?,
                key_type: SessionKeyType::from_str(key_type).map_err(StoreError::Serialization)?,
                stable_id: Bytes::copy_from_slice(stable_id),
            },
            generation: Generation::new(persisted_u64(restore_scan_integer(row, 4)?)?),
            owner: persisted_owner_id(owner.to_owned())?,
            fence: FenceToken::new(persisted_u64(restore_scan_integer(row, 6)?)?),
            state_class: state_class_from_str(state_class)?,
            state_type: StateType::new(state_type.to_owned()).map_err(StoreError::Serialization)?,
            expires_at,
            payload_bytes: budget.payload_bytes,
            encoding: restore_scan_integer(row, 11)?,
        })
    }

    fn matches_scope(&self, scope: &RestoreScanScope) -> bool {
        scope
            .tenant
            .as_ref()
            .is_none_or(|value| value == &self.key.tenant)
            && scope
                .nf_kind
                .as_ref()
                .is_none_or(|value| value == &self.key.nf_kind)
            && scope
                .key_type
                .as_ref()
                .is_none_or(|value| value == &self.key.key_type)
            && scope
                .state_class
                .is_none_or(|value| value == self.state_class)
            && scope
                .state_type
                .as_ref()
                .is_none_or(|value| value == &self.state_type)
            && scope
                .owner
                .as_ref()
                .is_none_or(|value| value == &self.owner)
    }

    fn load_record(self, conn: &Connection) -> Result<StoredSessionRecord, StoreError> {
        let payload = conn
            .query_row(
                RESTORE_SCAN_PAYLOAD_SQL,
                params![
                    self.key.tenant.as_str(),
                    self.key.nf_kind.as_str(),
                    self.key.key_type.as_str(),
                    self.key.stable_id.as_ref(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(restore_scan_sqlite_error)?;
        if payload.len() != self.payload_bytes {
            return Err(StoreError::BackendUnavailable(
                "session restore scan failed".into(),
            ));
        }
        Ok(StoredSessionRecord {
            key: self.key,
            generation: self.generation,
            owner: self.owner,
            fence: self.fence,
            state_class: self.state_class,
            state_type: self.state_type,
            expires_at: self.expires_at,
            payload: payload_from_row(payload, self.encoding)?,
        })
    }
}

fn restore_scan_failed() -> StoreError {
    StoreError::BackendUnavailable("session restore scan failed".into())
}

fn restore_scan_text<'row>(row: &'row Row<'_>, index: usize) -> Result<&'row str, StoreError> {
    match row.get_ref(index).map_err(|_| restore_scan_failed())? {
        ValueRef::Text(value) => std::str::from_utf8(value)
            .map_err(|_| StoreError::Serialization("persisted session text is invalid".into())),
        _ => Err(StoreError::Serialization(
            "persisted session text is invalid".into(),
        )),
    }
}

fn restore_scan_blob<'row>(row: &'row Row<'_>, index: usize) -> Result<&'row [u8], StoreError> {
    match row.get_ref(index).map_err(|_| restore_scan_failed())? {
        ValueRef::Blob(value) => Ok(value),
        _ => Err(StoreError::Serialization(
            "persisted session blob is invalid".into(),
        )),
    }
}

fn restore_scan_integer(row: &Row<'_>, index: usize) -> Result<i64, StoreError> {
    match row.get_ref(index).map_err(|_| restore_scan_failed())? {
        ValueRef::Integer(value) => Ok(value),
        _ => Err(StoreError::Serialization(
            "persisted session integer is invalid".into(),
        )),
    }
}

fn restore_scan_row_budget(row: &Row<'_>) -> Result<RestoreScanRowBudget, StoreError> {
    let tenant = restore_scan_text(row, 0)?;
    let nf_kind = restore_scan_text(row, 1)?;
    let key_type = restore_scan_text(row, 2)?;
    let stable_id = restore_scan_blob(row, 3)?;
    let owner = restore_scan_text(row, 5)?;
    let state_class = restore_scan_text(row, 7)?;
    let state_type = restore_scan_text(row, 8)?;
    let expires_at_bytes = match row.get_ref(9).map_err(|_| restore_scan_failed())? {
        ValueRef::Null => 0,
        ValueRef::Text(value) => value.len(),
        _ => {
            return Err(StoreError::Serialization(
                "persisted session timestamp is invalid".into(),
            ))
        }
    };
    let payload_bytes = usize::try_from(restore_scan_integer(row, 10)?).map_err(|_| {
        StoreError::Serialization("session restore payload length is invalid".into())
    })?;
    if key_type.len() > SESSION_KEY_TYPE_MAX_BYTES {
        return Err(StoreError::Serialization(
            "custom session key type must be at most 128 bytes".into(),
        ));
    }
    if tenant.len() > RESTORE_SCAN_TENANT_MAX_BYTES
        || nf_kind.len() > RESTORE_SCAN_NF_KIND_MAX_BYTES
        || stable_id.len() > crate::SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES
        || owner.len() > OWNER_ID_MAX_BYTES
        || state_type.len() > STATE_TYPE_MAX_BYTES
    {
        return Err(StoreError::RestoreScanWorkBudgetExceeded);
    }
    // Validate fixed-width and enum fields before any row-owned allocation.
    let _ = persisted_u64(restore_scan_integer(row, 4)?)?;
    let _ = persisted_u64(restore_scan_integer(row, 6)?)?;
    let _ = state_class_from_str(state_class)?;
    let _ = restore_scan_integer(row, 11)?;

    let examined_metadata_bytes = [
        std::mem::size_of::<RestoreScanCandidate>(),
        tenant.len(),
        nf_kind.len(),
        key_type.len(),
        stable_id.len(),
        owner.len(),
        state_class.len(),
        state_type.len(),
        expires_at_bytes,
    ]
    .into_iter()
    .try_fold(0_usize, |total, bytes| total.checked_add(bytes))
    .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
    if examined_metadata_bytes > RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES {
        return Err(StoreError::RestoreScanWorkBudgetExceeded);
    }
    let retained_record_bytes = restore_record_retained_bytes_from_lengths(
        tenant.len(),
        nf_kind.len(),
        key_type.len(),
        stable_id.len(),
        owner.len(),
        state_type.len(),
        payload_bytes,
    )?;
    Ok(RestoreScanRowBudget {
        examined_metadata_bytes,
        retained_record_bytes,
        payload_bytes,
    })
}

pub(crate) fn scan_restore_records_sync(
    conn: &Connection,
    request: RestoreScanRequest,
    now: Timestamp,
    cancellation: Arc<AtomicBool>,
    operation_deadline: std::time::Instant,
    prune_expired: bool,
) -> Result<RestoreScanPage, StoreError> {
    request.validate()?;
    let _progress_guard =
        install_restore_scan_progress_budget(conn, Arc::clone(&cancellation), operation_deadline);
    if cancellation.load(Ordering::Acquire) {
        return Err(StoreError::RestoreScanWorkBudgetExceeded);
    }
    if prune_expired {
        prune_sync(conn, now)?;
    }
    let (backend_epoch, snapshot_revision, cursor_key) = read_restore_scan_state_sync(conn)?;
    let (seek_key, examined_position, snapshot_time) = match request.cursor {
        Some(cursor) => {
            let (cursor_epoch, cursor_revision, snapshot_time, seek_key, examined_position) =
                cursor.authenticated_parts(&request.scope, &cursor_key)?;
            if cursor_epoch != backend_epoch || cursor_revision != snapshot_revision {
                return Err(StoreError::RestoreScanCursorStale);
            }
            (Some(seek_key), examined_position, snapshot_time)
        }
        None => (None, 0_u64, now),
    };
    let query_limit = RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
    let snapshot_time_text = format_rfc3339_normalized(snapshot_time);
    let mut stmt = conn
        .prepare(if seek_key.is_some() {
            RESTORE_SCAN_SEEK_PAGE_SQL
        } else {
            RESTORE_SCAN_FIRST_PAGE_SQL
        })
        .map_err(restore_scan_sqlite_error)?;
    let mut rows = match seek_key.as_ref() {
        Some(seek_key) => stmt.query(named_params! {
            ":snapshot_time": snapshot_time_text,
            ":seek_tenant": seek_key.tenant.as_str(),
            ":seek_nf_kind": seek_key.nf_kind.as_str(),
            ":seek_key_type": seek_key.key_type.as_str(),
            ":seek_stable_id": seek_key.stable_id.as_ref(),
            ":query_limit": query_limit,
        }),
        None => stmt.query(named_params! {
            ":snapshot_time": snapshot_time_text,
            ":query_limit": query_limit,
        }),
    }
    .map_err(restore_scan_sqlite_error)?;

    let mut candidates = Vec::with_capacity(request.limit.min(64));
    let mut payload_bytes = 0_usize;
    let mut retained_page_bytes = std::mem::size_of::<RestoreScanPage>();
    let mut examined_metadata_bytes = 0_usize;
    let mut has_more = false;
    let mut excluded_count = 0_usize;
    let mut examined_count = 0_usize;
    let mut last_examined_key = None;
    loop {
        if examined_count == RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE {
            has_more = rows.next().map_err(restore_scan_sqlite_error)?.is_some();
            break;
        }
        let Some(row) = rows.next().map_err(restore_scan_sqlite_error)? else {
            break;
        };
        let row_budget = restore_scan_row_budget(row)?;
        let next_examined_metadata_bytes = examined_metadata_bytes
            .checked_add(row_budget.examined_metadata_bytes)
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
        if next_examined_metadata_bytes > RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES {
            if examined_count == 0 {
                return Err(StoreError::RestoreScanWorkBudgetExceeded);
            }
            has_more = true;
            break;
        }
        let candidate = RestoreScanCandidate::from_row(row, row_budget)?;
        let candidate_key = candidate.key.clone();
        let previous_candidates = candidates.len();
        let previous_examined_count = examined_count;
        let previous_excluded_count = excluded_count;
        let previous_last_examined_key = last_examined_key.clone();

        if candidate.matches_scope(&request.scope) {
            if row_budget.payload_bytes > RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES {
                if examined_count == 0 && candidates.is_empty() {
                    return Err(StoreError::RestoreScanResponseTooLarge {
                        max_bytes: RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES,
                    });
                }
                has_more = true;
                break;
            }
            let next_payload_bytes = payload_bytes
                .checked_add(row_budget.payload_bytes)
                .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            if next_payload_bytes > RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES {
                has_more = true;
                break;
            }
            let next_retained_page_bytes = retained_page_bytes
                .checked_add(row_budget.retained_record_bytes)
                .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            if next_retained_page_bytes > RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES {
                if examined_count == 0 && candidates.is_empty() {
                    return Err(StoreError::RestoreScanResponseTooLarge {
                        max_bytes: RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES,
                    });
                }
                has_more = true;
                break;
            }
            payload_bytes = next_payload_bytes;
            retained_page_bytes = next_retained_page_bytes;
            candidates.push(candidate);
        } else {
            excluded_count += 1;
        }
        examined_metadata_bytes = next_examined_metadata_bytes;
        examined_count += 1;
        last_examined_key = Some(candidate_key);

        let cursor_bytes = RestoreScanCursor::durable_retained_token_bytes_for_key(
            last_examined_key.as_ref().ok_or_else(restore_scan_failed)?,
        )?;
        if retained_page_bytes
            .checked_add(cursor_bytes)
            .is_none_or(|bytes| bytes > RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES)
        {
            let more_rows = rows.next().map_err(restore_scan_sqlite_error)?.is_some();
            if more_rows {
                candidates.truncate(previous_candidates);
                examined_count = previous_examined_count;
                excluded_count = previous_excluded_count;
                last_examined_key = previous_last_examined_key;
                if last_examined_key.is_none() {
                    return Err(StoreError::RestoreScanResponseTooLarge {
                        max_bytes: RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES,
                    });
                }
                has_more = true;
            }
            break;
        }

        if candidates.len() == request.limit
            || examined_count == RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE
        {
            has_more = rows.next().map_err(restore_scan_sqlite_error)?.is_some();
            break;
        }
    }

    drop(rows);
    drop(stmt);

    let mut records = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if cancellation.load(Ordering::Acquire) || std::time::Instant::now() >= operation_deadline {
            return Err(StoreError::RestoreScanWorkBudgetExceeded);
        }
        records.push(candidate.load_record(conn)?);
    }

    if cancellation.load(Ordering::Acquire) {
        return Err(StoreError::RestoreScanWorkBudgetExceeded);
    }

    let examined_count_u64 =
        u64::try_from(examined_count).map_err(|_| StoreError::RestoreScanWorkBudgetExceeded)?;
    let next_position = examined_position
        .checked_add(examined_count_u64)
        .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
    let next_cursor = if has_more {
        let last_examined_key = last_examined_key.ok_or_else(|| {
            StoreError::BackendUnavailable("session restore scan made no progress".into())
        })?;
        Some(RestoreScanCursor::durable(
            &cursor_key,
            backend_epoch,
            snapshot_revision,
            snapshot_time,
            &request.scope,
            &last_examined_key,
            next_position,
        )?)
    } else {
        None
    };
    records.sort_by(crate::restore::compare_restore_records);
    Ok(RestoreScanPage::new_durable(
        records,
        excluded_count,
        next_cursor,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn stored_record_from_row(
    tenant_str: String,
    nf_kind_str: String,
    key_type_str: String,
    stable_id: Vec<u8>,
    generation: i64,
    owner_str: String,
    fence: i64,
    state_class_str: String,
    state_type_str: String,
    expires_at_str: Option<String>,
    payload_bytes: Vec<u8>,
    encoding: i64,
) -> Result<StoredSessionRecord, StoreError> {
    let tenant = opc_types::TenantId::new(tenant_str)
        .map_err(|err| StoreError::Serialization(err.to_string()))?;
    let nf_kind = opc_types::NetworkFunctionKind::new(nf_kind_str)
        .map_err(|err| StoreError::Serialization(err.to_string()))?;
    let key_type =
        crate::SessionKeyType::from_str(&key_type_str).map_err(StoreError::Serialization)?;
    let owner = persisted_owner_id(owner_str)?;
    let state_class = state_class_from_str(&state_class_str)?;
    let state_type = StateType::new(state_type_str).map_err(StoreError::Serialization)?;
    let expires_at = match &expires_at_str {
        Some(s) => Some(
            opc_types::Timestamp::from_str(s.as_str())
                .map_err(|e| StoreError::Serialization(e.to_string()))?,
        ),
        None => None,
    };
    let payload = payload_from_row(payload_bytes, encoding)?;

    Ok(StoredSessionRecord {
        key: SessionKey {
            tenant,
            nf_kind,
            key_type,
            stable_id: Bytes::from(stable_id),
        },
        generation: Generation::new(persisted_u64(generation)?),
        owner,
        fence: FenceToken::new(persisted_u64(fence)?),
        state_class,
        state_type,
        expires_at,
        payload,
    })
}

fn state_class_from_str(value: &str) -> Result<StateClass, StoreError> {
    match value {
        "authoritative-session" => Ok(StateClass::AuthoritativeSession),
        "dataplane-lookup" => Ok(StateClass::DataplaneLookup),
        "replicated-dr" => Ok(StateClass::ReplicatedDr),
        "telemetry-derived" => Ok(StateClass::TelemetryDerived),
        "ephemeral-procedure" => Ok(StateClass::EphemeralProcedure),
        _ => Err(StoreError::Serialization(format!(
            "unknown state class: {value}"
        ))),
    }
}

fn payload_from_row(
    payload_bytes: Vec<u8>,
    encoding: i64,
) -> Result<EncryptedSessionPayload, StoreError> {
    match encoding {
        0 => EncryptedSessionPayload::try_from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::Plaintext,
        ),
        1 => EncryptedSessionPayload::try_from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::LegacyPlaintext,
        ),
        2 => EncryptedSessionPayload::try_from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::EnvelopeV1,
        ),
        3 => EncryptedSessionPayload::try_from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::Unclassified,
        ),
        _ => Err(StoreError::Serialization(format!(
            "unknown payload encoding: {encoding}"
        ))),
    }
}

pub(crate) fn insert_or_replace_record_sync(
    conn: &Connection,
    record: &StoredSessionRecord,
) -> Result<(), StoreError> {
    let expires_at_str = record.expires_at.map(format_rfc3339_normalized);
    let encoding_val = match record.payload.encoding() {
        SessionPayloadEncoding::Plaintext => 0,
        SessionPayloadEncoding::LegacyPlaintext => 1,
        SessionPayloadEncoding::EnvelopeV1 => 2,
        SessionPayloadEncoding::Unclassified => 3,
    };

    conn.execute(
        r#"
        INSERT INTO session_records (
            tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, state_type, expires_at, payload, encoding
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ON CONFLICT(tenant, nf_kind, key_type, stable_id) DO UPDATE SET
            generation = excluded.generation,
            owner = excluded.owner,
            fence = excluded.fence,
            state_class = excluded.state_class,
            state_type = excluded.state_type,
            expires_at = excluded.expires_at,
            payload = excluded.payload,
            encoding = excluded.encoding
        "#,
        params![
            record.key.tenant.as_str(),
            record.key.nf_kind.as_str(),
            record.key.key_type.to_string(),
            record.key.stable_id.as_ref(),
            sqlite_u64(record.generation.get())?,
            record.owner.as_str(),
            sqlite_u64(record.fence.get())?,
            record.state_class.to_string(),
            record.state_type.as_str(),
            expires_at_str,
            record.payload.as_bytes(),
            encoding_val,
        ],
    )
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    advance_restore_scan_revision_sync(conn)?;

    Ok(())
}

pub(crate) fn insert_or_replace_fence_sync(
    conn: &Connection,
    key: &SessionKey,
    fence: u64,
) -> Result<(), StoreError> {
    conn.execute(
        r#"
        INSERT OR REPLACE INTO key_fences (
            tenant, nf_kind, key_type, stable_id, fence
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            key.tenant.as_str(),
            key.nf_kind.as_str(),
            key.key_type.to_string(),
            key.stable_id.as_ref(),
            sqlite_u64(fence)?,
        ],
    )
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    Ok(())
}

pub(crate) fn compare_and_set_sync(
    conn: &Connection,
    op: CompareAndSet,
    caps: &BackendCapabilities,
    now: Timestamp,
) -> Result<CompareAndSetResult, StoreError> {
    prune_sync(conn, now)?;

    if !caps.atomic_compare_and_set {
        return Err(StoreError::CapabilityNotSupported(
            "atomic_compare_and_set".into(),
        ));
    }
    if !caps.monotonic_fencing_token {
        return Err(StoreError::CapabilityNotSupported(
            "monotonic_fencing_token".into(),
        ));
    }
    if op.lease.key() != &op.key {
        return Err(StoreError::InvalidKey(
            "compare-and-set key does not match lease key".into(),
        ));
    }
    if op.new_record.key != op.key {
        return Err(StoreError::InvalidKey(
            "compare-and-set key does not match record key".into(),
        ));
    }
    if op.new_record.owner != *op.lease.owner() || op.new_record.fence != op.lease.fence() {
        return Err(StoreError::StaleFence);
    }
    if op.new_record.payload.len() > caps.max_value_bytes {
        return Err(StoreError::PayloadTooLarge {
            actual: op.new_record.payload.len(),
            max: caps.max_value_bytes,
        });
    }

    validate_fenced_mutation_sync(conn, &op.lease, now)?;
    let current_fence = current_fence_sync(conn, &op.key)?;

    if op.lease.fence().get() < current_fence {
        return Err(StoreError::StaleFence);
    }

    let existing = get_sync(conn, &op.key, now)?;

    match (op.expected_generation, existing) {
        (None, None) => {
            insert_or_replace_record_sync(conn, &op.new_record)?;
            insert_or_replace_fence_sync(conn, &op.key, op.lease.fence().get())?;
            Ok(CompareAndSetResult::Success)
        }
        (Some(expected), Some(current)) => {
            if current.generation != expected {
                return Ok(CompareAndSetResult::Conflict {
                    current: Some(current),
                });
            }
            if (current.state_class.requires_monotonic_generation()
                || op.new_record.state_class.requires_monotonic_generation())
                && op.new_record.generation <= current.generation
            {
                return Ok(CompareAndSetResult::Conflict {
                    current: Some(current),
                });
            }
            insert_or_replace_record_sync(conn, &op.new_record)?;
            insert_or_replace_fence_sync(conn, &op.key, op.lease.fence().get())?;
            Ok(CompareAndSetResult::Success)
        }
        (None, Some(current)) => Ok(CompareAndSetResult::Conflict {
            current: Some(current),
        }),
        (Some(_), None) => Ok(CompareAndSetResult::Conflict { current: None }),
    }
}

pub(crate) fn delete_fenced_sync(
    conn: &Connection,
    lease: &LeaseGuard,
    caps: &BackendCapabilities,
    now: Timestamp,
) -> Result<(), StoreError> {
    prune_sync(conn, now)?;

    if !caps.monotonic_fencing_token {
        return Err(StoreError::CapabilityNotSupported(
            "monotonic_fencing_token".into(),
        ));
    }

    validate_fenced_mutation_sync(conn, lease, now)?;
    let current_fence = current_fence_sync(conn, lease.key())?;

    if lease.fence().get() < current_fence {
        return Err(StoreError::StaleFence);
    }

    let removed = conn
        .execute(
            r#"
        DELETE FROM session_records
        WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
        "#,
            params![
                lease.key().tenant.as_str(),
                lease.key().nf_kind.as_str(),
                lease.key().key_type.to_string(),
                lease.key().stable_id.as_ref(),
            ],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    if removed > 0 {
        advance_restore_scan_revision_sync(conn)?;
    }

    insert_or_replace_fence_sync(conn, lease.key(), lease.fence().get())?;

    Ok(())
}

pub(crate) fn refresh_ttl_sync(
    conn: &Connection,
    lease: &LeaseGuard,
    ttl: Duration,
    caps: &BackendCapabilities,
    now: Timestamp,
) -> Result<(), StoreError> {
    let expires_at = checked_session_deadline(now, ttl)?;
    prune_sync(conn, now)?;

    if !caps.per_key_ttl {
        return Err(StoreError::CapabilityNotSupported("per_key_ttl".into()));
    }
    if !caps.monotonic_fencing_token {
        return Err(StoreError::CapabilityNotSupported(
            "monotonic_fencing_token".into(),
        ));
    }

    validate_fenced_mutation_sync(conn, lease, now)?;
    let current_fence = current_fence_sync(conn, lease.key())?;

    if lease.fence().get() < current_fence {
        return Err(StoreError::StaleFence);
    }

    let record = get_sync(conn, lease.key(), now)?;
    let Some(mut record) = record else {
        return Err(StoreError::NotFound);
    };

    record.expires_at = Some(expires_at);

    insert_or_replace_record_sync(conn, &record)?;
    insert_or_replace_fence_sync(conn, lease.key(), lease.fence().get())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_continuation_uses_primary_key_range_search() {
        let conn = Connection::open_in_memory().expect("in-memory SQLite");
        conn.execute_batch(
            r#"
            CREATE TABLE session_records (
                tenant TEXT NOT NULL,
                nf_kind TEXT NOT NULL,
                key_type TEXT NOT NULL,
                stable_id BLOB NOT NULL,
                generation INTEGER NOT NULL,
                owner TEXT NOT NULL,
                fence INTEGER NOT NULL,
                state_class TEXT NOT NULL,
                state_type TEXT NOT NULL,
                expires_at TEXT,
                payload BLOB NOT NULL,
                encoding INTEGER NOT NULL,
                PRIMARY KEY (tenant, nf_kind, key_type, stable_id)
            );
            "#,
        )
        .expect("restore table");
        let explain_sql = format!("EXPLAIN QUERY PLAN {RESTORE_SCAN_SEEK_PAGE_SQL}");
        let mut stmt = conn.prepare(&explain_sql).expect("prepare query plan");
        let details = stmt
            .query_map(
                named_params! {
                    ":snapshot_time": "2026-07-12T00:00:00.000000000Z",
                    ":seek_tenant": "tenant-a",
                    ":seek_nf_kind": "upf",
                    ":seek_key_type": "pdu-session",
                    ":seek_stable_id": b"seek".as_slice(),
                    ":query_limit": 4097_i64,
                },
                |row| row.get::<_, String>(3),
            )
            .expect("explain continuation")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect query plan");
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("SEARCH session_records")
                    && detail.contains("tenant")
                    && detail.contains(">")),
            "continuation must be an indexed tuple range search: {details:?}"
        );
        assert!(
            details
                .iter()
                .all(|detail| !detail.contains("SCAN session_records")),
            "continuation cannot restart a full index scan: {details:?}"
        );
    }

    #[test]
    fn restore_scan_progress_budget_interrupts_and_is_removed_afterward() {
        let conn = Connection::open_in_memory().expect("in-memory SQLite");
        let guard = install_restore_scan_progress_budget(
            &conn,
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now() + Duration::from_secs(5),
        );
        let error = conn
            .query_row(
                r#"
                WITH RECURSIVE numbers(value) AS (
                    SELECT 1
                    UNION ALL
                    SELECT value + 1 FROM numbers WHERE value < 100000000
                )
                SELECT sum(value) FROM numbers
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect_err("fixed restore work budget must interrupt unbounded SQLite work");
        assert_eq!(
            restore_scan_sqlite_error(error),
            StoreError::RestoreScanWorkBudgetExceeded
        );

        drop(guard);
        assert_eq!(
            conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .expect("progress handler is removed after the bounded scan"),
            1
        );
    }

    #[test]
    fn restore_scan_progress_budget_interrupts_on_the_exact_callback_limit() {
        assert!(!restore_scan_callback_limit_reached(1_998, 2_000));
        assert!(restore_scan_callback_limit_reached(1_999, 2_000));
        assert!(restore_scan_callback_limit_reached(usize::MAX, 2_000));
    }

    #[test]
    fn restore_scan_progress_budget_observes_external_cancellation() {
        let conn = Connection::open_in_memory().expect("in-memory SQLite");
        let cancellation = Arc::new(AtomicBool::new(true));
        let guard = install_restore_scan_progress_budget(
            &conn,
            cancellation,
            std::time::Instant::now() + Duration::from_secs(5),
        );
        let error = conn
            .query_row(
                r#"
                WITH RECURSIVE numbers(value) AS (
                    SELECT 1
                    UNION ALL
                    SELECT value + 1 FROM numbers WHERE value < 100000000
                )
                SELECT sum(value) FROM numbers
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect_err("cancelled restore work is interrupted");
        assert_eq!(
            restore_scan_sqlite_error(error),
            StoreError::RestoreScanWorkBudgetExceeded
        );
        drop(guard);
    }

    #[test]
    fn restore_scan_progress_budget_observes_the_outer_absolute_deadline() {
        let conn = Connection::open_in_memory().expect("in-memory SQLite");
        let guard = install_restore_scan_progress_budget(
            &conn,
            Arc::new(AtomicBool::new(false)),
            std::time::Instant::now(),
        );
        let error = conn
            .query_row(
                r#"
                WITH RECURSIVE numbers(value) AS (
                    SELECT 1
                    UNION ALL
                    SELECT value + 1 FROM numbers WHERE value < 100000000
                )
                SELECT sum(value) FROM numbers
                "#,
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect_err("expired outer deadline interrupts SQLite work");
        assert_eq!(
            restore_scan_sqlite_error(error),
            StoreError::RestoreScanWorkBudgetExceeded
        );
        drop(guard);
    }
}
