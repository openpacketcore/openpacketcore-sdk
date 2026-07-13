use opc_types::Timestamp;
use rusqlite::{params, Connection, OptionalExtension};
use std::str::FromStr;

use super::ops::{
    advance_restore_scan_revision_sync, current_fence_sync, format_rfc3339_normalized, get_sync,
    insert_or_replace_fence_sync, insert_or_replace_record_sync, persisted_owner_id, persisted_u64,
    sqlite_u64, timestamp_unix_millis,
};
use crate::{
    backend::{
        next_replication_sequence, validate_replication_prefix, ReplicationEntry, ReplicationOp,
        ReplicationTxId, REPLICATION_TX_ID_MAX_BYTES, REPLICATION_TX_ID_MIN_BYTES,
    },
    capability::BackendCapabilities,
    error::StoreError,
};

pub(crate) fn sqlite_replication_sequence(sequence: u64) -> Result<i64, StoreError> {
    if sequence == 0 {
        return Err(StoreError::InvalidReplicationSequence);
    }
    i64::try_from(sequence).map_err(|_| StoreError::InvalidReplicationSequence)
}

pub(crate) fn stored_replication_sequence(sequence: i64) -> Result<u64, StoreError> {
    let sequence = u64::try_from(sequence).map_err(|_| StoreError::InvalidReplicationSequence)?;
    if sequence == 0 {
        return Err(StoreError::InvalidReplicationSequence);
    }
    Ok(sequence)
}

pub(crate) fn hydrate_replication_entry(
    stored_sequence: i64,
    stored_tx_id: Option<String>,
    encoded: &str,
) -> Result<ReplicationEntry, StoreError> {
    let stored_sequence = stored_replication_sequence(stored_sequence)?;
    let stored_tx_id: ReplicationTxId = stored_tx_id
        .ok_or_else(|| {
            StoreError::Serialization("persisted replication transaction ID is invalid".into())
        })?
        .try_into()
        .map_err(|_| {
            StoreError::Serialization("persisted replication transaction ID is invalid".into())
        })?;
    let entry: ReplicationEntry = serde_json::from_str(encoded)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let entry = entry.into_validated()?;
    if entry.sequence != stored_sequence {
        return Err(StoreError::InvalidReplicationSequence);
    }
    if entry.tx_id != stored_tx_id {
        return Err(StoreError::Serialization(
            "persisted replication transaction ID is inconsistent".into(),
        ));
    }
    Ok(entry)
}

pub(crate) fn apply_replicated_op_sync(
    conn: &Connection,
    op: ReplicationOp,
    _caps: &BackendCapabilities,
    now: Timestamp,
) -> Result<(), StoreError> {
    match op {
        ReplicationOp::CompareAndSet {
            key,
            expected_generation,
            credential_id,
            guard_expires_at,
            new_record,
        } => {
            let current_fence = current_fence_sync(conn, &key)?;
            if new_record.fence.get() < current_fence {
                return Err(StoreError::StaleFence);
            }

            let mut lease_stmt = conn
                .prepare(
                    r#"
                    SELECT active, credential_id, owner, fence, guard_expires_at
                    FROM leases
                    WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
                    "#,
                )
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            let row = lease_stmt
                .query_row(
                    params![
                        key.tenant.as_str(),
                        key.nf_kind.as_str(),
                        key.key_type.to_string(),
                        key.stable_id.as_ref(),
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

            let Some((active, row_credential_id, owner_str, fence_val, guard_expires_at_str)) = row
            else {
                return Err(StoreError::StaleFence);
            };
            let stored_owner = persisted_owner_id(owner_str)?;
            if active == 0
                || persisted_u64(row_credential_id)? != credential_id
                || stored_owner != new_record.owner
                || persisted_u64(fence_val)? != new_record.fence.get()
            {
                return Err(StoreError::StaleFence);
            }
            let stored_guard_expires_at = Timestamp::from_str(guard_expires_at_str.as_str())
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            if stored_guard_expires_at != guard_expires_at {
                return Err(StoreError::StaleFence);
            }
            if stored_guard_expires_at <= now {
                return Err(StoreError::LeaseExpired);
            }

            let existing = get_sync(conn, &key, now)?;
            match (expected_generation, existing) {
                (None, None) => {
                    insert_or_replace_record_sync(conn, &new_record)?;
                    insert_or_replace_fence_sync(conn, &key, new_record.fence.get())?;
                    Ok(())
                }
                (Some(expected), Some(current)) => {
                    if current.generation != expected {
                        return Err(StoreError::CasConflict);
                    }
                    if (current.state_class.requires_monotonic_generation()
                        || new_record.state_class.requires_monotonic_generation())
                        && new_record.generation <= current.generation
                    {
                        return Err(StoreError::CasConflict);
                    }
                    insert_or_replace_record_sync(conn, &new_record)?;
                    insert_or_replace_fence_sync(conn, &key, new_record.fence.get())?;
                    Ok(())
                }
                _ => Err(StoreError::CasConflict),
            }
        }
        ReplicationOp::DeleteFenced {
            key,
            owner: _,
            fence,
        } => {
            let current_fence = current_fence_sync(conn, &key)?;
            if fence.get() < current_fence {
                return Err(StoreError::StaleFence);
            }
            let removed = conn
                .execute(
                    r#"
                DELETE FROM session_records
                WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
                "#,
                    params![
                        key.tenant.as_str(),
                        key.nf_kind.as_str(),
                        key.key_type.to_string(),
                        key.stable_id.as_ref(),
                    ],
                )
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            if removed > 0 {
                advance_restore_scan_revision_sync(conn)?;
            }
            insert_or_replace_fence_sync(conn, &key, fence.get())?;
            Ok(())
        }
        ReplicationOp::RefreshTtl {
            key,
            owner: _,
            fence,
            ttl: _,
            expires_at,
        } => {
            let current_fence = current_fence_sync(conn, &key)?;
            if fence.get() < current_fence {
                return Err(StoreError::StaleFence);
            }
            let record = get_sync(conn, &key, now)?;
            let Some(mut record) = record else {
                return Err(StoreError::NotFound);
            };
            record.expires_at = Some(expires_at);
            insert_or_replace_record_sync(conn, &record)?;
            insert_or_replace_fence_sync(conn, &key, fence.get())?;
            Ok(())
        }
        ReplicationOp::AcquireLease {
            key,
            owner,
            fence,
            credential_id,
            ttl: _,
            expires_at,
        } => {
            let current_fence = current_fence_sync(conn, &key)?;
            if fence.get() < current_fence {
                return Err(StoreError::StaleFence);
            }
            let mut stmt = conn
                .prepare(
                    r#"
                    SELECT active, owner, guard_expires_at
                    FROM leases
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
                            row.get::<_, i32>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

            if let Some((active, owner_str, guard_expires_at_str)) = row {
                let stored_owner = persisted_owner_id(owner_str)?;
                if active != 0 && stored_owner != owner {
                    let guard_expires_at = Timestamp::from_str(guard_expires_at_str.as_str())
                        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                    if guard_expires_at > now {
                        return Err(StoreError::LeaseHeld);
                    }
                }
            }

            let expires_at_unix_ms = timestamp_unix_millis(expires_at)?;

            conn.execute(
                r#"
                INSERT OR REPLACE INTO leases (
                    tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at
                ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    key.tenant.as_str(),
                    key.nf_kind.as_str(),
                    key.key_type.to_string(),
                    key.stable_id.as_ref(),
                    sqlite_u64(credential_id)?,
                    owner.as_str(),
                    sqlite_u64(fence.get())?,
                    expires_at_unix_ms,
                    format_rfc3339_normalized(expires_at),
                ],
            )
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

            insert_or_replace_fence_sync(conn, &key, fence.get())?;

            let next_fence = fence
                .get()
                .checked_add(1)
                .ok_or_else(|| StoreError::BackendUnavailable("fence token exhausted".into()))?;
            conn.execute(
                "UPDATE lease_globals SET val = MAX(val, ?1) WHERE key = 'next_fence'",
                [sqlite_u64(next_fence)?],
            )
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            let next_credential_id = credential_id.checked_add(1).ok_or_else(|| {
                StoreError::BackendUnavailable("lease credential ID exhausted".into())
            })?;
            conn.execute(
                "UPDATE lease_globals SET val = MAX(val, ?1) WHERE key = 'next_credential_id'",
                [sqlite_u64(next_credential_id)?],
            )
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            Ok(())
        }
        ReplicationOp::RenewLease {
            key,
            owner,
            fence,
            credential_id,
            ttl: _,
            expires_at,
        } => {
            let current_fence = current_fence_sync(conn, &key)?;
            if fence.get() < current_fence {
                return Err(StoreError::StaleFence);
            }
            let expires_at_unix_ms = timestamp_unix_millis(expires_at)?;

            conn.execute(
                r#"
                INSERT OR REPLACE INTO leases (
                    tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at
                ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    key.tenant.as_str(),
                    key.nf_kind.as_str(),
                    key.key_type.to_string(),
                    key.stable_id.as_ref(),
                    sqlite_u64(credential_id)?,
                    owner.as_str(),
                    sqlite_u64(fence.get())?,
                    expires_at_unix_ms,
                    format_rfc3339_normalized(expires_at),
                ],
            )
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

            insert_or_replace_fence_sync(conn, &key, fence.get())?;
            Ok(())
        }
        ReplicationOp::ReleaseLease {
            key,
            owner: _,
            fence,
            credential_id,
        } => {
            let current_fence = current_fence_sync(conn, &key)?;
            if fence.get() < current_fence {
                return Err(StoreError::StaleFence);
            }
            conn.execute(
                r#"
                UPDATE leases
                SET active = 0
                WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4 AND credential_id = ?5
                "#,
                params![
                    key.tenant.as_str(),
                    key.nf_kind.as_str(),
                    key.key_type.to_string(),
                    key.stable_id.as_ref(),
                    sqlite_u64(credential_id)?,
                ],
            )
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            insert_or_replace_fence_sync(conn, &key, fence.get())?;
            Ok(())
        }
        ReplicationOp::Batch { ops } => {
            for sub_op in ops {
                apply_replicated_op_sync(conn, sub_op, _caps, now)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn replicate_entry_sync(
    conn: &Connection,
    entry: &ReplicationEntry,
    caps: &BackendCapabilities,
    now: Timestamp,
) -> Result<bool, StoreError> {
    entry.validate()?;
    let sqlite_sequence = sqlite_replication_sequence(entry.sequence)?;
    let tx = super::standalone_transaction(conn)?;

    // 1. Get max sequence
    let max_seq: Option<Option<i64>> = tx
        .query_row(
            "SELECT MAX(sequence) FROM session_replication_log",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    let max_seq = max_seq
        .flatten()
        .map(stored_replication_sequence)
        .transpose()?
        .unwrap_or(0);

    if entry.sequence <= max_seq {
        // Check for duplicate delivery and idempotency
        let existing: Option<(Option<String>, String)> = tx
            .query_row(
                r#"
                SELECT CASE
                           WHEN typeof(tx_id) = 'text'
                            AND length(CAST(tx_id AS BLOB)) BETWEEN ?2 AND ?3
                           THEN tx_id
                       END,
                       entry_json
                FROM session_replication_log
                WHERE sequence = ?1
                "#,
                params![
                    sqlite_sequence,
                    REPLICATION_TX_ID_MIN_BYTES,
                    REPLICATION_TX_ID_MAX_BYTES
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        if let Some((stored_tx_id, existing_entry_json)) = existing {
            let existing =
                hydrate_replication_entry(sqlite_sequence, stored_tx_id, &existing_entry_json)?;
            if existing == *entry {
                return Ok(false); // Already applied, do not notify watchers again
            }
        }
        return Err(StoreError::BackendUnavailable(
            "divergent replication entry sequence".into(),
        ));
    }

    if entry.sequence != next_replication_sequence(max_seq)? {
        return Err(StoreError::BackendUnavailable(
            "replication log sequence gap".into(),
        ));
    }

    // Apply mutation
    apply_replicated_op_sync(&tx, entry.op.clone(), caps, now)?;

    // Append to replication log table
    let entry_json =
        serde_json::to_string(&entry).map_err(|e| StoreError::Serialization(e.to_string()))?;
    let timestamp_str = format_rfc3339_normalized(entry.timestamp);

    tx.execute(
        "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![
            sqlite_sequence,
            entry.tx_id.as_str(),
            entry_json,
            timestamp_str
        ],
    )
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    tx.commit()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    Ok(true)
}

pub(crate) fn rebuild_replication_state_sync(
    conn: &Connection,
    entries: &[ReplicationEntry],
    caps: &BackendCapabilities,
) -> Result<(), StoreError> {
    validate_replication_prefix(entries)?;
    let tx = super::standalone_transaction(conn)?;

    let removed_records = tx
        .execute("DELETE FROM session_records", [])
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    if removed_records > 0 {
        advance_restore_scan_revision_sync(&tx)?;
    }
    tx.execute("DELETE FROM leases", [])
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    tx.execute("DELETE FROM key_fences", [])
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    tx.execute("DELETE FROM session_replication_log", [])
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    tx.execute(
        "UPDATE lease_globals SET val = 1 WHERE key = 'next_fence'",
        [],
    )
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    tx.execute(
        "UPDATE lease_globals SET val = 1 WHERE key = 'next_credential_id'",
        [],
    )
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    for entry in entries {
        apply_replicated_op_sync(&tx, entry.op.clone(), caps, entry.timestamp)?;

        let entry_json =
            serde_json::to_string(entry).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let timestamp_str = format_rfc3339_normalized(entry.timestamp);
        tx.execute(
            "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![
                sqlite_replication_sequence(entry.sequence)?,
                entry.tx_id.as_str(),
                entry_json,
                timestamp_str
            ],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    }

    tx.commit()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    Ok(())
}
