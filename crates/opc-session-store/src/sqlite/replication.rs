use opc_types::Timestamp;
use rusqlite::{params, Connection, OptionalExtension};
use std::str::FromStr;

use super::ops::{
    current_fence_sync, format_rfc3339_normalized, get_sync, insert_or_replace_fence_sync,
    insert_or_replace_record_sync,
};
use crate::{
    backend::{ReplicationEntry, ReplicationOp},
    capability::BackendCapabilities,
    error::StoreError,
};

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
            if active == 0
                || row_credential_id as u64 != credential_id
                || owner_str != new_record.owner.as_str()
                || fence_val as u64 != new_record.fence.get()
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
            conn.execute(
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
                if active != 0 && owner_str != owner.as_str() {
                    let guard_expires_at = Timestamp::from_str(guard_expires_at_str.as_str())
                        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                    if guard_expires_at > now {
                        return Err(StoreError::LeaseHeld);
                    }
                }
            }

            let expires_at_unix_ms =
                (expires_at.as_offset_datetime().unix_timestamp_nanos() / 1_000_000) as i64;

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
                    credential_id as i64,
                    owner.as_str(),
                    fence.get() as i64,
                    expires_at_unix_ms,
                    format_rfc3339_normalized(expires_at),
                ],
            )
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

            insert_or_replace_fence_sync(conn, &key, fence.get())?;

            conn.execute(
                "UPDATE lease_globals SET val = val + 1 WHERE key = 'next_fence'",
                [],
            )
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            conn.execute(
                "UPDATE lease_globals SET val = val + 1 WHERE key = 'next_credential_id'",
                [],
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
            let expires_at_unix_ms =
                (expires_at.as_offset_datetime().unix_timestamp_nanos() / 1_000_000) as i64;

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
                    credential_id as i64,
                    owner.as_str(),
                    fence.get() as i64,
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
                    credential_id as i64,
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
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    // 1. Get max sequence
    let max_seq: Option<Option<i64>> = tx
        .query_row(
            "SELECT MAX(sequence) FROM session_replication_log",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    let max_seq = max_seq.flatten().unwrap_or(0) as u64;

    if entry.sequence <= max_seq {
        // Check for duplicate delivery and idempotency
        let existing_tx_id: Option<String> = tx
            .query_row(
                "SELECT tx_id FROM session_replication_log WHERE sequence = ?1",
                params![entry.sequence as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        if let Some(tx_id) = existing_tx_id {
            if tx_id == entry.tx_id {
                return Ok(false); // Already applied, do not notify watchers again
            }
        }
        return Err(StoreError::BackendUnavailable(
            "divergent replication entry sequence".into(),
        ));
    }

    if entry.sequence > max_seq + 1 {
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
        params![entry.sequence as i64, entry.tx_id, entry_json, timestamp_str],
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
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    tx.execute("DELETE FROM session_records", [])
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
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

    for (expected_sequence, entry) in (1_u64..).zip(entries.iter()) {
        if entry.sequence != expected_sequence {
            return Err(StoreError::BackendUnavailable(
                "replication log sequence gap".into(),
            ));
        }

        apply_replicated_op_sync(&tx, entry.op.clone(), caps, entry.timestamp)?;

        let entry_json =
            serde_json::to_string(entry).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let timestamp_str = format_rfc3339_normalized(entry.timestamp);
        tx.execute(
            "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![entry.sequence as i64, entry.tx_id, entry_json, timestamp_str],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    }

    tx.commit()
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    Ok(())
}
