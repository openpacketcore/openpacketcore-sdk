use opc_types::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};
use std::str::FromStr;

use super::ops::{
    advance_restore_scan_revision_sync, current_fence_sync, format_rfc3339_normalized, get_sync,
    insert_or_replace_fence_sync, insert_or_replace_record_sync, persisted_normalized_timestamp,
    persisted_owner_id, persisted_u64, sqlite_u64, timestamp_unix_millis,
};
use crate::{
    backend::{
        ProtectedRosterEstablishedSuccessor, REPLICATION_TX_ID_MAX_BYTES,
        REPLICATION_TX_ID_MIN_BYTES, ReplicationEntry, ReplicationOp, ReplicationTxId,
        next_replication_sequence, validate_replication_prefix,
    },
    capability::BackendCapabilities,
    error::StoreError,
    model::StateClass,
    record::SessionPayloadEncoding,
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
    caps: &BackendCapabilities,
    now: Timestamp,
) -> Result<(), StoreError> {
    // Keep this defense at the replay boundary as callers other than the
    // public async adapter can invoke this synchronous helper directly.
    // In particular, validate an entire nested batch before its first child
    // can mutate the transaction.
    validate_replication_payloads(&op, caps.max_value_bytes)?;
    apply_validated_replicated_op_sync(conn, op, now)
}

fn apply_validated_replicated_op_sync(
    conn: &Connection,
    op: ReplicationOp,
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
                    tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, acquired_at, expires_at_unix_ms, guard_expires_at
                ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    key.tenant.as_str(),
                    key.nf_kind.as_str(),
                    key.key_type.to_string(),
                    key.stable_id.as_ref(),
                    sqlite_u64(credential_id)?,
                    owner.as_str(),
                    sqlite_u64(fence.get())?,
                    format_rfc3339_normalized(now),
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
            // A renew event carries no acquisition timestamp by design. It
            // must preserve an already-authoritative value, never synthesize
            // one for a migrated legacy row.
            let current_fence = current_fence_sync(conn, &key)?;
            if fence.get() < current_fence {
                return Err(StoreError::StaleFence);
            }
            let persisted_authority = conn
                .query_row(
                    r#"
                    SELECT acquired_at, guard_expires_at
                    FROM leases
                    WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
                    "#,
                    params![
                        key.tenant.as_str(),
                        key.nf_kind.as_str(),
                        key.key_type.to_string(),
                        key.stable_id.as_ref(),
                    ],
                    |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            persisted_authority
                .and_then(|(acquired_at, guard_expires_at)| {
                    let guard_expires_at = persisted_normalized_timestamp(Some(guard_expires_at))?;
                    persisted_normalized_timestamp(acquired_at)
                        .filter(|acquired_at| *acquired_at <= guard_expires_at)
                        .map(|_| ())
                })
                .ok_or(StoreError::StaleFence)?;
            let expires_at_unix_ms = timestamp_unix_millis(expires_at)?;

            let changed = conn
                .execute(
                    r#"
                UPDATE leases
                SET expires_at_unix_ms = ?1, guard_expires_at = ?2
                WHERE tenant = ?3 AND nf_kind = ?4 AND key_type = ?5 AND stable_id = ?6
                  AND active = 1 AND credential_id = ?7 AND owner = ?8 AND fence = ?9
                "#,
                    params![
                        expires_at_unix_ms,
                        format_rfc3339_normalized(expires_at),
                        key.tenant.as_str(),
                        key.nf_kind.as_str(),
                        key.key_type.to_string(),
                        key.stable_id.as_ref(),
                        sqlite_u64(credential_id)?,
                        owner.as_str(),
                        sqlite_u64(fence.get())?,
                    ],
                )
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            if changed != 1 {
                return Err(StoreError::StaleFence);
            }

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
        ReplicationOp::ProtectedRosterEstablished {
            key,
            expected_record,
            successor,
            owner,
            fence,
            credential_id,
            guard_acquired_at,
            guard_expires_at,
        } => apply_protected_roster_established_sync(
            conn,
            &key,
            &expected_record,
            successor,
            &owner,
            fence,
            credential_id,
            guard_acquired_at,
            guard_expires_at,
            now,
        ),
        ReplicationOp::Batch { ops } => {
            for sub_op in ops {
                apply_validated_replicated_op_sync(conn, sub_op, now)?;
            }
            Ok(())
        }
    }
}

/// Validate the narrow shape that the protected-roster terminal builder
/// materializes from an immutable admission.  This is intentionally stricter
/// than an ordinary CAS: a roster terminal never carries a TTL row or an
/// unsealed payload, and its successor retains the admission provenance even
/// when the execution lease has moved to a higher fence.
fn validate_protected_roster_authoritative_record(
    record: &crate::StoredSessionRecord,
    key: &crate::model::SessionKey,
) -> Result<(), StoreError> {
    if record.key != *key
        || record.state_class != StateClass::AuthoritativeSession
        || record.expires_at.is_some()
        || record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1
    {
        return Err(StoreError::InvalidKey(
            "protected roster replication record is invalid".into(),
        ));
    }
    record
        .payload
        .validate_envelope_for_record(record)
        .map_err(|_| {
            StoreError::Serialization("protected roster replication record is invalid".into())
        })
}

/// Apply the session-record projection of one already-committed protected
/// roster Established terminal.  Its roster receipt/proof state belongs to
/// the Raft transaction; this separate replication journal replays only the
/// exact business effect while retaining a higher successor fence floor.
#[allow(clippy::too_many_arguments)]
fn apply_protected_roster_established_sync(
    conn: &Connection,
    key: &crate::model::SessionKey,
    expected_record: &crate::StoredSessionRecord,
    successor: ProtectedRosterEstablishedSuccessor,
    owner: &crate::model::OwnerId,
    fence: crate::model::FenceToken,
    credential_id: u64,
    guard_acquired_at: Timestamp,
    guard_expires_at: Timestamp,
    now: Timestamp,
) -> Result<(), StoreError> {
    validate_protected_roster_authoritative_record(expected_record, key)?;
    if credential_id == 0
        || guard_expires_at <= guard_acquired_at
        || fence.get() < expected_record.fence.get()
    {
        return Err(StoreError::StaleFence);
    }
    let current_fence = current_fence_sync(conn, key)?;
    if current_fence > fence.get() {
        return Err(StoreError::StaleFence);
    }

    let lease: Option<(i32, i64, String, i64, Option<String>, String)> = conn
        .query_row(
            r#"
            SELECT active, credential_id, owner, fence, acquired_at, guard_expires_at
            FROM leases
            WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
            "#,
            params![
                key.tenant.as_str(),
                key.nf_kind.as_str(),
                key.key_type.to_string(),
                key.stable_id.as_ref(),
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| {
            StoreError::BackendUnavailable("protected roster replication unavailable".into())
        })?;
    let Some((
        active,
        stored_credential,
        stored_owner,
        stored_fence,
        stored_acquired,
        stored_expiry,
    )) = lease
    else {
        return Err(StoreError::StaleFence);
    };
    let stored_acquired =
        persisted_normalized_timestamp(stored_acquired).ok_or(StoreError::StaleFence)?;
    let stored_expiry = Timestamp::from_str(&stored_expiry).map_err(|_| {
        StoreError::Serialization("protected roster replication metadata is invalid".into())
    })?;
    if active == 0
        || persisted_u64(stored_credential)? != credential_id
        || persisted_owner_id(stored_owner)? != *owner
        || persisted_u64(stored_fence)? != fence.get()
        || stored_acquired != guard_acquired_at
        || stored_expiry != guard_expires_at
    {
        return Err(StoreError::StaleFence);
    }
    if guard_expires_at <= now {
        return Err(StoreError::LeaseExpired);
    }

    let current = super::ops::get_raw_sync(conn, key)?;
    if current.as_ref() != Some(expected_record) {
        return Err(StoreError::CasConflict);
    }
    match successor {
        ProtectedRosterEstablishedSuccessor::Put { record } => {
            validate_protected_roster_authoritative_record(&record, key)?;
            // The established Update path is the only generation-advancing
            // materialization.  It intentionally preserves the original
            // owner/fence provenance rather than adopting `fence` above.
            if record.owner != expected_record.owner
                || record.fence != expected_record.fence
                || record.generation <= expected_record.generation
            {
                return Err(StoreError::CasConflict);
            }
            insert_or_replace_record_sync(conn, &record)?;
        }
        ProtectedRosterEstablishedSuccessor::Delete => {
            let removed = conn
                .execute(
                    "DELETE FROM session_records WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3 AND stable_id=?4",
                    params![
                        key.tenant.as_str(),
                        key.nf_kind.as_str(),
                        key.key_type.to_string(),
                        key.stable_id.as_ref(),
                    ],
                )
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "protected roster replication unavailable".into(),
                    )
                })?;
            if removed != 1 {
                return Err(StoreError::CasConflict);
            }
            advance_restore_scan_revision_sync(conn)?;
        }
        ProtectedRosterEstablishedSuccessor::NoOp => {}
    }
    // Do not rewrite equal floors, but atomically raise a missing or lower
    // floor after the exact business CAS succeeds.  This permanently rejects
    // any later replay under the immutable admission's older fence.
    if current_fence < fence.get() {
        insert_or_replace_fence_sync(conn, key, fence.get())?;
    }
    Ok(())
}

fn validate_replication_payload_len(
    record: &crate::StoredSessionRecord,
    max_value_bytes: usize,
) -> Result<(), StoreError> {
    if record.payload.len() > max_value_bytes {
        return Err(StoreError::PayloadTooLarge {
            actual: record.payload.len(),
            max: max_value_bytes,
        });
    }
    Ok(())
}

pub(crate) fn validate_replication_payloads(
    root: &ReplicationOp,
    max_value_bytes: usize,
) -> Result<(), StoreError> {
    // This preflight is shared by the public adapter, append/rebuild helpers,
    // and the replay defense above. Structure is checked first so walking an
    // untrusted tree stays bounded before we inspect every nested CAS.
    root.validate_structure()?;

    let mut pending = vec![root];
    while let Some(op) = pending.pop() {
        match op {
            ReplicationOp::CompareAndSet {
                key, new_record, ..
            } => {
                if new_record.key != *key {
                    return Err(StoreError::InvalidKey(
                        "compare-and-set key does not match record key".into(),
                    ));
                }
                validate_replication_payload_len(new_record, max_value_bytes)?;
            }
            ReplicationOp::ProtectedRosterEstablished {
                key,
                expected_record,
                successor,
                ..
            } => {
                if expected_record.key != *key {
                    return Err(StoreError::InvalidKey(
                        "protected roster replication key does not match record key".into(),
                    ));
                }
                validate_replication_payload_len(expected_record, max_value_bytes)?;
                if let ProtectedRosterEstablishedSuccessor::Put { record } = successor {
                    if record.key != *key {
                        return Err(StoreError::InvalidKey(
                            "protected roster replication key does not match record key".into(),
                        ));
                    }
                    validate_replication_payload_len(record, max_value_bytes)?;
                }
            }
            ReplicationOp::Batch { ops } => pending.extend(ops.iter()),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn replicate_entry_sync(
    conn: &Connection,
    entry: &ReplicationEntry,
    caps: &BackendCapabilities,
    now: Timestamp,
) -> Result<bool, StoreError> {
    entry.validate()?;
    validate_replication_payloads(&entry.op, caps.max_value_bytes)?;
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
        .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;

    Ok(true)
}

pub(crate) fn rebuild_replication_state_sync(
    conn: &Connection,
    entries: &[ReplicationEntry],
    caps: &BackendCapabilities,
) -> Result<(), StoreError> {
    validate_replication_prefix(entries)?;
    for entry in entries {
        validate_replication_payloads(&entry.op, caps.max_value_bytes)?;
    }
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
        .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;
    Ok(())
}
