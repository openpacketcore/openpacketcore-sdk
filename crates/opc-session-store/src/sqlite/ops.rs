use opc_types::Timestamp;
use rusqlite::{params, Connection, OptionalExtension};
use std::str::FromStr;
use std::time::Duration;

use crate::{
    backend::{CompareAndSet, CompareAndSetResult},
    capability::BackendCapabilities,
    error::StoreError,
    lease::LeaseGuard,
    model::{FenceToken, Generation, OwnerId, SessionKey, StateClass, StateType},
    record::{EncryptedSessionPayload, SessionPayloadEncoding, StoredSessionRecord},
};

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

pub(crate) fn prune_sync(conn: &Connection, now: Timestamp) -> Result<(), StoreError> {
    let now_str = format_rfc3339_normalized(now);
    // 1. Delete expired session records
    conn.execute(
        "DELETE FROM session_records WHERE expires_at IS NOT NULL AND expires_at <= ?1",
        params![now_str],
    )
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    // 2. Delete expired or released leases
    conn.execute(
        "DELETE FROM leases WHERE active = 0 OR guard_expires_at <= ?1",
        params![now_str],
    )
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

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

    if credential_id as u64 != lease.credential_id() {
        return Err(StoreError::StaleFence);
    }

    if owner_str != lease.owner().as_str() {
        return Err(StoreError::StaleFence);
    }

    if fence as u64 != lease.fence().get() {
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

    Ok(row.unwrap_or(0) as u64)
}

pub(crate) fn get_sync(
    conn: &Connection,
    key: &SessionKey,
    now: Timestamp,
) -> Result<Option<StoredSessionRecord>, StoreError> {
    prune_sync(conn, now)?;

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

    let owner = OwnerId::new(owner_str).map_err(StoreError::Serialization)?;
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
        0 => EncryptedSessionPayload::from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::Plaintext,
        ),
        1 => EncryptedSessionPayload::from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::LegacyPlaintext,
        ),
        2 => EncryptedSessionPayload::from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::EnvelopeV1,
        ),
        3 => EncryptedSessionPayload::from_vec_with_encoding(
            payload_bytes,
            SessionPayloadEncoding::Unclassified,
        ),
        _ => {
            return Err(StoreError::Serialization(format!(
                "unknown payload encoding: {encoding}"
            )))
        }
    };

    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(generation as u64),
        owner,
        fence: FenceToken::new(fence as u64),
        state_class,
        state_type,
        expires_at,
        payload,
    };

    if record.is_expired_at(now) {
        Ok(None)
    } else {
        Ok(Some(record))
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
        INSERT OR REPLACE INTO session_records (
            tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, state_type, expires_at, payload, encoding
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
        params![
            record.key.tenant.as_str(),
            record.key.nf_kind.as_str(),
            record.key.key_type.to_string(),
            record.key.stable_id.as_ref(),
            record.generation.get() as i64,
            record.owner.as_str(),
            record.fence.get() as i64,
            record.state_class.to_string(),
            record.state_type.as_str(),
            expires_at_str,
            record.payload.as_bytes(),
            encoding_val,
        ],
    )
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

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
            fence as i64,
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

    conn.execute(
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

    let expires = *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
    record.expires_at = Some(Timestamp::from_offset_datetime(expires));

    insert_or_replace_record_sync(conn, &record)?;
    insert_or_replace_fence_sync(conn, lease.key(), lease.fence().get())?;

    Ok(())
}
