use opc_types::Timestamp;
use rusqlite::{params, Connection, OptionalExtension};
use std::str::FromStr;
use std::time::Duration;

use super::ops::{
    current_fence_sync, format_rfc3339_normalized, insert_or_replace_fence_sync, prune_sync,
};
use crate::{
    error::LeaseError,
    lease::LeaseGuard,
    model::{FenceToken, OwnerId, SessionKey},
};

pub(crate) fn acquire_sync(
    conn: &Connection,
    key: &SessionKey,
    owner: OwnerId,
    ttl: Duration,
    now: Timestamp,
) -> Result<LeaseGuard, LeaseError> {
    prune_sync(conn, now).map_err(|e| LeaseError::Backend(e.to_string()))?;

    // Query active lease
    let mut stmt = conn
        .prepare(
            r#"
            SELECT active, owner, guard_expires_at
            FROM leases
            WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
            "#,
        )
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

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
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    if let Some((active, owner_str, guard_expires_at_str)) = row {
        if active != 0 && owner_str != owner.as_str() {
            let guard_expires_at = Timestamp::from_str(guard_expires_at_str.as_str())
                .map_err(|e| LeaseError::Backend(e.to_string()))?;
            if guard_expires_at > now {
                return Err(LeaseError::AlreadyHeld);
            }
        }
    }

    let current_fence_val =
        current_fence_sync(conn, key).map_err(|e| LeaseError::Backend(e.to_string()))?;

    let next_for_key = current_fence_val
        .checked_add(1)
        .ok_or_else(|| LeaseError::Backend("fence token exhausted".into()))?;

    // Get globals
    let mut global_stmt = conn
        .prepare("SELECT val FROM lease_globals WHERE key = ?1")
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    let global_next_fence: i64 = global_stmt
        .query_row(["next_fence"], |row| row.get(0))
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    let global_next_credential_id: i64 = global_stmt
        .query_row(["next_credential_id"], |row| row.get(0))
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    let next_fence = (global_next_fence as u64).max(next_for_key);
    let fence = FenceToken::new(next_fence);

    let next_fence_global = next_fence.saturating_add(1);
    let next_credential_id = global_next_credential_id as u64;
    let next_credential_id_global = next_credential_id.saturating_add(1);

    // Update globals
    conn.execute(
        "UPDATE lease_globals SET val = ?1 WHERE key = 'next_fence'",
        params![next_fence_global as i64],
    )
    .map_err(|e| LeaseError::Backend(e.to_string()))?;

    conn.execute(
        "UPDATE lease_globals SET val = ?1 WHERE key = 'next_credential_id'",
        params![next_credential_id_global as i64],
    )
    .map_err(|e| LeaseError::Backend(e.to_string()))?;

    let acquired_at = now;
    let expires =
        *acquired_at.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
    let expires_at = Timestamp::from_offset_datetime(expires);
    let expires_at_unix_ms = (expires.unix_timestamp_nanos() / 1_000_000) as i64;

    // Save lease
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
            next_credential_id as i64,
            owner.as_str(),
            fence.get() as i64,
            expires_at_unix_ms,
            format_rfc3339_normalized(expires_at),
        ],
    )
    .map_err(|e| LeaseError::Backend(e.to_string()))?;

    // Update key fences
    insert_or_replace_fence_sync(conn, key, fence.get())
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    Ok(LeaseGuard::new(
        key.clone(),
        owner,
        fence,
        acquired_at,
        expires_at,
        next_credential_id,
    ))
}

pub(crate) fn renew_sync(
    conn: &Connection,
    lease: &LeaseGuard,
    ttl: Duration,
    now: Timestamp,
) -> Result<LeaseGuard, LeaseError> {
    if lease.expires_at() <= now {
        return Err(LeaseError::Expired);
    }

    prune_sync(conn, now).map_err(|e| LeaseError::Backend(e.to_string()))?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT active, credential_id, owner, fence, guard_expires_at
            FROM leases
            WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
            "#,
        )
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

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
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    let Some((active, credential_id, owner_str, fence, guard_expires_at_str)) = row else {
        let current_fence = current_fence_sync(conn, lease.key())
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        if lease.fence().get() <= current_fence {
            return Err(LeaseError::StaleFence);
        }
        return Err(LeaseError::NotFound);
    };

    if active == 0 {
        return Err(LeaseError::StaleFence);
    }
    if credential_id as u64 != lease.credential_id() {
        return Err(LeaseError::StaleFence);
    }
    if owner_str != lease.owner().as_str() {
        return Err(LeaseError::AlreadyHeld);
    }

    let guard_expires_at = Timestamp::from_str(guard_expires_at_str.as_str())
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    if fence as u64 != lease.fence().get() || guard_expires_at != lease.expires_at() {
        return Err(LeaseError::StaleFence);
    }

    if guard_expires_at <= now {
        return Err(LeaseError::Expired);
    }

    let fence_token = lease.fence();
    let acquired_at = lease.acquired_at();
    let expires = *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
    let expires_at = Timestamp::from_offset_datetime(expires);
    let expires_at_unix_ms = (expires.unix_timestamp_nanos() / 1_000_000) as i64;

    conn.execute(
        r#"
        UPDATE leases
        SET expires_at_unix_ms = ?1, guard_expires_at = ?2
        WHERE tenant = ?3 AND nf_kind = ?4 AND key_type = ?5 AND stable_id = ?6
        "#,
        params![
            expires_at_unix_ms,
            format_rfc3339_normalized(expires_at),
            lease.key().tenant.as_str(),
            lease.key().nf_kind.as_str(),
            lease.key().key_type.to_string(),
            lease.key().stable_id.as_ref(),
        ],
    )
    .map_err(|e| LeaseError::Backend(e.to_string()))?;

    Ok(LeaseGuard::new(
        lease.key().clone(),
        lease.owner().clone(),
        fence_token,
        acquired_at,
        expires_at,
        credential_id as u64,
    ))
}

pub(crate) fn release_sync(
    conn: &Connection,
    lease: LeaseGuard,
    now: Timestamp,
) -> Result<(), LeaseError> {
    prune_sync(conn, now).map_err(|e| LeaseError::Backend(e.to_string()))?;

    let mut stmt = conn
        .prepare(
            r#"
            SELECT active, credential_id, owner, fence, guard_expires_at
            FROM leases
            WHERE tenant = ?1 AND nf_kind = ?2 AND key_type = ?3 AND stable_id = ?4
            "#,
        )
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

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
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    let Some((active, credential_id, owner_str, fence, guard_expires_at_str)) = row else {
        let current_fence = current_fence_sync(conn, lease.key())
            .map_err(|e| LeaseError::Backend(e.to_string()))?;
        if lease.fence().get() <= current_fence {
            return Err(LeaseError::StaleFence);
        }
        return Err(LeaseError::NotFound);
    };

    if active == 0 {
        return Err(LeaseError::StaleFence);
    }
    if credential_id as u64 != lease.credential_id() {
        return Err(LeaseError::StaleFence);
    }
    if owner_str != lease.owner().as_str() {
        return Err(LeaseError::AlreadyHeld);
    }

    let guard_expires_at = Timestamp::from_str(guard_expires_at_str.as_str())
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    if fence as u64 != lease.fence().get() || guard_expires_at != lease.expires_at() {
        return Err(LeaseError::StaleFence);
    }

    conn.execute(
        r#"
        UPDATE leases
        SET active = 0, guard_expires_at = ?1
        WHERE tenant = ?2 AND nf_kind = ?3 AND key_type = ?4 AND stable_id = ?5
        "#,
        params![
            format_rfc3339_normalized(now),
            lease.key().tenant.as_str(),
            lease.key().nf_kind.as_str(),
            lease.key().key_type.to_string(),
            lease.key().stable_id.as_ref(),
        ],
    )
    .map_err(|e| LeaseError::Backend(e.to_string()))?;

    Ok(())
}
