use opc_types::Timestamp;
use rusqlite::{params, Connection, OptionalExtension};
use std::time::Duration;

use super::ops::{
    current_fence_sync, format_rfc3339_normalized, insert_or_replace_fence_sync,
    persisted_normalized_timestamp, persisted_owner_id, persisted_u64, prune_sync, sqlite_u64,
    timestamp_unix_millis,
};
use crate::{
    error::LeaseError,
    lease::LeaseGuard,
    model::{FenceToken, OwnerId, SessionKey},
    ttl::checked_session_deadline,
};

pub(crate) fn acquire_sync(
    conn: &Connection,
    key: &SessionKey,
    owner: OwnerId,
    ttl: Duration,
    now: Timestamp,
) -> Result<LeaseGuard, LeaseError> {
    acquire_with_fence_sync(conn, key, owner, ttl, now, None)
}

/// Acquire using the exact previously observed per-key fence.
///
/// Unlike the legacy global allocator, this path deterministically mints the
/// per-key successor so a protected record in the same consensus command can
/// bind the resulting fence before proposal. The global high-water allocator
/// is advanced when necessary and remains strictly above every stored fence.
pub(crate) fn acquire_exact_sync(
    conn: &Connection,
    key: &SessionKey,
    owner: OwnerId,
    expected_fence: FenceToken,
    ttl: Duration,
    now: Timestamp,
) -> Result<LeaseGuard, LeaseError> {
    acquire_with_fence_sync(conn, key, owner, ttl, now, Some(expected_fence))
}

fn acquire_with_fence_sync(
    conn: &Connection,
    key: &SessionKey,
    owner: OwnerId,
    ttl: Duration,
    now: Timestamp,
    expected_fence: Option<FenceToken>,
) -> Result<LeaseGuard, LeaseError> {
    let expires_at = checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
    // The legacy standalone lease operation retains its global expiry sweep.
    // An exact acquire is used by the single-key fenced transition and must
    // not mutate unrelated expired records or leases at that log position.
    if expected_fence.is_none() {
        prune_sync(conn, now).map_err(|e| LeaseError::Backend(e.to_string()))?;
    }

    let current_fence_val =
        current_fence_sync(conn, key).map_err(|e| LeaseError::Backend(e.to_string()))?;
    if expected_fence.is_some_and(|expected| expected.get() != current_fence_val) {
        return Err(LeaseError::StaleFence);
    }

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
        let stored_owner = persisted_owner_id(owner_str)
            .map_err(|_| LeaseError::Backend("persisted session owner is invalid".to_string()))?;
        if active != 0 && (expected_fence.is_some() || stored_owner != owner) {
            let guard_expires_at = persisted_normalized_timestamp(Some(guard_expires_at_str))
                .ok_or_else(|| LeaseError::Backend("persisted lease expiry is invalid".into()))?;
            if guard_expires_at > now {
                return Err(LeaseError::AlreadyHeld);
            }
        }
    }

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

    let global_next_fence =
        persisted_u64(global_next_fence).map_err(|error| LeaseError::Backend(error.to_string()))?;
    if global_next_fence == 0 {
        return Err(LeaseError::Backend(
            "persisted next fence is invalid".to_string(),
        ));
    }
    let next_fence = if expected_fence.is_some() {
        next_for_key
    } else {
        global_next_fence.max(next_for_key)
    };
    let fence = FenceToken::new(next_fence);

    let successor_fence = next_fence
        .checked_add(1)
        .ok_or_else(|| LeaseError::Backend("fence token exhausted".into()))?;
    let next_fence_global = global_next_fence.max(successor_fence);
    let next_credential_id = persisted_u64(global_next_credential_id)
        .map_err(|error| LeaseError::Backend(error.to_string()))?;
    if next_credential_id == 0 {
        return Err(LeaseError::Backend(
            "persisted next credential ID is invalid".to_string(),
        ));
    }
    let next_credential_id_global = next_credential_id
        .checked_add(1)
        .ok_or_else(|| LeaseError::Backend("lease credential ID exhausted".into()))?;

    // Update globals
    conn.execute(
        "UPDATE lease_globals SET val = ?1 WHERE key = 'next_fence'",
        params![sqlite_u64(next_fence_global)
            .map_err(|error| LeaseError::Backend(error.to_string()))?],
    )
    .map_err(|e| LeaseError::Backend(e.to_string()))?;

    conn.execute(
        "UPDATE lease_globals SET val = ?1 WHERE key = 'next_credential_id'",
        params![sqlite_u64(next_credential_id_global)
            .map_err(|error| LeaseError::Backend(error.to_string()))?],
    )
    .map_err(|e| LeaseError::Backend(e.to_string()))?;

    let acquired_at = now;
    let expires_at_unix_ms = timestamp_unix_millis(expires_at)
        .map_err(|error| LeaseError::Backend(error.to_string()))?;

    // Save lease
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
            sqlite_u64(next_credential_id)
                .map_err(|error| LeaseError::Backend(error.to_string()))?,
            owner.as_str(),
            sqlite_u64(fence.get()).map_err(|error| LeaseError::Backend(error.to_string()))?,
            format_rfc3339_normalized(acquired_at),
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
    renew_with_prune_sync(conn, lease, ttl, now, true)
}

/// Renew an exact credential without sweeping unrelated expired state.
pub(crate) fn renew_exact_sync(
    conn: &Connection,
    lease: &LeaseGuard,
    ttl: Duration,
    now: Timestamp,
) -> Result<LeaseGuard, LeaseError> {
    renew_with_prune_sync(conn, lease, ttl, now, false)
}

fn renew_with_prune_sync(
    conn: &Connection,
    lease: &LeaseGuard,
    ttl: Duration,
    now: Timestamp,
    prune_expired: bool,
) -> Result<LeaseGuard, LeaseError> {
    let expires_at = checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
    if lease.expires_at() <= now {
        return Err(LeaseError::Expired);
    }

    if prune_expired {
        prune_sync(conn, now).map_err(|e| LeaseError::Backend(e.to_string()))?;
    }

    let mut stmt = conn
        .prepare(
            r#"
            SELECT active, credential_id, owner, fence, acquired_at, guard_expires_at
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
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    let Some((active, credential_id, owner_str, fence, acquired_at_str, guard_expires_at_str)) =
        row
    else {
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
    if persisted_u64(credential_id).map_err(|error| LeaseError::Backend(error.to_string()))?
        != lease.credential_id()
    {
        return Err(LeaseError::StaleFence);
    }
    let stored_owner = persisted_owner_id(owner_str)
        .map_err(|_| LeaseError::Backend("persisted session owner is invalid".to_string()))?;
    if stored_owner != *lease.owner() {
        return Err(LeaseError::AlreadyHeld);
    }

    let guard_expires_at =
        persisted_normalized_timestamp(Some(guard_expires_at_str)).ok_or(LeaseError::StaleFence)?;
    let acquired_at = persisted_normalized_timestamp(acquired_at_str)
        .filter(|acquired_at| *acquired_at <= guard_expires_at)
        .ok_or(LeaseError::StaleFence)?;

    if persisted_u64(fence).map_err(|error| LeaseError::Backend(error.to_string()))?
        != lease.fence().get()
        || guard_expires_at != lease.expires_at()
        || acquired_at != lease.acquired_at()
    {
        return Err(LeaseError::StaleFence);
    }

    if guard_expires_at <= now {
        return Err(LeaseError::Expired);
    }

    let fence_token = lease.fence();
    let expires_at_unix_ms = timestamp_unix_millis(expires_at)
        .map_err(|error| LeaseError::Backend(error.to_string()))?;

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
        persisted_u64(credential_id).map_err(|error| LeaseError::Backend(error.to_string()))?,
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
            SELECT active, credential_id, owner, fence, acquired_at, guard_expires_at
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
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|e| LeaseError::Backend(e.to_string()))?;

    let Some((active, credential_id, owner_str, fence, acquired_at_str, guard_expires_at_str)) =
        row
    else {
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
    if persisted_u64(credential_id).map_err(|error| LeaseError::Backend(error.to_string()))?
        != lease.credential_id()
    {
        return Err(LeaseError::StaleFence);
    }
    let stored_owner = persisted_owner_id(owner_str)
        .map_err(|_| LeaseError::Backend("persisted session owner is invalid".to_string()))?;
    if stored_owner != *lease.owner() {
        return Err(LeaseError::AlreadyHeld);
    }

    let guard_expires_at =
        persisted_normalized_timestamp(Some(guard_expires_at_str)).ok_or(LeaseError::StaleFence)?;
    let acquired_at = persisted_normalized_timestamp(acquired_at_str)
        .filter(|acquired_at| *acquired_at <= guard_expires_at)
        .ok_or(LeaseError::StaleFence)?;

    if persisted_u64(fence).map_err(|error| LeaseError::Backend(error.to_string()))?
        != lease.fence().get()
        || guard_expires_at != lease.expires_at()
        || acquired_at != lease.acquired_at()
    {
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    use super::*;
    use crate::sqlite::{ops, SqliteSessionBackend};

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("lease-acquired-at-test"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: crate::SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"lease-acquired-at")
                .try_into()
                .expect("valid stable ID"),
        }
    }

    fn timestamp(second: u8) -> Timestamp {
        Timestamp::from_str(&format!("2026-07-12T00:00:{second:02}Z"))
            .expect("valid fixture timestamp")
    }

    fn lease_row(conn: &Connection) -> (i32, Option<String>, i64, String) {
        conn.query_row(
            "SELECT active, acquired_at, expires_at_unix_ms, guard_expires_at FROM leases",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read lease row")
    }

    #[test]
    fn forged_acquired_at_is_stale_and_cannot_renew_or_release() {
        let conn = SqliteSessionBackend::canonical_schema_connection().expect("schema");
        let lease = acquire_sync(
            &conn,
            &key(),
            OwnerId::new("lease-acquired-at-owner").expect("owner"),
            Duration::from_secs(60),
            timestamp(1),
        )
        .expect("acquire lease");
        let forged = LeaseGuard::new(
            lease.key().clone(),
            lease.owner().clone(),
            lease.fence(),
            timestamp(2),
            lease.expires_at(),
            lease.credential_id(),
        );
        let before = lease_row(&conn);

        assert!(matches!(
            renew_sync(&conn, &forged, Duration::from_secs(60), timestamp(2)),
            Err(LeaseError::StaleFence)
        ));
        assert_eq!(lease_row(&conn), before);
        assert!(matches!(
            release_sync(&conn, forged, timestamp(2)),
            Err(LeaseError::StaleFence)
        ));
        assert_eq!(lease_row(&conn), before);
    }

    #[test]
    fn exact_renewal_keeps_the_persisted_acquisition_time() {
        let conn = SqliteSessionBackend::canonical_schema_connection().expect("schema");
        let lease = acquire_sync(
            &conn,
            &key(),
            OwnerId::new("lease-acquired-at-owner").expect("owner"),
            Duration::from_secs(60),
            timestamp(1),
        )
        .expect("acquire lease");

        let renewed = renew_sync(&conn, &lease, Duration::from_secs(60), timestamp(2))
            .expect("renew exact lease");
        assert_eq!(renewed.acquired_at(), lease.acquired_at());
        assert_eq!(
            lease_row(&conn).1,
            Some(format_rfc3339_normalized(lease.acquired_at()))
        );
    }

    #[test]
    fn nullable_legacy_marker_remains_reopenable_but_is_not_guard_authority() {
        let conn = SqliteSessionBackend::canonical_schema_connection().expect("schema");
        let lease = acquire_sync(
            &conn,
            &key(),
            OwnerId::new("lease-acquired-at-owner").expect("owner"),
            Duration::from_secs(60),
            timestamp(1),
        )
        .expect("acquire lease");
        conn.execute("UPDATE leases SET acquired_at = NULL", [])
            .expect("mark migrated legacy lease");
        let before = lease_row(&conn);

        assert!(matches!(
            ops::validate_fenced_mutation_sync(&conn, &lease, timestamp(2)),
            Err(crate::StoreError::StaleFence)
        ));
        assert!(matches!(
            renew_exact_sync(&conn, &lease, Duration::from_secs(60), timestamp(2)),
            Err(LeaseError::StaleFence)
        ));
        assert!(matches!(
            release_sync(&conn, lease, timestamp(2)),
            Err(LeaseError::StaleFence)
        ));
        assert_eq!(lease_row(&conn), before);
    }
}
