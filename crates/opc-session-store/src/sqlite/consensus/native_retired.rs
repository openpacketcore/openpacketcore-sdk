//! Portable exact key-retirement tags. Epochs are unsigned, fixed-width blobs;
//! their canonical big-endian encoding also orders the epoch index.

use super::*;
use crate::key_retention::{KeyRetention, RETIRED_KEYS_PER_EPOCH};
use rusqlite::types::ValueRef;

const TABLE: &str = "consensus_native_retired_keys";
const SCHEMA: &str = "CREATE TABLE consensus_native_retired_keys (tenant TEXT NOT NULL, nf_kind TEXT NOT NULL, key_type TEXT NOT NULL, stable_id BLOB NOT NULL, epoch BLOB NOT NULL CHECK(length(epoch) = 8), PRIMARY KEY(tenant,nf_kind,key_type,stable_id)) WITHOUT ROWID";
const INDEX: &str = "consensus_native_retired_epoch";
const INDEX_SCHEMA: &str = "CREATE INDEX consensus_native_retired_epoch ON consensus_native_retired_keys(epoch,tenant,nf_kind,key_type,stable_id)";

pub(crate) fn exists(conn: &Connection) -> io::Result<bool> {
    let mut found = false;
    for (name, kind, expected) in [(TABLE, "table", SCHEMA), (INDEX, "index", INDEX_SCHEMA)] {
        let schema: Option<(String, String)> = conn
            .query_row(
                "SELECT type,sql FROM sqlite_schema WHERE name=?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db_error)?;
        if name == TABLE {
            found = schema.is_some();
        }
        if schema
            .as_ref()
            .is_some_and(|(actual_kind, sql)| actual_kind != kind || sql != expected)
            || schema.is_some() != found
        {
            return Err(invalid_data("native retired-key snapshot schema differs"));
        }
    }
    Ok(found)
}

pub(crate) fn create(tx: &Transaction<'_>) -> io::Result<()> {
    if !exists(tx)? {
        tx.execute_batch(SCHEMA).map_err(db_error)?;
        tx.execute_batch(INDEX_SCHEMA).map_err(db_error)?;
    }
    Ok(())
}

fn epoch(bytes: &[u8]) -> io::Result<u64> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
        invalid_data("native retired-key epoch extent differs")
    })?))
}

pub(crate) fn read(conn: &Connection, key: &SessionKey) -> io::Result<Option<u64>> {
    if !table_exists(conn, TABLE).map_err(db_error)? {
        return Ok(None);
    }
    conn.query_row(
        "SELECT epoch FROM consensus_native_retired_keys WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3 AND stable_id=?4",
        params![key.tenant.as_str(),key.nf_kind.as_str(),key.key_type.to_string(),key.stable_id.as_ref()],
        |row| row.get::<_, Vec<u8>>(0),
    ).optional().map_err(db_error)?.as_deref().map(epoch).transpose()
}

pub(crate) fn insert(tx: &Transaction<'_>, key: &SessionKey, retired_epoch: u64) -> io::Result<()> {
    tx.execute(
        "INSERT INTO consensus_native_retired_keys (tenant,nf_kind,key_type,stable_id,epoch) VALUES (?1,?2,?3,?4,?5)",
        params![key.tenant.as_str(),key.nf_kind.as_str(),key.key_type.to_string(),key.stable_id.as_ref(),retired_epoch.to_be_bytes().as_slice()],
    ).map_err(db_error)?;
    Ok(())
}

fn key(row: &rusqlite::Row<'_>) -> io::Result<SessionKey> {
    for (column, maximum) in [
        128,
        64,
        crate::model::SESSION_KEY_TYPE_MAX_BYTES,
        crate::model::STABLE_ID_MAX_BYTES,
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = match row.get_ref(column).map_err(db_error)? {
            ValueRef::Text(bytes) if column < 3 => bytes,
            ValueRef::Blob(bytes) if column == 3 => bytes,
            _ => return Err(invalid_data("native retired-key component type differs")),
        };
        if bytes.len() > maximum {
            return Err(invalid_data(
                "native retired-key component exceeds model bound",
            ));
        }
    }
    ops::persisted_session_key(
        row.get(0).map_err(db_error)?,
        row.get(1).map_err(db_error)?,
        row.get(2).map_err(db_error)?,
        row.get(3).map_err(db_error)?,
    )
    .map_err(|_| invalid_data("native retired-key identity invalid"))
}

pub(crate) fn validate(
    conn: &Connection,
    retention: KeyRetention,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    if !exists(conn)? {
        if retention != KeyRetention::default() {
            return Err(invalid_data(
                "native retirement snapshot tag namespace absent",
            ));
        }
        return Ok(());
    }
    let mut statement = conn.prepare(
        "SELECT r.tenant,r.nf_kind,r.key_type,r.stable_id,r.epoch,f.fence,EXISTS(SELECT 1 FROM leases l WHERE l.tenant=r.tenant AND l.nf_kind=r.nf_kind AND l.key_type=r.key_type AND l.stable_id=r.stable_id),EXISTS(SELECT 1 FROM session_records s WHERE s.tenant=r.tenant AND s.nf_kind=r.nf_kind AND s.key_type=r.key_type AND s.stable_id=r.stable_id) FROM consensus_native_retired_keys r LEFT JOIN key_fences f USING (tenant,nf_kind,key_type,stable_id) ORDER BY r.epoch,r.tenant,r.nf_kind,r.key_type,r.stable_id"
    ).map_err(db_error)?;
    let mut rows = statement.query([]).map_err(db_error)?;
    let mut current = 0u64;
    let mut previous = 0u64;
    while let Some(row) = rows.next().map_err(db_error)? {
        check()?;
        let key = key(row)?;
        let ValueRef::Blob(bytes) = row.get_ref(4).map_err(db_error)? else {
            return Err(invalid_data("native retired-key epoch type differs"));
        };
        let retired_epoch = epoch(bytes)?;
        let fence = row.get::<_, u64>(5).map_err(db_error)?;
        if !retention.valid_retired_fence(retired_epoch, fence)
            || crate::scope_storage::is_scope_record_key(&key)
            || row.get::<_, bool>(6).map_err(db_error)?
            || row.get::<_, bool>(7).map_err(db_error)?
            || crate::sqlite::consensus::native_snapshot::reserved(conn, &key)?
        {
            return Err(invalid_data(
                "native retired-key row is not exact dead history",
            ));
        }
        if retired_epoch == retention.epoch {
            current += 1;
            if current > retention.retired_count || fence > retention.retired_max {
                return Err(invalid_data("native current retirement counters differ"));
            }
        } else {
            previous += 1;
        }
        if current > RETIRED_KEYS_PER_EPOCH || previous > RETIRED_KEYS_PER_EPOCH {
            return Err(invalid_data("native retired-key window exceeds bound"));
        }
    }
    Ok(())
}

pub(crate) fn replace(
    tx: &Transaction<'_>,
    source: &Connection,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    if exists(tx)? {
        tx.execute("DELETE FROM consensus_native_retired_keys", [])
            .map_err(db_error)?;
    }
    if !exists(source)? {
        return Ok(());
    }
    create(tx)?;
    let mut statement = source.prepare("SELECT tenant,nf_kind,key_type,stable_id,epoch FROM consensus_native_retired_keys ORDER BY epoch,tenant,nf_kind,key_type,stable_id").map_err(db_error)?;
    let mut rows = statement.query([]).map_err(db_error)?;
    let mut count = 0u64;
    while let Some(row) = rows.next().map_err(db_error)? {
        check()?;
        count += 1;
        if count > 2 * RETIRED_KEYS_PER_EPOCH {
            return Err(invalid_data("native retired-key window exceeds bound"));
        }
        let key = key(row)?;
        let ValueRef::Blob(bytes) = row.get_ref(4).map_err(db_error)? else {
            return Err(invalid_data("native retired-key epoch type differs"));
        };
        insert(tx, &key, epoch(bytes)?)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_retired_tests.rs"]
mod tests;
