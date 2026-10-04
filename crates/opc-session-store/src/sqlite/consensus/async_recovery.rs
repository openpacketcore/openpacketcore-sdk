//! Exact optional recovery vocabulary in a native portable snapshot. Ordinary
//! SQL execution never constructs or consumes this authority boundary.

use super::*;
use crate::consensus::native::async_recovery::Boundary;

const TABLE: &str = "consensus_async_recovery";
const SCHEMA: &str = "CREATE TABLE consensus_async_recovery (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), boundary BLOB NOT NULL CHECK(length(boundary) BETWEEN 1 AND 65536))";
const MAX_BYTES: usize = 65536;

pub(crate) fn read(conn: &Connection) -> io::Result<Option<Boundary>> {
    let mut schema = conn
        .prepare("SELECT type, sql FROM sqlite_schema WHERE name = ?1")
        .map_err(db_error)?;
    let mut rows = schema.query([TABLE]).map_err(db_error)?;
    let Some(row) = rows.next().map_err(db_error)? else {
        return Ok(None);
    };
    use rusqlite::types::ValueRef;
    if row.get_ref(0).map_err(db_error)? != ValueRef::Text(b"table")
        || row.get_ref(1).map_err(db_error)? != ValueRef::Text(SCHEMA.as_bytes())
        || rows.next().map_err(db_error)?.is_some()
    {
        return Err(invalid_data("native asynchronous snapshot schema differs"));
    }
    let mut statement = conn
        .prepare("SELECT singleton, boundary FROM consensus_async_recovery")
        .map_err(db_error)?;
    let mut rows = statement.query([]).map_err(db_error)?;
    let row = rows
        .next()
        .map_err(db_error)?
        .ok_or_else(|| invalid_data("native asynchronous snapshot boundary absent"))?;
    if row.get_ref(0).map_err(db_error)? != ValueRef::Integer(1) {
        return Err(invalid_data(
            "native asynchronous snapshot singleton differs",
        ));
    }
    let ValueRef::Blob(bytes) = row.get_ref(1).map_err(db_error)? else {
        return Err(invalid_data(
            "native asynchronous snapshot boundary type differs",
        ));
    };
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(invalid_data(
            "native asynchronous snapshot boundary extent differs",
        ));
    }
    let boundary: Boundary = serde_json::from_slice(bytes)
        .map_err(|_| invalid_data("native asynchronous snapshot boundary malformed"))?;
    boundary.validate()?;
    if serde_json::to_vec(&boundary)
        .map_err(|_| invalid_data("native asynchronous snapshot encoding failed"))?
        != bytes
        || rows.next().map_err(db_error)?.is_some()
    {
        return Err(invalid_data(
            "native asynchronous snapshot boundary is not canonical",
        ));
    }
    Ok(Some(boundary))
}

pub(crate) fn transition(before: Option<&Boundary>, after: Option<&Boundary>) -> io::Result<()> {
    if let Some(prior) = before {
        let next =
            after.ok_or_else(|| invalid_data("native asynchronous snapshot boundary removed"))?;
        if next != prior
            && (next.era <= prior.era
                || next.applied.index <= prior.applied.index
                || next.applied.leader_id <= prior.applied.leader_id)
        {
            return Err(invalid_data(
                "native asynchronous snapshot boundary regressed",
            ));
        }
    }
    if let Some(boundary) = after {
        boundary.validate()?;
    }
    Ok(())
}

pub(crate) fn write(tx: &Transaction<'_>, boundary: Option<&Boundary>) -> io::Result<()> {
    let before = read(tx)?;
    transition(before.as_ref(), boundary)?;
    let Some(boundary) = boundary else {
        return Ok(());
    };
    let bytes = serde_json::to_vec(boundary)
        .map_err(|_| invalid_data("native asynchronous snapshot encoding failed"))?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid_data(
            "native asynchronous snapshot boundary extent differs",
        ));
    }
    if before.is_none() {
        tx.execute_batch(SCHEMA).map_err(db_error)?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO consensus_async_recovery (singleton, boundary) VALUES (1, ?1)",
        [bytes],
    )
    .map_err(db_error)?;
    Ok(())
}
