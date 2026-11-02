//! Canonical replay floors in a native portable snapshot. The ordinary SQL
//! backend does not retire native history or manufacture these frontiers.

use super::*;
use crate::consensus::native::retention::Retention;
use rusqlite::types::ValueRef;

const TABLE: &str = "consensus_native_retention";
const SCHEMA: &str = "CREATE TABLE consensus_native_retention (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), frontiers BLOB NOT NULL CHECK(length(frontiers) BETWEEN 1 AND 4096))";

pub(crate) fn read(conn: &Connection) -> io::Result<Option<Retention>> {
    let mut schema = conn
        .prepare("SELECT type, sql FROM sqlite_schema WHERE name = ?1")
        .map_err(db_error)?;
    let mut rows = schema.query([TABLE]).map_err(db_error)?;
    let Some(row) = rows.next().map_err(db_error)? else {
        return Ok(None);
    };
    if row.get_ref(0).map_err(db_error)? != ValueRef::Text(b"table")
        || row.get_ref(1).map_err(db_error)? != ValueRef::Text(SCHEMA.as_bytes())
        || rows.next().map_err(db_error)?.is_some()
    {
        return Err(invalid_data("native retention snapshot schema differs"));
    }
    let mut statement = conn
        .prepare("SELECT singleton, frontiers FROM consensus_native_retention")
        .map_err(db_error)?;
    let mut rows = statement.query([]).map_err(db_error)?;
    let row = rows
        .next()
        .map_err(db_error)?
        .ok_or_else(|| invalid_data("native retention snapshot frontiers absent"))?;
    if row.get_ref(0).map_err(db_error)? != ValueRef::Integer(1) {
        return Err(invalid_data("native retention snapshot singleton differs"));
    }
    let ValueRef::Blob(bytes) = row.get_ref(1).map_err(db_error)? else {
        return Err(invalid_data(
            "native retention snapshot frontiers type differs",
        ));
    };
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(invalid_data(
            "native retention snapshot frontiers extent differs",
        ));
    }
    let frontiers: Retention = serde_json::from_slice(bytes)
        .map_err(|_| invalid_data("native retention snapshot frontiers malformed"))?;
    if serde_json::to_vec(&frontiers)
        .map_err(|_| invalid_data("native retention encoding failed"))?
        != bytes
        || rows.next().map_err(db_error)?.is_some()
    {
        return Err(invalid_data(
            "native retention snapshot frontiers are not canonical",
        ));
    }
    Ok(Some(frontiers))
}

pub(crate) fn write(tx: &Transaction<'_>, frontiers: Retention) -> io::Result<()> {
    let before = read(tx)?;
    before.unwrap_or_default().transition(frontiers)?;
    // This namespace identifies the native replay profile even at genesis:
    // an ordinary command can request retirement before its first dead key.
    if before.is_none() {
        tx.execute_batch(SCHEMA).map_err(db_error)?;
    }
    let bytes = serde_json::to_vec(&frontiers)
        .map_err(|_| invalid_data("native retention encoding failed"))?;
    tx.execute(
        "INSERT OR REPLACE INTO consensus_native_retention (singleton, frontiers) VALUES (1, ?1)",
        [bytes],
    )
    .map_err(db_error)?;
    Ok(())
}
