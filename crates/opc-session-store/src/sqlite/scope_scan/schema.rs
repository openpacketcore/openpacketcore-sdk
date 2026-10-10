//! Exact, derived scan indexes. Their presence does not grant scope authority.

use rusqlite::Connection;
use std::io;

pub(crate) const INDEX_COUNT: usize = 2;
const MAX_INDEX_SQL_BYTES: i64 = 4 * 1024;
const INDEXES: [(&str, &str); INDEX_COUNT] = [
    (
        "scope_scan_keys",
        "CREATE INDEX scope_scan_keys
         ON session_records(tenant,nf_kind,key_type,stable_id)
         WHERE typeof(stable_id)='blob' AND length(stable_id)=64
         AND key_type IN ('opc-scope-child','opc-scope-claim')",
    ),
    (
        "scope_scan_bad_keys",
        "CREATE INDEX scope_scan_bad_keys
         ON session_records(tenant,nf_kind,key_type,
            CASE WHEN typeof(stable_id)='blob' AND length(stable_id)>=32
            THEN substr(stable_id,1,32) ELSE x'' END)
         WHERE (typeof(stable_id)!='blob' OR length(stable_id)!=64)
         AND key_type IN ('opc-scope-child','opc-scope-claim')",
    ),
];

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "scope scan index schema differs",
    )
}

fn normalized(sql: &str) -> impl Iterator<Item = char> + '_ {
    let mut quoted = false;
    sql.trim()
        .trim_end_matches(';')
        .chars()
        .filter(move |character| {
            if *character == '\'' {
                quoted = !quoted;
            }
            quoted || !character.is_ascii_whitespace()
        })
}

pub(crate) fn is_index_name(name: &str) -> bool {
    INDEXES.iter().any(|(expected, _)| *expected == name)
}

pub(crate) fn matches_definition(name: &str, sql: &str) -> bool {
    sql.len() <= MAX_INDEX_SQL_BYTES as usize
        && INDEXES.iter().any(|(expected_name, expected_sql)| {
            *expected_name == name && normalized(sql).eq(normalized(expected_sql))
        })
}

/// Recognize only the complete exact pair, or the layout before these derived
/// indexes existed. Read-only inspection never installs or repairs an index.
pub(crate) fn optional_object_count(conn: &Connection, attached: bool) -> io::Result<usize> {
    let master = if attached {
        "consensus_incoming.sqlite_master"
    } else {
        "main.sqlite_master"
    };
    let mut statement = conn
        .prepare(&format!(
            "SELECT name, type='index' AND tbl_name='session_records',
             CASE WHEN typeof(sql)='text' AND octet_length(sql)<=?1 THEN sql END
             FROM {master} WHERE name IN ('scope_scan_keys','scope_scan_bad_keys')
             ORDER BY name LIMIT 3"
        ))
        .map_err(|_| invalid())?;
    let mut rows = statement
        .query([MAX_INDEX_SQL_BYTES])
        .map_err(|_| invalid())?;
    let mut seen = 0u8;
    while let Some(row) = rows.next().map_err(|_| invalid())? {
        let name: String = row.get(0).map_err(|_| invalid())?;
        let is_index: bool = row.get(1).map_err(|_| invalid())?;
        let sql: Option<String> = row.get(2).map_err(|_| invalid())?;
        let bit = match name.as_str() {
            "scope_scan_keys" => 1,
            "scope_scan_bad_keys" => 2,
            _ => return Err(invalid()),
        };
        if seen & bit != 0 || !is_index || !sql.is_some_and(|sql| matches_definition(&name, &sql)) {
            return Err(invalid());
        }
        seen |= bit;
    }
    match seen {
        0 => Ok(0),
        3 => Ok(INDEX_COUNT),
        _ => Err(invalid()),
    }
}

pub(crate) fn install(conn: &Connection) -> io::Result<()> {
    for (_, sql) in INDEXES {
        conn.execute_batch(&sql.replacen("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1))
            .map_err(|_| invalid())?;
    }
    if optional_object_count(conn, false)? != INDEX_COUNT {
        return Err(invalid());
    }
    Ok(())
}
