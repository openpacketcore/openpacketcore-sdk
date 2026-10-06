//! Immutable creation-time profile. Format six retains the established lane
//! layouts inside its own exact marker; it never opens a baseline store as an
//! extended store or rewrites the outer format when another lane activates.

use super::*;
use crate::FencedTransitionV2Profile;

pub(super) const DATABASE_FORMAT: i64 = 6;
const TABLE: &str = "consensus_fenced_transition_profile";
const SCHEMA: &str = r#"
CREATE TABLE consensus_fenced_transition_profile (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    profile_digest BLOB NOT NULL CHECK (typeof(profile_digest) = 'blob' AND length(profile_digest) = 32),
    layout_version INTEGER NOT NULL CHECK (layout_version BETWEEN 1 AND 5)
)
"#;

fn selected(conn: &Connection, attached: bool) -> io::Result<(FencedTransitionV2Profile, i64)> {
    let version = raw_persisted_schema_version_in_sync(conn, attached)?;
    let present = if attached {
        attached_snapshot_table_exists(conn, TABLE)?
    } else {
        table_exists(conn, TABLE).map_err(db_error)?
    };
    if version != DATABASE_FORMAT {
        if present || !(1..=5).contains(&version) {
            return Err(invalid_data("fenced transition store profile mismatch"));
        }
        return Ok((FencedTransitionV2Profile::V2, version));
    }
    if !present || !schema_object_is_exact_in_sync(conn, attached, "table", TABLE, SCHEMA)? {
        return Err(invalid_data("fenced transition store profile mismatch"));
    }
    let source = if attached {
        "consensus_incoming.consensus_fenced_transition_profile"
    } else {
        "main.consensus_fenced_transition_profile"
    };
    let (count, digest, layout): (i64, Vec<u8>, i64) = conn.query_row(
        &format!("SELECT (SELECT COUNT(*) FROM {source}), profile_digest, layout_version FROM {source} WHERE singleton=1"),
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(db_error)?;
    if count != 1
        || digest != FencedTransitionV2Profile::V2WithVoid.digest()
        || !(1..=5).contains(&layout)
    {
        return Err(invalid_data("fenced transition store profile mismatch"));
    }
    Ok((FencedTransitionV2Profile::V2WithVoid, layout))
}

pub(crate) fn fenced_transition_profile_in_sync(
    conn: &Connection,
    attached: bool,
) -> io::Result<FencedTransitionV2Profile> {
    selected(conn, attached).map(|(profile, _)| profile)
}

pub(super) fn layout(conn: &Connection, attached: bool) -> io::Result<i64> {
    selected(conn, attached).map(|(_, layout)| layout)
}

/// The manifest budget follows the exact supported schema. It grants no
/// admission to an extra object unless the complete profile marker is valid.
pub(crate) fn schema_max_objects(conn: &Connection, attached: bool) -> io::Result<usize> {
    let present = if attached {
        attached_snapshot_table_exists(conn, TABLE)?
    } else {
        table_exists(conn, TABLE).map_err(db_error)?
    };
    if !present {
        return Ok(CONSENSUS_SCHEMA_MAX_OBJECTS);
    }
    selected(conn, attached)?;
    Ok(CONSENSUS_SCHEMA_MAX_OBJECTS + 1)
}

/// Called only inside the transaction which first creates consensus_identity.
pub(super) fn create(conn: &Connection, profile: FencedTransitionV2Profile) -> io::Result<()> {
    if profile == FencedTransitionV2Profile::V2 {
        return Ok(());
    }
    conn.execute_batch(SCHEMA).map_err(db_error)?;
    conn.execute(
        "INSERT INTO consensus_fenced_transition_profile (singleton, profile_digest, layout_version) VALUES (1, ?1, 1)",
        [profile.digest().as_slice()],
    ).map_err(db_error)?;
    if conn
        .execute(
            "UPDATE consensus_identity SET schema_version=6 WHERE singleton=1 AND schema_version=1",
            [],
        )
        .map_err(db_error)?
        != 1
    {
        return Err(invalid_data(
            "fenced transition store profile creation failed",
        ));
    }
    Ok(())
}

pub(super) fn set_layout(
    conn: &Connection,
    layout: i64,
    activated: Option<bool>,
    predecessors: &[(i64, Option<bool>)],
) -> io::Result<usize> {
    let (profile, previous_layout) = selected(conn, false)?;
    let previous_activation: bool = conn
        .query_row(
            "SELECT fenced_transition_receipt_ledger_activated FROM consensus_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if layout < previous_layout
        || !predecessors
            .iter()
            .any(|(expected_layout, expected_activation)| {
                *expected_layout == previous_layout
                    && expected_activation.is_none_or(|expected| expected == previous_activation)
            })
    {
        return Ok(0);
    }
    let version = match profile {
        FencedTransitionV2Profile::V2 => layout,
        FencedTransitionV2Profile::V2WithVoid => {
            let changed = conn.execute(
                "UPDATE consensus_fenced_transition_profile SET layout_version=?1 WHERE singleton=1 AND layout_version=?2 AND profile_digest=?3 AND EXISTS (SELECT 1 FROM consensus_identity WHERE singleton=1 AND schema_version=6 AND fenced_transition_receipt_ledger_activated=?4)",
                params![layout, previous_layout, profile.digest().as_slice(), previous_activation],
            ).map_err(db_error)?;
            if changed != 1 {
                return Ok(0);
            }
            DATABASE_FORMAT
        }
    };
    conn.execute(
        "UPDATE consensus_identity SET schema_version=?1, fenced_transition_receipt_ledger_activated=coalesce(?2, fenced_transition_receipt_ledger_activated) WHERE singleton=1 AND schema_version=?3 AND fenced_transition_receipt_ledger_activated=?4",
        params![version, activated, if profile == FencedTransitionV2Profile::V2 {previous_layout} else {DATABASE_FORMAT}, previous_activation],
    ).map_err(db_error)
}

pub(super) fn copy_snapshot_layout(conn: &Connection) -> io::Result<()> {
    let local = fenced_transition_profile_in_sync(conn, false)?;
    if local != fenced_transition_profile_in_sync(conn, true)? {
        return Err(invalid_data(
            "snapshot cannot convert fenced transition store profile",
        ));
    }
    if local == FencedTransitionV2Profile::V2WithVoid {
        conn.execute(
            "UPDATE main.consensus_fenced_transition_profile SET layout_version=(SELECT layout_version FROM consensus_incoming.consensus_fenced_transition_profile WHERE singleton=1) WHERE singleton=1",
            [],
        ).map_err(db_error)?;
    }
    Ok(())
}
