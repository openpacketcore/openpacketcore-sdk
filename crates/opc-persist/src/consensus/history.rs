//! Bounded retained configuration history owned by the existing consensus writer.

use opc_types::{ConfigVersion, TxId};
use serde::{Deserialize, Serialize};

use crate::PersistError;

use std::io;

use hmac::{Hmac, Mac};
use opc_consensus::ConsensusIdentity;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use super::types::ConfigMutationFailure;
use crate::AuditKey;

const HISTORY_DOMAIN: &[u8] = b"openpacketcore/config-consensus/history-retention/v1\0";
const STATE_MAX_BYTES: usize = 4096;

/// Explicit bounds for canonical retained configuration records and their data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigHistoryLimits {
    max_records: u32,
    max_bytes: u64,
}

impl ConfigHistoryLimits {
    /// Admit at least a current record and its rollback predecessor. The byte
    /// limit includes retained record metadata, ciphertext and associated audit.
    pub fn new(max_records: u32, max_bytes: u64) -> Result<Self, PersistError> {
        if !(2..=1_000_000).contains(&max_records) || !(1..=1_073_741_824).contains(&max_bytes) {
            return Err(PersistError::constraint_violation(
                "invalid config history limits",
            ));
        }
        Ok(Self {
            max_records,
            max_bytes,
        })
    }

    /// Maximum retained complete records.
    pub const fn max_records(self) -> u32 {
        self.max_records
    }

    /// Maximum aggregate retained encoded data bytes.
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }
}

/// An explicit retention decision for one exact committed head.
///
/// The authority caller must have resolved all operations and external history
/// references through `acknowledged_through`. Observation, restart and time do
/// not imply this acknowledgement. SDK-owned pending and rollback references
/// independently prevent pruning. The acknowledgement is not worker application
/// or serving authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigHistoryRetention {
    pub(crate) expected_head: TxId,
    pub(crate) expected_version: ConfigVersion,
    pub(crate) acknowledged_through: ConfigVersion,
    pub(crate) retain_from: ConfigVersion,
    pub(crate) limits: ConfigHistoryLimits,
}

impl ConfigHistoryRetention {
    /// Bind bounded pruning to the exact observed head and independently
    /// acknowledged prefix. Keep at least the head and its predecessor.
    pub fn new(
        expected_head: TxId,
        expected_version: ConfigVersion,
        acknowledged_through: ConfigVersion,
        retain_from: ConfigVersion,
        limits: ConfigHistoryLimits,
    ) -> Result<Self, PersistError> {
        let value = Self {
            expected_head,
            expected_version,
            acknowledged_through,
            retain_from,
            limits,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), PersistError> {
        ConfigHistoryLimits::new(self.limits.max_records, self.limits.max_bytes)?;
        if self.retain_from.get() == 0
            || self.retain_from.get() >= self.expected_version.get()
            || self.acknowledged_through.get() >= self.expected_version.get()
            || self.retain_from.get() - 1 > self.acknowledged_through.get()
        {
            return Err(PersistError::constraint_violation(
                "invalid config history boundary",
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for ConfigHistoryRetention {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfigHistoryRetention(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryHead {
    tx_id: TxId,
    version: ConfigVersion,
    encrypted_digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryBoundary {
    first: HistoryHead,
    original_parent: TxId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryState {
    format_version: u16,
    identity: ConsensusIdentity,
    key_epoch: u64,
    limits: Option<ConfigHistoryLimits>,
    acknowledged_through: Option<ConfigVersion>,
    boundary: Option<HistoryBoundary>,
    head: Option<HistoryHead>,
    records: u64,
}

fn corrupt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid authenticated config history",
    )
}

fn database_error(_: rusqlite::Error) -> io::Error {
    io::Error::other("config history storage unavailable")
}

fn persist_error(_: io::Error) -> PersistError {
    PersistError::corrupt_blob()
}

fn history_mac(key: &AuditKey, bytes: &[u8]) -> io::Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| corrupt())?;
    mac.update(HISTORY_DOMAIN);
    mac.update(bytes);
    Ok(mac)
}

fn record_count(conn: &Connection) -> io::Result<u64> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
        .map_err(database_error)?;
    u64::try_from(count).map_err(|_| corrupt())
}

fn head_sync(conn: &Connection) -> io::Result<Option<HistoryHead>> {
    let row = conn.query_row(
        "SELECT tx_id, version, encrypted_blob FROM config_history ORDER BY version DESC LIMIT 1",
        [], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?)),
    ).optional().map_err(database_error)?;
    row.map(|(tx_id, version, encrypted)| {
        Ok(HistoryHead {
            tx_id: TxId::from_uuid(uuid::Uuid::from_slice(&tx_id).map_err(|_| corrupt())?),
            version: ConfigVersion::new(u64::try_from(version).map_err(|_| corrupt())?),
            encrypted_digest: Sha256::digest(encrypted).into(),
        })
    })
    .transpose()
}

fn save_state(conn: &Connection, key: &AuditKey, state: &HistoryState) -> io::Result<()> {
    let encoded = serde_json::to_vec(state).map_err(|_| corrupt())?;
    if encoded.len() > STATE_MAX_BYTES {
        return Err(corrupt());
    }
    let tag = history_mac(key, &encoded)?.finalize().into_bytes();
    conn.execute(
        "INSERT INTO config_raft_history_retention (singleton, state_json, state_hmac) VALUES (1, ?1, ?2) ON CONFLICT(singleton) DO UPDATE SET state_json = excluded.state_json, state_hmac = excluded.state_hmac",
        params![encoded, tag.as_slice()],
    ).map_err(database_error)?;
    Ok(())
}

/// Called only in the existing new-authority/approved recovery transaction.
pub(crate) fn initialize_sync(
    conn: &Connection,
    identity: ConsensusIdentity,
    key: &AuditKey,
) -> io::Result<()> {
    save_state(
        conn,
        key,
        &HistoryState {
            format_version: 1,
            identity,
            key_epoch: key.epoch(),
            limits: None,
            acknowledged_through: None,
            boundary: None,
            head: head_sync(conn)?,
            records: record_count(conn)?,
        },
    )
}

fn load_state(conn: &Connection, key: &AuditKey) -> io::Result<Option<HistoryState>> {
    let consensus: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'config_raft_identity')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    if !consensus {
        return Ok(None);
    }
    let (encoded, tag): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT state_json, state_hmac FROM config_raft_history_retention WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(database_error)?;
    if encoded.len() > STATE_MAX_BYTES {
        return Err(corrupt());
    }
    history_mac(key, &encoded)?
        .verify_slice(&tag)
        .map_err(|_| corrupt())?;
    let state: HistoryState = serde_json::from_slice(&encoded).map_err(|_| corrupt())?;
    let (cluster, configuration, epoch): (Vec<u8>, Vec<u8>, i64) = conn.query_row(
        "SELECT cluster_id, configuration_id, configuration_epoch FROM config_raft_identity WHERE singleton = 1",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(database_error)?;
    if state.format_version != 1
        || state.key_epoch != key.epoch()
        || state.identity.cluster_id().as_bytes().as_slice() != cluster
        || state.identity.configuration_id().as_bytes().as_slice() != configuration
        || u64::try_from(epoch).ok() != Some(state.identity.configuration_epoch().get())
    {
        return Err(corrupt());
    }
    if let Some(limits) = state.limits {
        ConfigHistoryLimits::new(limits.max_records, limits.max_bytes).map_err(|_| corrupt())?;
    }
    if let Some(boundary) = &state.boundary {
        if state.limits.is_none()
            || boundary.first.version.get() == 0
            || state
                .acknowledged_through
                .is_none_or(|ack| ack.get() < boundary.first.version.get() - 1)
            || state
                .head
                .as_ref()
                .is_none_or(|head| head.version < boundary.first.version)
        {
            return Err(corrupt());
        }
    }
    Ok(Some(state))
}

fn validate_state(conn: &Connection, state: &HistoryState) -> io::Result<()> {
    if head_sync(conn)? != state.head || record_count(conn)? != state.records {
        return Err(corrupt());
    }
    if let Some(boundary) = &state.boundary {
        let (first_tx, first_version, parent, blob): (Vec<u8>, i64, Option<Vec<u8>>, Vec<u8>) = conn.query_row(
            "SELECT tx_id, version, parent_tx_id, encrypted_blob FROM config_history ORDER BY version ASC LIMIT 1",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).map_err(database_error)?;
        if first_tx != boundary.first.tx_id.as_uuid().as_bytes()
            || u64::try_from(first_version).ok() != Some(boundary.first.version.get())
            || parent.is_some()
            || <[u8; 32]>::from(Sha256::digest(blob)) != boundary.first.encrypted_digest
        {
            return Err(corrupt());
        }
    }
    Ok(())
}

/// Restore the original AEAD-bound predecessor of the surviving first record.
/// SQLite's parent link describes only retained rows; the authenticated boundary
/// owns the removed predecessor. All external record projections retain it.
pub(crate) fn original_parent_sync(
    conn: &Connection,
    key: &AuditKey,
    tx_id: &[u8],
    version: i64,
    parent: Option<Vec<u8>>,
) -> io::Result<Option<Vec<u8>>> {
    let Some(state) = load_state(conn, key)? else {
        return Ok(parent);
    };
    validate_state(conn, &state)?;
    if let Some(boundary) = state.boundary {
        if u64::try_from(version).ok() == Some(boundary.first.version.get()) {
            if tx_id != boundary.first.tx_id.as_uuid().as_bytes() || parent.is_some() {
                return Err(corrupt());
            }
            return Ok(Some(boundary.original_parent.as_uuid().as_bytes().to_vec()));
        }
    }
    Ok(parent)
}

pub(crate) fn floor_sync(
    conn: &Connection,
    key: &AuditKey,
) -> Result<Option<ConfigVersion>, PersistError> {
    let Some(state) = load_state(conn, key).map_err(persist_error)? else {
        return Ok(None);
    };
    validate_state(conn, &state).map_err(persist_error)?;
    Ok(state.limits.map(|_| {
        state.boundary.map_or(ConfigVersion::new(0), |boundary| {
            ConfigVersion::new(boundary.first.version.get() - 1)
        })
    }))
}

pub(crate) fn validate_cursor_sync(
    conn: &Connection,
    key: &AuditKey,
    cursor: ConfigVersion,
) -> Result<(), PersistError> {
    if floor_sync(conn, key)?.is_some_and(|floor| cursor < floor) {
        return Err(PersistError::config_history_compacted());
    }
    Ok(())
}

fn retained_size(conn: &Connection, before: Option<i64>) -> io::Result<(u64, u64)> {
    // Bound encoded canonical data, including conservative fixed metadata per
    // row; SQLite/Raft physical storage has its separate admission/snapshot policy.
    let (records, bytes): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(256 + length(CAST(principal AS BLOB)) + length(CAST(committed_at AS BLOB)) + length(encrypted_blob) + length(plaintext_digest) + length(schema_digest)), 0) FROM config_history WHERE (?1 IS NULL OR version < ?1)",
        [before], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(database_error)?;
    let audit: i64 = conn.query_row(
        "SELECT COALESCE(SUM(128 + length(CAST(a.yang_path AS BLOB)) + COALESCE(length(CAST(a.previous_value AS BLOB)),0) + COALESCE(length(CAST(a.new_value AS BLOB)),0)),0) FROM audit_trail a JOIN config_history h ON h.tx_id = a.tx_id WHERE (?1 IS NULL OR h.version < ?1)",
        [before], |row| row.get(0),
    ).map_err(database_error)?;
    let lifecycle: i64 = conn.query_row(
        "SELECT COALESCE(SUM(128 + length(CAST(a.action AS BLOB)) + length(CAST(a.principal AS BLOB)) + length(CAST(a.occurred_at AS BLOB)) + length(CAST(a.details AS BLOB))),0) FROM config_lifecycle_audit a JOIN config_history h ON h.tx_id = a.tx_id WHERE (?1 IS NULL OR h.version < ?1)",
        [before], |row| row.get(0),
    ).map_err(database_error)?;
    let labels: i64 = conn.query_row(
        "SELECT COALESCE(SUM(64 + length(CAST(a.label AS BLOB)) + length(CAST(a.created_at AS BLOB))),0) FROM rollback_labels a JOIN config_history h ON h.tx_id = a.tx_id WHERE (?1 IS NULL OR h.version < ?1)",
        [before], |row| row.get(0),
    ).map_err(database_error)?;
    let bytes = bytes
        .checked_add(audit)
        .and_then(|v| v.checked_add(lifecycle))
        .and_then(|v| v.checked_add(labels))
        .ok_or_else(corrupt)?;
    Ok((
        u64::try_from(records).map_err(|_| corrupt())?,
        u64::try_from(bytes).map_err(|_| corrupt())?,
    ))
}

pub(crate) fn validate_sync(conn: &Connection, key: &AuditKey) -> io::Result<()> {
    if let Some(state) = load_state(conn, key)? {
        validate_state(conn, &state)?;
        if let Some(limits) = state.limits {
            let (records, bytes) = retained_size(conn, None)?;
            if records > u64::from(limits.max_records) || bytes > limits.max_bytes {
                return Err(corrupt());
            }
        }
    }
    Ok(())
}

/// Runs in the existing per-command SQLite savepoint after a possible mutation.
/// Capacity rejection rolls that savepoint back, including pending resolution.
pub(crate) fn refresh_sync(
    conn: &Connection,
    key: &AuditKey,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    let mut state = load_state(conn, key)?.ok_or_else(corrupt)?;
    if let Some(limits) = state.limits {
        let (records, bytes) = retained_size(conn, None)?;
        if records > u64::from(limits.max_records) || bytes > limits.max_bytes {
            return Ok(Err(ConfigMutationFailure::HistoryFull));
        }
    }
    state.head = head_sync(conn)?;
    state.records = record_count(conn)?;
    save_state(conn, key, &state)?;
    Ok(Ok(()))
}

pub(crate) fn retain_sync(
    conn: &Connection,
    key: &AuditKey,
    decision: &ConfigHistoryRetention,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    if decision.validate().is_err() {
        return Ok(Err(ConfigMutationFailure::InvalidInput));
    }
    let mut state = load_state(conn, key)?.ok_or_else(corrupt)?;
    validate_state(conn, &state)?;
    if state.head.as_ref().is_none_or(|head| {
        head.tx_id != decision.expected_head || head.version != decision.expected_version
    }) || state
        .acknowledged_through
        .is_some_and(|ack| ack > decision.acknowledged_through)
        || state
            .boundary
            .as_ref()
            .is_some_and(|boundary| boundary.first.version > decision.retain_from)
    {
        return Ok(Err(ConfigMutationFailure::Conflict));
    }
    let from = i64::try_from(decision.retain_from.get()).map_err(|_| corrupt())?;
    let (first_tx, parent, encrypted): (Vec<u8>, Option<Vec<u8>>, Vec<u8>) = conn
        .query_row(
            "SELECT tx_id, parent_tx_id, encrypted_blob FROM config_history WHERE version = ?1",
            [from],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(database_error)?
        .ok_or_else(corrupt)?;
    // The head and its immediate predecessor always survive. A pending marker
    // on an older row was resolved by its successor's atomic confirm/rollback;
    // rollback intentionally does not set that historical row's confirmed_at.
    // Treating it as current pending authority would pin resolved history forever.
    let mut statement = conn.prepare(
        "SELECT principal, rollback_point FROM config_history WHERE version < ?1 ORDER BY version ASC",
    ).map_err(database_error)?;
    let rows = statement
        .query_map([from], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
        })
        .map_err(database_error)?;
    for row in rows {
        let (principal, rollback) = row.map_err(database_error)?;
        if rollback || crate::types::config_recovery_required(&principal).map_err(|_| corrupt())? {
            return Ok(Err(ConfigMutationFailure::HistoryProtected));
        }
    }
    drop(statement);
    // The public Previous rollback selector belongs to the latest resolved
    // configuration, which can precede a pending head. Preserve its target too.
    let previous_version: Option<i64> = conn.query_row(
        "SELECT p.version FROM config_history h JOIN config_history p ON p.tx_id = h.parent_tx_id WHERE (h.confirmed_at IS NOT NULL OR h.confirmed_deadline IS NULL) ORDER BY h.version DESC LIMIT 1",
        [], |row| row.get(0),
    ).optional().map_err(database_error)?;
    if previous_version.is_some_and(|version| version < from) {
        return Ok(Err(ConfigMutationFailure::HistoryProtected));
    }
    let named: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM rollback_labels l JOIN config_history h ON h.tx_id = l.tx_id WHERE h.version < ?1)",
        [from], |row| row.get(0),
    ).map_err(database_error)?;
    if named {
        return Ok(Err(ConfigMutationFailure::HistoryProtected));
    }
    let (all_records, all_bytes) = retained_size(conn, None)?;
    let (removed_records, removed_bytes) = retained_size(conn, Some(from))?;
    if all_records
        .checked_sub(removed_records)
        .ok_or_else(corrupt)?
        > u64::from(decision.limits.max_records)
        || all_bytes.checked_sub(removed_bytes).ok_or_else(corrupt)? > decision.limits.max_bytes
    {
        return Ok(Err(ConfigMutationFailure::HistoryFull));
    }
    if removed_records > 0 {
        let parent = parent.ok_or_else(corrupt)?;
        // Only the retained SQL graph is detached; the original predecessor
        // remains in the authenticated boundary and unchanged AEAD metadata.
        let original_parent =
            TxId::from_uuid(uuid::Uuid::from_slice(&parent).map_err(|_| corrupt())?);
        let previous: Vec<u8> = conn
            .query_row(
                "SELECT tx_id FROM config_history WHERE version = ?1",
                [from - 1],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if previous != parent {
            return Err(corrupt());
        }
        state.boundary = Some(HistoryBoundary {
            first: HistoryHead {
                tx_id: TxId::from_uuid(uuid::Uuid::from_slice(&first_tx).map_err(|_| corrupt())?),
                version: decision.retain_from,
                encrypted_digest: Sha256::digest(encrypted).into(),
            },
            original_parent,
        });
        conn.execute(
            "UPDATE config_history SET parent_tx_id = NULL WHERE tx_id = ?1",
            [&first_tx],
        )
        .map_err(database_error)?;
        conn.execute("DELETE FROM audit_trail WHERE tx_id IN (SELECT tx_id FROM config_history WHERE version < ?1)", [from]).map_err(database_error)?;
        conn.execute("DELETE FROM config_lifecycle_audit WHERE tx_id IN (SELECT tx_id FROM config_history WHERE version < ?1)", [from]).map_err(database_error)?;
        conn.execute("DELETE FROM config_history WHERE version < ?1", [from])
            .map_err(database_error)?;
    }
    state.records = record_count(conn)?;
    state.limits = Some(decision.limits);
    state.acknowledged_through = Some(decision.acknowledged_through);
    save_state(conn, key, &state)?;
    Ok(Ok(()))
}
