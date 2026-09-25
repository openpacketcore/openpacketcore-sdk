//! Bounded retained configuration history owned by the existing consensus writer.

use opc_types::{ConfigVersion, TxId};
use serde::{Deserialize, Serialize};

use crate::PersistError;

use std::io;

use hmac::{Hmac, KeyInit, Mac};
use opc_consensus::ConsensusIdentity;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::sqlite::SqliteWorkCancellation;
use super::types::ConfigMutationFailure;
use crate::AuditKey;

const HISTORY_DOMAIN: &[u8] = b"openpacketcore/config-consensus/history-retention/v1\0";
const RECORD_CHAIN_DOMAIN: &[u8] = b"openpacketcore/config-consensus/history-record-chain/v1\0";
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
    record_chain: [u8; 32],
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

fn empty_record_chain() -> [u8; 32] {
    Sha256::digest(RECORD_CHAIN_DOMAIN).into()
}

fn audit_anchor_digest(count: i64, terminal: &[u8]) -> io::Result<[u8; 32]> {
    let count = u32::try_from(count).map_err(|_| corrupt())?;
    if count as usize > super::types::CONFIG_AUDIT_RECORDS_MAX || terminal.len() != 32 {
        return Err(corrupt());
    }
    let mut digest = Sha256::new();
    digest.update(count.to_be_bytes());
    digest.update(terminal);
    Ok(digest.finalize().into())
}

fn record_metadata_digest(
    conn: &Connection,
    head: &HistoryHead,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<[u8; 32]> {
    use rusqlite::types::ValueRef;

    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/config-consensus/history-metadata/v1\0");
    // These closed queries bind the metadata that can authorize rollback,
    // publication and replay, plus its labels and lifecycle audit. They never
    // expose that content outside the existing persistence authority.
    for (domain, sql) in [
        (
            b"record\0".as_slice(),
            "SELECT parent_tx_id, committed_at, principal, source, schema_digest, plaintext_digest, rollback_point, rollback_label, confirmed_deadline, confirmed_at FROM config_history WHERE tx_id = ?1",
        ),
        (
            b"labels\0".as_slice(),
            "SELECT label, created_at FROM rollback_labels WHERE tx_id = ?1 ORDER BY label ASC",
        ),
        (
            b"lifecycle\0".as_slice(),
            "SELECT id, action, principal, occurred_at, details FROM config_lifecycle_audit WHERE tx_id = ?1 ORDER BY id ASC",
        ),
    ] {
        cancellation.check_io()?;
        digest.update(domain);
        let mut statement = conn.prepare(sql).map_err(database_error)?;
        let width = statement.column_count();
        let mut rows = statement
            .query([head.tx_id.as_uuid().as_bytes().as_slice()])
            .map_err(database_error)?;
        let mut count = 0_u64;
        while let Some(row) = rows.next().map_err(database_error)? {
            cancellation.check_io()?;
            count = count.checked_add(1).ok_or_else(corrupt)?;
            digest.update([1]);
            digest.update(u64::try_from(width).map_err(|_| corrupt())?.to_be_bytes());
            for index in 0..width {
                match row.get_ref(index).map_err(database_error)? {
                    ValueRef::Null => digest.update([0]),
                    ValueRef::Integer(value) => {
                        digest.update([1]);
                        digest.update(value.to_be_bytes());
                    }
                    ValueRef::Text(value) => {
                        digest.update([2]);
                        digest.update(
                            u64::try_from(value.len())
                                .map_err(|_| corrupt())?
                                .to_be_bytes(),
                        );
                        digest.update(value);
                    }
                    ValueRef::Blob(value) => {
                        digest.update([3]);
                        digest.update(
                            u64::try_from(value.len())
                                .map_err(|_| corrupt())?
                                .to_be_bytes(),
                        );
                        digest.update(value);
                    }
                    ValueRef::Real(_) => return Err(corrupt()),
                }
            }
        }
        digest.update([0]);
        digest.update(count.to_be_bytes());
    }
    Ok(digest.finalize().into())
}

fn extend_record_chain(
    previous: [u8; 32],
    head: &HistoryHead,
    audit_anchor: [u8; 32],
    metadata: [u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RECORD_CHAIN_DOMAIN);
    digest.update(previous);
    digest.update(head.tx_id.as_uuid().as_bytes());
    digest.update(head.version.get().to_be_bytes());
    digest.update(head.encrypted_digest);
    digest.update(audit_anchor);
    digest.update(metadata);
    digest.finalize().into()
}

fn record_chain_sync(
    conn: &Connection,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<[u8; 32]> {
    let mut statement = conn
        .prepare("SELECT tx_id, version, encrypted_blob, audit_count, audit_terminal_hash FROM config_history ORDER BY version ASC")
        .map_err(database_error)?;
    let mut rows = statement.query([]).map_err(database_error)?;
    let mut digest = empty_record_chain();
    loop {
        cancellation.check_io()?;
        let Some(row) = rows.next().map_err(database_error)? else {
            break;
        };
        let tx_id: Vec<u8> = row.get(0).map_err(database_error)?;
        let version: i64 = row.get(1).map_err(database_error)?;
        let encrypted: Vec<u8> = row.get(2).map_err(database_error)?;
        let count: i64 = row.get(3).map_err(database_error)?;
        let terminal: Vec<u8> = row.get(4).map_err(database_error)?;
        let head = HistoryHead {
            tx_id: TxId::from_uuid(uuid::Uuid::from_slice(&tx_id).map_err(|_| corrupt())?),
            version: ConfigVersion::new(u64::try_from(version).map_err(|_| corrupt())?),
            encrypted_digest: Sha256::digest(encrypted).into(),
        };
        digest = extend_record_chain(
            digest,
            &head,
            audit_anchor_digest(count, &terminal)?,
            record_metadata_digest(conn, &head, cancellation)?,
        );
    }
    Ok(digest)
}

/// Full validation precedes live reads/admission, pruning, retained reopen and
/// snapshot acceptance, within the same transaction as the protected use.
/// Framing/AAD validation cannot authenticate opaque ciphertext without the
/// decryption key. The history HMAC authenticates this ordered digest, including
/// each record's audit anchor and mutable reference metadata. Removing audit
/// rows together with their anchor, or clearing a protected reference, fails.
pub(crate) fn validate_record_chain_sync(
    conn: &Connection,
    key: &AuditKey,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    if let Some(state) = load_state(conn, key)? {
        if record_chain_sync(conn, cancellation)? != state.record_chain {
            return Err(corrupt());
        }
    }
    Ok(())
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
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    super::sqlite::validate_live_history_schema_sync(conn, cancellation)?;
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
            record_chain: record_chain_sync(conn, cancellation)?,
        },
    )
}

/// Presence is only a refusal fence: partial consensus state cannot grant the
/// standalone path. An admitted backend also remembers this requirement if all
/// these tables are subsequently removed by an independent connection.
pub(crate) fn has_consensus_metadata_sync(conn: &Connection) -> io::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND (name GLOB 'config_raft_*' OR name = 'consensus_retained_binding'))",
        [], |row| row.get(0),
    ).map_err(database_error)
}

fn load_state(conn: &Connection, key: &AuditKey) -> io::Result<Option<HistoryState>> {
    let consensus: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'config_raft_identity')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    if !consensus {
        if has_consensus_metadata_sync(conn)? {
            return Err(corrupt());
        }
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

fn validate_limited_state(conn: &Connection, state: &HistoryState) -> io::Result<()> {
    validate_state(conn, state)?;
    if let Some(limits) = state.limits {
        let (records, bytes) = retained_size(conn, None)?;
        if records > u64::from(limits.max_records) || bytes > limits.max_bytes {
            return Err(corrupt());
        }
    }
    Ok(())
}

pub(crate) fn validate_sync(conn: &Connection, key: &AuditKey) -> io::Result<()> {
    if let Some(state) = load_state(conn, key)? {
        validate_limited_state(conn, &state)?;
    }
    Ok(())
}

/// Authenticate once per read/apply transaction, before even a negative lookup
/// or metadata-based admission decision. Per-row projection must not repeat the
/// complete scan; it runs in this same authenticated SQLite snapshot instead.
pub(crate) fn validate_access_sync(
    conn: &Connection,
    key: &AuditKey,
    consensus_required: bool,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    validate_access_for_profile_sync(
        conn,
        key,
        consensus_required,
        crate::RetainedConfigProfile::Legacy,
        cancellation,
    )
}

/// The selection comes from the admitted backend, never from stored row tags.
/// The existing read/apply transaction pins both history and target validation.
pub(crate) fn validate_access_for_profile_sync(
    conn: &Connection,
    key: &AuditKey,
    consensus_required: bool,
    profile: crate::RetainedConfigProfile,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<()> {
    if consensus_required
        || profile != crate::RetainedConfigProfile::Legacy
        || has_consensus_metadata_sync(conn)?
    {
        super::sqlite::validate_live_history_schema_for_profile(conn, cancellation, profile)?;
    }
    let Some(state) = load_state(conn, key)? else {
        return if consensus_required {
            Err(corrupt())
        } else {
            Ok(())
        };
    };
    if profile == crate::RetainedConfigProfile::NetconfTargetsV1 {
        super::audit_targets::validate_inactive_sync(conn, key, state.identity, cancellation)?;
    }
    validate_limited_state(conn, &state)?;
    if record_chain_sync(conn, cancellation)? != state.record_chain {
        return Err(corrupt());
    }
    Ok(())
}

/// Runs in the existing per-command SQLite savepoint after a possible mutation.
/// Capacity rejection rolls that savepoint back, including pending resolution.
/// Rebinding an existing record requires validation of the prior chain before
/// the command's effects; appends extend the old digest without rehashing it.
pub(crate) fn refresh_sync(
    conn: &Connection,
    key: &AuditKey,
    updates_existing_records: bool,
    cancellation: &SqliteWorkCancellation,
) -> io::Result<Result<(), ConfigMutationFailure>> {
    let mut state = load_state(conn, key)?.ok_or_else(corrupt)?;
    if let Some(limits) = state.limits {
        let (records, bytes) = retained_size(conn, None)?;
        if records > u64::from(limits.max_records) || bytes > limits.max_bytes {
            return Ok(Err(ConfigMutationFailure::HistoryFull));
        }
    }
    let head = head_sync(conn)?;
    let records = record_count(conn)?;
    if head != state.head {
        let next = head.as_ref().ok_or_else(corrupt)?;
        if state.records.checked_add(1) != Some(records)
            || state.head.as_ref().is_some_and(|previous| {
                previous.version.get().checked_add(1) != Some(next.version.get())
            })
            || state.head.is_none() && state.records != 0
        {
            return Err(corrupt());
        }
        // Extend the authenticated prior digest with only this new record.
        // Rehashing old rows here would bless unrelated on-disk corruption.
        let (count, terminal): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT audit_count, audit_terminal_hash FROM config_history WHERE tx_id = ?1",
                [next.tx_id.as_uuid().as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(database_error)?;
        if !updates_existing_records {
            state.record_chain = extend_record_chain(
                state.record_chain,
                next,
                audit_anchor_digest(count, &terminal)?,
                record_metadata_digest(conn, next, cancellation)?,
            );
        }
    } else if records != state.records {
        return Err(corrupt());
    }
    if updates_existing_records {
        // Only a command whose prior chain was authenticated may rebind an
        // existing record's mutable metadata. Otherwise a legitimate lifecycle
        // update could bless unrelated historical damage.
        state.record_chain = record_chain_sync(conn, cancellation)?;
    }
    state.head = head;
    state.records = records;
    save_state(conn, key, &state)?;
    Ok(Ok(()))
}

pub(crate) fn retain_sync(
    conn: &Connection,
    key: &AuditKey,
    decision: &ConfigHistoryRetention,
    cancellation: &SqliteWorkCancellation,
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
    if super::audit::protects_config_prefix(conn, key, decision.retain_from.get())? {
        return Ok(Err(ConfigMutationFailure::HistoryProtected));
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
        cancellation.check_io()?;
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
        state.record_chain = record_chain_sync(conn, cancellation)?;
    }
    state.records = record_count(conn)?;
    state.limits = Some(decision.limits);
    state.acknowledged_through = Some(decision.acknowledged_through);
    save_state(conn, key, &state)?;
    Ok(Ok(()))
}
