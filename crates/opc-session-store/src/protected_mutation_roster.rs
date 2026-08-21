//! Independent durable retention for protected mutation-roster frames.
//!
//! The journal accepts already-protected canonical plan, checkpoint, and
//! terminal-result frames.  It never calls a sealing provider; consequently
//! local/remote sealing-key rotation cannot alter bytes recovered after restart.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2_zeroize::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::fenced_mutation_roster::{
    FencedMutationRosterPlan, FencedMutationRosterProtectedResult, FencedMutationRosterRequestId,
    FencedMutationRosterTerminal, FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES,
    FENCED_MUTATION_ROSTER_MAX_EXACT_RESULT_BYTES, FENCED_MUTATION_ROSTER_MAX_LIVE,
    FENCED_MUTATION_ROSTER_REQUEST_ID_BYTES, FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES,
};

/// Width of a protected-roster journal HMAC key.
pub const PROTECTED_MUTATION_ROSTER_JOURNAL_KEY_BYTES: usize = 32;
const APP_ID: i64 = 0x4f50_4652;
const VERSION: i64 = 1;
const MAX_ROWS: i64 = FENCED_MUTATION_ROSTER_MAX_LIVE as i64;
const KEY_DOMAIN: &[u8] = b"opc/protected-roster-journal/v1/key\0";
const PATH_DOMAIN: &[u8] = b"opc/protected-roster-journal/v1/path\0";
const ROW_DOMAIN: &[u8] = b"opc/protected-roster-journal/v1/row\0";

/// Redaction-safe protected journal failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtectedMutationRosterJournalError {
    /// No local retained frame exists for this identity.
    #[error("protected mutation roster journal entry is absent")]
    Absent,
    /// A stable identity was presented with substituted bytes.
    #[error("protected mutation roster journal request conflict")]
    RequestConflict,
    /// The bounded local journal is full.
    #[error("protected mutation roster journal capacity exhausted")]
    CapacityExhausted,
    /// I/O, authentication, schema, or canonical validation failed.
    #[error("protected mutation roster journal unavailable")]
    Unavailable,
}

/// Stable secret for one independent protected-roster journal.
pub struct ProtectedMutationRosterJournalKey(
    Zeroizing<[u8; PROTECTED_MUTATION_ROSTER_JOURNAL_KEY_BYTES]>,
);
impl ProtectedMutationRosterJournalKey {
    /// Import a durable journal integrity key.
    pub fn from_bytes(bytes: [u8; PROTECTED_MUTATION_ROSTER_JOURNAL_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    fn for_path(&self, path: &Path) -> Self {
        let mut h = Hmac::new(&self.0);
        h.update(PATH_DOMAIN);
        h.update(&APP_ID.to_be_bytes());
        h.update(&VERSION.to_be_bytes());
        let bytes = path.as_os_str().as_encoded_bytes();
        h.update(&(bytes.len() as u64).to_be_bytes());
        h.update(bytes);
        Self(h.finish())
    }
}
impl Clone for ProtectedMutationRosterJournalKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl fmt::Debug for ProtectedMutationRosterJournalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedMutationRosterJournalKey(<redacted>)")
    }
}

/// Authenticated exact frames retained for one stable roster identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedMutationRosterJournalEntry {
    plan: Box<[u8]>,
    checkpoint: Option<Box<[u8]>>,
    terminal: Option<Box<[u8]>>,
}
impl fmt::Debug for ProtectedMutationRosterJournalEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedMutationRosterJournalEntry")
            .field("plan", &"<redacted>")
            .field("has_checkpoint", &self.checkpoint.is_some())
            .field("has_terminal", &self.terminal.is_some())
            .finish()
    }
}
impl ProtectedMutationRosterJournalEntry {
    /// Decode the retained immutable plan.
    pub fn plan(&self) -> Result<FencedMutationRosterPlan, ProtectedMutationRosterJournalError> {
        FencedMutationRosterPlan::decode_canonical(&self.plan).map_err(|_| unavailable())
    }
    /// Return exact opaque checkpoint bytes.
    pub fn checkpoint(&self) -> Option<&[u8]> {
        self.checkpoint.as_deref()
    }
    /// Decode the retained terminal receipt.
    pub fn terminal(
        &self,
    ) -> Result<Option<FencedMutationRosterTerminal>, ProtectedMutationRosterJournalError> {
        self.terminal
            .as_deref()
            .map(|bytes| {
                FencedMutationRosterTerminal::decode_canonical(bytes).map_err(|_| unavailable())
            })
            .transpose()
    }
    /// Return exact canonical plan bytes without resealing.
    pub fn canonical_plan_bytes(&self) -> &[u8] {
        &self.plan
    }
    /// Return exact canonical terminal bytes without resealing.
    pub fn canonical_terminal_bytes(&self) -> Option<&[u8]> {
        self.terminal.as_deref()
    }
}

/// Bounded local cache of protected roster frames.
///
/// `lookup` returning `None` is never authority that a distributed request was
/// not transmitted or adopted; consensus must recover status from its own log.
pub struct ProtectedMutationRosterJournal {
    connection: Mutex<Connection>,
    key: ProtectedMutationRosterJournalKey,
}
impl fmt::Debug for ProtectedMutationRosterJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedMutationRosterJournal(<redacted>)")
    }
}
impl ProtectedMutationRosterJournal {
    /// Create a missing dedicated journal. Symbolic-link leaves are rejected.
    pub fn create_new(
        path: impl AsRef<Path>,
        key: ProtectedMutationRosterJournalKey,
    ) -> Result<Self, ProtectedMutationRosterJournalError> {
        Self::open(checked_path(path.as_ref(), true)?, key, true)
    }
    /// Open a fully initialized existing journal.
    pub fn open_existing(
        path: impl AsRef<Path>,
        key: ProtectedMutationRosterJournalKey,
    ) -> Result<Self, ProtectedMutationRosterJournalError> {
        Self::open(checked_path(path.as_ref(), false)?, key, false)
    }
    fn open(
        path: PathBuf,
        raw_key: ProtectedMutationRosterJournalKey,
        create: bool,
    ) -> Result<Self, ProtectedMutationRosterJournalError> {
        let key = raw_key.for_path(&path);
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | if create {
                OpenFlags::SQLITE_OPEN_CREATE
            } else {
                OpenFlags::empty()
            };
        let mut connection = Connection::open_with_flags(path, flags).map_err(|_| unavailable())?;
        connection
            .busy_timeout(std::time::Duration::from_millis(100))
            .map_err(|_| unavailable())?;
        connection.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA secure_delete = ON; PRAGMA temp_store = MEMORY;").map_err(|_| unavailable())?;
        connection.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            (FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES
                + FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES
                + FENCED_MUTATION_ROSTER_MAX_EXACT_RESULT_BYTES) as i32,
        );
        initialize(&mut connection, &key, create)?;
        Ok(Self {
            connection: Mutex::new(connection),
            key,
        })
    }
    /// Persist the exact canonical immutable plan before transmission.
    pub fn admit(
        &self,
        id: FencedMutationRosterRequestId,
        plan: &FencedMutationRosterPlan,
    ) -> Result<(), ProtectedMutationRosterJournalError> {
        if id.body_commitment() != plan.body_commitment() {
            return Err(ProtectedMutationRosterJournalError::RequestConflict);
        }
        let plan = plan.encode_canonical();
        self.transaction(move |tx, key| match read(tx, key, id)? {
            Some(entry) if entry.plan.as_ref() == plan.as_slice() => Ok(()),
            Some(_) => Err(ProtectedMutationRosterJournalError::RequestConflict),
            None => {
                let count: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM protected_mutation_roster_journal_entries",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(|_| unavailable())?;
                if count >= MAX_ROWS {
                    return Err(ProtectedMutationRosterJournalError::CapacityExhausted);
                }
                write(tx, key, id, &plan, None, None)
            }
        })
    }
    /// Persist one exact protected checkpoint without any provider call.
    pub fn checkpoint(
        &self,
        id: FencedMutationRosterRequestId,
        checkpoint: FencedMutationRosterProtectedResult,
    ) -> Result<(), ProtectedMutationRosterJournalError> {
        let checkpoint = checkpoint.as_bytes().to_vec();
        self.transaction(move |tx, key| {
            let entry = read(tx, key, id)?.ok_or(ProtectedMutationRosterJournalError::Absent)?;
            if entry.terminal.is_some() {
                return Err(ProtectedMutationRosterJournalError::RequestConflict);
            }
            if let Some(old) = &entry.checkpoint {
                return if old.as_ref() == checkpoint.as_slice() {
                    Ok(())
                } else {
                    Err(ProtectedMutationRosterJournalError::RequestConflict)
                };
            }
            write(tx, key, id, &entry.plan, Some(&checkpoint), None)
        })
    }
    /// Persist a terminal receipt bound to the admitted stable member roster.
    ///
    /// The generic terminal frame carries its own exact protected checkpoint
    /// and result, including the aborted-result form.
    pub fn terminal(
        &self,
        id: FencedMutationRosterRequestId,
        terminal: &FencedMutationRosterTerminal,
    ) -> Result<(), ProtectedMutationRosterJournalError> {
        let terminal = terminal.encode_canonical();
        self.transaction(move |tx, key| {
            let entry = read(tx, key, id)?.ok_or(ProtectedMutationRosterJournalError::Absent)?;
            let plan = entry.plan()?;
            let decoded = FencedMutationRosterTerminal::decode_canonical(&terminal)
                .map_err(|_| unavailable())?;
            if !decoded.belongs_to(&plan) {
                return Err(ProtectedMutationRosterJournalError::RequestConflict);
            }
            if let Some(old) = &entry.terminal {
                return if old.as_ref() == terminal.as_slice() {
                    Ok(())
                } else {
                    Err(ProtectedMutationRosterJournalError::RequestConflict)
                };
            }
            write(
                tx,
                key,
                id,
                &entry.plan,
                entry.checkpoint.as_deref(),
                Some(&terminal),
            )
        })
    }
    /// Load exact local frames without a sealing/provider call.
    pub fn lookup(
        &self,
        id: FencedMutationRosterRequestId,
    ) -> Result<Option<ProtectedMutationRosterJournalEntry>, ProtectedMutationRosterJournalError>
    {
        let connection = self.connection.lock().map_err(|_| unavailable())?;
        metadata(&connection, &self.key)?;
        read(&connection, &self.key, id)
    }
    fn transaction<T>(
        &self,
        work: impl FnOnce(
            &rusqlite::Transaction<'_>,
            &ProtectedMutationRosterJournalKey,
        ) -> Result<T, ProtectedMutationRosterJournalError>,
    ) -> Result<T, ProtectedMutationRosterJournalError> {
        let mut connection = self.connection.lock().map_err(|_| unavailable())?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        metadata(&tx, &self.key)?;
        let result = work(&tx, &self.key)?;
        metadata(&tx, &self.key)?;
        tx.commit().map_err(|_| unavailable())?;
        Ok(result)
    }
}

fn checked_path(path: &Path, create: bool) -> Result<PathBuf, ProtectedMutationRosterJournalError> {
    if path.as_os_str().is_empty() {
        return Err(unavailable());
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() || create => {
            Err(unavailable())
        }
        Ok(_) => Ok(path.to_path_buf()),
        Err(err) if create && err.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(_) => Err(unavailable()),
    }
}
fn initialize(
    connection: &mut Connection,
    key: &ProtectedMutationRosterJournalKey,
    create: bool,
) -> Result<(), ProtectedMutationRosterJournalError> {
    let app: i64 = connection
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(|_| unavailable())?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|_| unavailable())?;
    let objects: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )
        .map_err(|_| unavailable())?;
    if app == 0 && version == 0 && objects == 0 && create {
        connection.execute_batch(&format!("CREATE TABLE protected_mutation_roster_journal_metadata (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL CHECK (version = {VERSION}), key_check BLOB NOT NULL CHECK (typeof(key_check) = 'blob' AND length(key_check) = 32)) STRICT; CREATE TABLE protected_mutation_roster_journal_entries (request_id BLOB PRIMARY KEY CHECK (typeof(request_id) = 'blob' AND length(request_id) = {FENCED_MUTATION_ROSTER_REQUEST_ID_BYTES}), plan BLOB NOT NULL CHECK (typeof(plan) = 'blob' AND length(plan) <= {FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES}), checkpoint BLOB CHECK (checkpoint IS NULL OR (typeof(checkpoint) = 'blob' AND length(checkpoint) <= {FENCED_MUTATION_ROSTER_MAX_EXACT_RESULT_BYTES})), terminal BLOB CHECK (terminal IS NULL OR (typeof(terminal) = 'blob' AND length(terminal) <= {FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES})), tag BLOB NOT NULL CHECK (typeof(tag) = 'blob' AND length(tag) = 32)) STRICT; PRAGMA application_id = {APP_ID}; PRAGMA user_version = {VERSION};")).map_err(|_| unavailable())?;
        let check = key_check(key);
        connection
            .execute(
                "INSERT INTO protected_mutation_roster_journal_metadata VALUES (1, ?1, ?2)",
                params![VERSION, check.as_slice()],
            )
            .map_err(|_| unavailable())?;
    } else if app != APP_ID || version != VERSION || objects != 2 {
        return Err(unavailable());
    }
    metadata(connection, key)
}
fn metadata(
    connection: &Connection,
    key: &ProtectedMutationRosterJournalKey,
) -> Result<(), ProtectedMutationRosterJournalError> {
    let (version, check): (i64, Vec<u8>) = connection.query_row("SELECT version, key_check FROM protected_mutation_roster_journal_metadata WHERE singleton = 1", [], |r| Ok((r.get(0)?, r.get(1)?))).map_err(|_| unavailable())?;
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM protected_mutation_roster_journal_entries",
            [],
            |r| r.get(0),
        )
        .map_err(|_| unavailable())?;
    if version != VERSION
        || check.len() != 32
        || !bool::from(key_check(key).as_slice().ct_eq(&check))
        || !(0..=MAX_ROWS).contains(&count)
    {
        return Err(unavailable());
    }
    Ok(())
}
fn read(
    connection: &Connection,
    key: &ProtectedMutationRosterJournalKey,
    id: FencedMutationRosterRequestId,
) -> Result<Option<ProtectedMutationRosterJournalEntry>, ProtectedMutationRosterJournalError> {
    let row = connection.query_row("SELECT plan, checkpoint, terminal, tag FROM protected_mutation_roster_journal_entries WHERE request_id = ?1", params![id_bytes(id).as_slice()], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<Vec<u8>>>(1)?, r.get::<_, Option<Vec<u8>>>(2)?, r.get::<_, Vec<u8>>(3)?))).optional().map_err(|_| unavailable())?;
    let Some((plan, checkpoint, terminal, tag)) = row else {
        return Ok(None);
    };
    if plan.len() > FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES
        || checkpoint
            .as_ref()
            .is_some_and(|v| v.len() > FENCED_MUTATION_ROSTER_MAX_EXACT_RESULT_BYTES)
        || terminal
            .as_ref()
            .is_some_and(|v| v.len() > FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES)
        || tag.len() != 32
    {
        return Err(unavailable());
    }
    let entry = ProtectedMutationRosterJournalEntry {
        plan: plan.into_boxed_slice(),
        checkpoint: checkpoint.map(Vec::into_boxed_slice),
        terminal: terminal.map(Vec::into_boxed_slice),
    };
    let plan = entry.plan()?;
    if id.body_commitment() != plan.body_commitment()
        || entry
            .terminal()?
            .is_some_and(|terminal| !terminal.belongs_to(&plan))
        || !bool::from(row_tag(key, id, &entry).as_slice().ct_eq(&tag))
    {
        return Err(unavailable());
    }
    Ok(Some(entry))
}
fn write(
    connection: &rusqlite::Transaction<'_>,
    key: &ProtectedMutationRosterJournalKey,
    id: FencedMutationRosterRequestId,
    plan: &[u8],
    checkpoint: Option<&[u8]>,
    terminal: Option<&[u8]>,
) -> Result<(), ProtectedMutationRosterJournalError> {
    let entry = ProtectedMutationRosterJournalEntry {
        plan: plan.into(),
        checkpoint: checkpoint.map(Into::into),
        terminal: terminal.map(Into::into),
    };
    let tag = row_tag(key, id, &entry);
    if connection.execute("INSERT INTO protected_mutation_roster_journal_entries VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(request_id) DO UPDATE SET plan=excluded.plan, checkpoint=excluded.checkpoint, terminal=excluded.terminal, tag=excluded.tag", params![id_bytes(id).as_slice(), plan, checkpoint, terminal, tag.as_slice()]).map_err(|_| unavailable())? != 1 { return Err(unavailable()); }
    Ok(())
}
fn id_bytes(id: FencedMutationRosterRequestId) -> [u8; FENCED_MUTATION_ROSTER_REQUEST_ID_BYTES] {
    let mut result = [0; FENCED_MUTATION_ROSTER_REQUEST_ID_BYTES];
    result[..8].copy_from_slice(&id.epoch().to_be_bytes());
    result[8..24].copy_from_slice(id.operation_id().as_bytes());
    result[24..].copy_from_slice(&id.body_commitment());
    result
}
fn key_check(key: &ProtectedMutationRosterJournalKey) -> Zeroizing<[u8; 32]> {
    let mut h = Hmac::new(&key.0);
    h.update(KEY_DOMAIN);
    h.update(&APP_ID.to_be_bytes());
    h.update(&VERSION.to_be_bytes());
    h.finish()
}
fn row_tag(
    key: &ProtectedMutationRosterJournalKey,
    id: FencedMutationRosterRequestId,
    entry: &ProtectedMutationRosterJournalEntry,
) -> Zeroizing<[u8; 32]> {
    let mut h = Hmac::new(&key.0);
    h.update(ROW_DOMAIN);
    h.update(&id_bytes(id));
    for value in [
        Some(entry.plan.as_ref()),
        entry.checkpoint.as_deref(),
        entry.terminal.as_deref(),
    ] {
        match value {
            Some(value) => {
                h.update(&[1]);
                h.update(&(value.len() as u64).to_be_bytes());
                h.update(value);
            }
            None => h.update(&[0]),
        }
    }
    h.finish()
}
fn unavailable() -> ProtectedMutationRosterJournalError {
    ProtectedMutationRosterJournalError::Unavailable
}
struct Hmac {
    inner: Sha256,
    outer: Zeroizing<[u8; 64]>,
}
impl Hmac {
    fn new(key: &[u8; 32]) -> Self {
        let mut inner_pad = Zeroizing::new([0x36; 64]);
        let mut outer = Zeroizing::new([0x5c; 64]);
        for ((a, b), key) in inner_pad.iter_mut().zip(outer.iter_mut()).zip(key.iter()) {
            *a ^= *key;
            *b ^= *key;
        }
        let mut inner = Sha256::new();
        inner.update(inner_pad.as_slice());
        Self { inner, outer }
    }
    fn update(&mut self, value: &[u8]) {
        self.inner.update(value);
    }
    fn finish(self) -> Zeroizing<[u8; 32]> {
        let mut inner = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(self.outer.as_slice());
        outer.update(inner.as_slice());
        zeroize::Zeroize::zeroize(inner.as_mut_slice());
        let mut digest = outer.finalize();
        let mut result = Zeroizing::new([0; 32]);
        result.copy_from_slice(digest.as_slice());
        zeroize::Zeroize::zeroize(digest.as_mut_slice());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fenced_mutation_roster::{
        FencedMutationRosterAdoption, FencedMutationRosterDescriptor,
        FencedMutationRosterDisposition, FencedMutationRosterMember,
        FencedMutationRosterMemberOutcome, FencedMutationRosterOperationId,
        FencedMutationRosterOrdinal, FencedMutationRosterStatusBytes,
    };
    use tempfile::tempdir;
    fn plan() -> FencedMutationRosterPlan {
        let member = FencedMutationRosterMember::new(
            FencedMutationRosterOrdinal::new(0).unwrap(),
            [2; 16],
            FencedMutationRosterDescriptor::new(b"member".to_vec()).unwrap(),
            2,
            3,
            FencedMutationRosterDisposition::Applied,
            FencedMutationRosterAdoption::Adopted,
        )
        .unwrap();
        FencedMutationRosterPlan::new(
            [1; 32],
            [2; 32],
            b"owner".to_vec(),
            b"fence".to_vec(),
            4,
            vec![member],
            b"sealed-plan".to_vec(),
            b"sealed-result".to_vec(),
        )
        .unwrap()
    }
    fn id(plan: &FencedMutationRosterPlan) -> FencedMutationRosterRequestId {
        FencedMutationRosterRequestId::for_plan(
            1,
            FencedMutationRosterOperationId::new([8; 16]).unwrap(),
            plan,
        )
    }
    #[test]
    fn restart_preserves_exact_plan_and_checkpoint() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("j.sqlite");
        let plan = plan();
        let id = id(&plan);
        let canonical = plan.encode_canonical();
        let journal = ProtectedMutationRosterJournal::create_new(
            &path,
            ProtectedMutationRosterJournalKey::from_bytes([7; 32]),
        )
        .unwrap();
        journal.admit(id, &plan).unwrap();
        journal
            .checkpoint(
                id,
                FencedMutationRosterProtectedResult::new(b"checkpoint".to_vec().into_boxed_slice())
                    .unwrap(),
            )
            .unwrap();
        drop(journal);
        let journal = ProtectedMutationRosterJournal::open_existing(
            &path,
            ProtectedMutationRosterJournalKey::from_bytes([7; 32]),
        )
        .unwrap();
        let entry = journal.lookup(id).unwrap().unwrap();
        assert_eq!(entry.canonical_plan_bytes(), canonical);
        assert_eq!(entry.checkpoint(), Some(&b"checkpoint"[..]));
    }
    #[test]
    fn corruption_and_substitution_fail_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("j.sqlite");
        let plan = plan();
        let id = id(&plan);
        let journal = ProtectedMutationRosterJournal::create_new(
            &path,
            ProtectedMutationRosterJournalKey::from_bytes([7; 32]),
        )
        .unwrap();
        journal.admit(id, &plan).unwrap();
        journal
            .checkpoint(
                id,
                FencedMutationRosterProtectedResult::new(b"one".to_vec().into_boxed_slice())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            journal
                .checkpoint(
                    id,
                    FencedMutationRosterProtectedResult::new(b"two".to_vec().into_boxed_slice())
                        .unwrap()
                )
                .unwrap_err(),
            ProtectedMutationRosterJournalError::RequestConflict
        );
        assert!(!format!("{:?}", journal).contains("j.sqlite"));
        drop(journal);
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE protected_mutation_roster_journal_entries SET plan=X'00'",
            [],
        )
        .unwrap();
        drop(conn);
        let journal = ProtectedMutationRosterJournal::open_existing(
            &path,
            ProtectedMutationRosterJournalKey::from_bytes([7; 32]),
        )
        .unwrap();
        assert_eq!(
            journal.lookup(id).unwrap_err(),
            ProtectedMutationRosterJournalError::Unavailable
        );
    }
    #[test]
    fn terminal_keeps_exact_aborted_result() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("j.sqlite");
        let plan = plan();
        let id = id(&plan);
        let journal = ProtectedMutationRosterJournal::create_new(
            &path,
            ProtectedMutationRosterJournalKey::from_bytes([7; 32]),
        )
        .unwrap();
        journal.admit(id, &plan).unwrap();
        let outcome = FencedMutationRosterMemberOutcome::new(
            FencedMutationRosterOrdinal::new(0).unwrap(),
            [2; 16],
            FencedMutationRosterDisposition::Compensated,
            FencedMutationRosterAdoption::Reconciled,
            FencedMutationRosterStatusBytes::new(b"aborted".to_vec()).unwrap(),
        )
        .unwrap();
        let terminal = FencedMutationRosterTerminal::new(
            plan.admission_commitment(),
            vec![outcome],
            b"checkpoint".to_vec(),
            b"sealed-result".to_vec(),
        )
        .unwrap();
        let canonical = terminal.encode_canonical();
        journal.terminal(id, &terminal).unwrap();
        assert_eq!(
            journal
                .lookup(id)
                .unwrap()
                .unwrap()
                .canonical_terminal_bytes(),
            Some(canonical.as_slice())
        );
    }
}
