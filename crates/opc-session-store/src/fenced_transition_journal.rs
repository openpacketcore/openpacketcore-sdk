//! Durable caller-side retention for protected atomic-transition requests.
//!
//! The journal is deliberately separate from application session state. It
//! binds one caller-stable transition identity to the exact opaque prepared
//! request before any transport or consensus proposal can observe that
//! request. A later process can therefore recover the same protected bytes
//! without invoking a key or remote-seal provider again.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use rand::{rngs::SysRng, TryRng};
use rusqlite::{
    limits::Limit, params, types::ValueRef, Connection, OpenFlags, OptionalExtension,
    TransactionBehavior,
};
use sha2_zeroize::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    FencedTransitionRequestId, PreparedFencedTransition, PreparedFencedTransitionLookup,
    StoreError, FENCED_TRANSITION_MAX_HISTORY_ENTRIES, FENCED_TRANSITION_MAX_PREPARED_BYTES,
    FENCED_TRANSITION_PREPARED_SCHEMA_V1, FENCED_TRANSITION_REQUEST_ID_BYTES,
};

/// Width of the independent integrity key protecting one prepared journal.
pub const PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES: usize = 32;

const JOURNAL_APPLICATION_ID: i64 = 0x4f50_464a;
const JOURNAL_SCHEMA_VERSION: i64 = 2;
const JOURNAL_SCHEMA_OBJECT_COUNT: i64 = 4;
const JOURNAL_MEMBERSHIP_INDEX: &str = "prepared_fenced_transition_journal_membership_idx";
const JOURNAL_BUSY_TIMEOUT: Duration = Duration::from_millis(100);
const JOURNAL_UNAVAILABLE: &str = "prepared fenced-transition journal unavailable";
const JOURNAL_CATALOG_MAX_OBJECTS: usize = 4;
const JOURNAL_METADATA_MAX_ROWS: usize = 1;
const JOURNAL_MEMBERSHIP_SCAN_LIMIT: usize = FENCED_TRANSITION_MAX_HISTORY_ENTRIES + 1;
const JOURNAL_CATALOG_SCAN_LIMIT: usize = JOURNAL_CATALOG_MAX_OBJECTS + 1;
const JOURNAL_METADATA_SCAN_LIMIT: usize = JOURNAL_METADATA_MAX_ROWS + 1;
// SQLite's length limit applies to an entire record as well as its largest
// BLOB. This covers the 16-byte request ID, an INTEGER schema version, the
// 32-byte tag, and 64 bytes for SQLite record-header varints (well above the
// five maximum-width varints this four-column row can need).
const JOURNAL_SQLITE_LENGTH_ROW_OVERHEAD_BYTES: usize =
    16 + std::mem::size_of::<i64>() + PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES + 64;
const JOURNAL_KEY_CHECK_DOMAIN: &[u8] =
    b"openpacketcore/session-store/prepared-journal/key-check/v1\0";
const JOURNAL_ENTRY_DOMAIN: &[u8] = b"openpacketcore/session-store/prepared-journal/entry/v1\0";
const JOURNAL_MEMBERSHIP_ROOT_DOMAIN: &[u8] =
    b"openpacketcore/session-store/prepared-journal/membership-root/v1\0";
const JOURNAL_MEMBERSHIP_TAG_DOMAIN: &[u8] =
    b"openpacketcore/session-store/prepared-journal/membership-tag/v1\0";

/// HMAC-SHA-256 with its key-derived pads and intermediate digests zeroized.
struct ZeroizingHmacSha256 {
    inner: Sha256,
    outer_pad: Zeroizing<[u8; 64]>,
}

impl ZeroizingHmacSha256 {
    fn new(key: &[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES]) -> Self {
        let mut inner_pad = Zeroizing::new([0x36_u8; 64]);
        let mut outer_pad = Zeroizing::new([0x5c_u8; 64]);
        for ((inner, outer), key_byte) in inner_pad
            .iter_mut()
            .zip(outer_pad.iter_mut())
            .zip(key.iter())
        {
            *inner ^= key_byte;
            *outer ^= key_byte;
        }
        let mut inner = Sha256::new();
        inner.update(inner_pad.as_slice());
        Self { inner, outer_pad }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    fn finalize(self) -> Zeroizing<[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES]> {
        let mut inner_digest = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(self.outer_pad.as_slice());
        outer.update(inner_digest.as_slice());
        zeroize::Zeroize::zeroize(inner_digest.as_mut_slice());
        let mut digest = outer.finalize();
        let mut output = Zeroizing::new([0_u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES]);
        output.copy_from_slice(digest.as_slice());
        zeroize::Zeroize::zeroize(digest.as_mut_slice());
        output
    }

    fn verify_slice(self, stored: &[u8]) -> bool {
        self.finalize().as_slice().ct_eq(stored).into()
    }
}

type HmacSha256 = ZeroizingHmacSha256;

/// Stable secret used only to authenticate an SDK prepared-request journal.
///
/// This key is independent of record-encryption and remote-provider keys. The
/// caller must restore the same value when reopening the journal after a
/// process restart. It must come from durable secret configuration rather
/// than from the journal file itself.
pub struct PreparedFencedTransitionJournalKey(
    Zeroizing<[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES]>,
);

impl PreparedFencedTransitionJournalKey {
    /// Import a stable journal-integrity key from secret configuration.
    pub fn from_bytes(bytes: [u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES] {
        &self.0
    }
}

impl Clone for PreparedFencedTransitionJournalKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for PreparedFencedTransitionJournalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedFencedTransitionJournalKey(<redacted>)")
    }
}

struct PreparedFencedTransitionJournalInner {
    conn: Mutex<Connection>,
    key: PreparedFencedTransitionJournalKey,
    #[cfg(unix)]
    path_guard: SecureJournalPathGuard,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum JournalOpenMode {
    CreateNew,
    OpenExisting,
}

/// The SQLite name and, on Unix, the descriptors that bind it to a checked
/// directory entry for the lifetime of the journal.
struct PreparedJournalPath {
    sqlite_path: PathBuf,
    #[cfg(unix)]
    path_guard: SecureJournalPathGuard,
}

#[cfg(unix)]
struct SecureJournalPathGuard {
    root: std::fs::File,
    /// Each descriptor is tied to its predecessor by the stored entry name.
    /// The last entry, when present, is the immediate parent.
    ancestors: Vec<(std::fs::File, std::ffi::OsString)>,
    parent: std::fs::File,
    leaf: std::fs::File,
    leaf_name: std::ffi::OsString,
}

/// SDK-owned durable binding of transition IDs to opaque prepared requests.
///
/// The database contains the complete protected prepared token, never the
/// logical plaintext request. Every row is authenticated with a stable key
/// that is intentionally independent of payload key/provider rotation.
#[derive(Clone)]
pub struct PreparedFencedTransitionJournal {
    inner: Arc<PreparedFencedTransitionJournalInner>,
    operation_permit: Arc<tokio::sync::Semaphore>,
}

impl fmt::Debug for PreparedFencedTransitionJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedFencedTransitionJournal")
            .field("path", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl PreparedFencedTransitionJournal {
    /// Provision one missing dedicated durable journal database.
    ///
    /// On Unix every existing ancestor is opened without following symlinks.
    /// The immediate parent and database must be owned by the effective user,
    /// deny all group and other access, and the database must be a regular,
    /// single-link file. Their descriptor-bound identity is revalidated before
    /// every operation. Platforms without those checks fail closed.
    ///
    /// The integrity key is scoped to exactly this journal storage boundary.
    /// Reusing it for another path or file is unsupported and unsafe: a
    /// missing or substituted path must never be authenticated as `Absent`.
    pub fn create_new(
        path: impl AsRef<Path>,
        key: PreparedFencedTransitionJournalKey,
    ) -> Result<Self, StoreError> {
        Self::open_with_mode(path.as_ref(), key, JournalOpenMode::CreateNew)
    }

    /// Open a fully initialized existing dedicated durable journal database.
    ///
    /// This never creates a leaf or initializes a pristine SQLite file.
    pub fn open_existing(
        path: impl AsRef<Path>,
        key: PreparedFencedTransitionJournalKey,
    ) -> Result<Self, StoreError> {
        Self::open_with_mode(path.as_ref(), key, JournalOpenMode::OpenExisting)
    }

    /// Open an existing journal.
    #[deprecated(note = "use open_existing; provisioning must use create_new")]
    pub fn open(
        path: impl AsRef<Path>,
        key: PreparedFencedTransitionJournalKey,
    ) -> Result<Self, StoreError> {
        Self::open_existing(path, key)
    }

    fn open_with_mode(
        path: &Path,
        key: PreparedFencedTransitionJournalKey,
        mode: JournalOpenMode,
    ) -> Result<Self, StoreError> {
        let path = prepare_secure_journal_path(path, mode)?;
        // SQLite's SQLITE_OPEN_NOFOLLOW rejects the descriptor-directory
        // anchor itself because /proc/self/fd and /dev/fd are symlinks. Unix
        // admission instead opens the final entry with O_NOFOLLOW beneath the
        // held directory descriptor, verifies the descriptor-bound anchor,
        // and retains that binding for every later operation.
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
        let mut conn = Connection::open_with_flags(&path.sqlite_path, flags)
            .map_err(|_| journal_unavailable())?;
        configure_journal_sqlite_limits(&conn)?;
        #[cfg(unix)]
        path.path_guard.verify_connection(&conn)?;
        initialize_connection(&mut conn, &key, mode)?;
        #[cfg(unix)]
        path.path_guard.verify_connection(&conn)?;
        Ok(Self {
            inner: Arc::new(PreparedFencedTransitionJournalInner {
                conn: Mutex::new(conn),
                key,
                #[cfg(unix)]
                path_guard: path.path_guard,
            }),
            operation_permit: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }

    pub(crate) async fn health_check(&self) -> Result<(), StoreError> {
        self.with_connection(|conn, key| {
            let transaction = journal_read_transaction(conn)?;
            verify_metadata(&transaction, key)?;
            verify_sqlite_main_file_binding(&transaction)?;
            transaction.commit().map_err(|_| journal_unavailable())
        })
        .await
    }

    pub(crate) async fn ensure_absent(
        &self,
        request_id: FencedTransitionRequestId,
    ) -> Result<(), StoreError> {
        self.with_connection(move |conn, key| {
            let transaction = journal_read_transaction(conn)?;
            let membership = verify_metadata(&transaction, key)?;
            if read_entry(&transaction, key, request_id)?.is_some() {
                return Err(StoreError::FencedTransitionRequestConflict);
            }
            if membership.count
                >= i64::try_from(FENCED_TRANSITION_MAX_HISTORY_ENTRIES)
                    .map_err(|_| journal_unavailable())?
            {
                return Err(StoreError::FencedTransitionHistoryFull);
            }
            verify_sqlite_main_file_binding(&transaction)?;
            transaction.commit().map_err(|_| journal_unavailable())
        })
        .await
    }

    pub(crate) async fn insert(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<(), StoreError> {
        let request_id = prepared.request_id();
        let canonical = Zeroizing::new(prepared.as_bytes().to_vec());
        self.with_connection(move |conn, key| {
            let transaction = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| journal_unavailable())?;
            let membership = verify_metadata(&transaction, key)?;

            let existing = read_entry(&transaction, key, request_id)?;
            if existing.is_some() {
                return Err(StoreError::FencedTransitionRequestConflict);
            }
            if membership.count
                >= i64::try_from(FENCED_TRANSITION_MAX_HISTORY_ENTRIES)
                    .map_err(|_| journal_unavailable())?
            {
                return Err(StoreError::FencedTransitionHistoryFull);
            }

            let tag = entry_tag(key, request_id, &canonical)?;
            let inserted = transaction
                .execute(
                    "INSERT INTO prepared_fenced_transition_journal \
                     (request_id, prepared_schema_version, prepared_token, integrity_tag) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        request_id.as_bytes().as_slice(),
                        i64::from(FENCED_TRANSITION_PREPARED_SCHEMA_V1),
                        canonical.as_slice(),
                        tag.as_slice(),
                    ],
                )
                .map_err(|_| journal_unavailable())?;
            if inserted != 1 {
                return Err(journal_unavailable());
            }
            let Some(inserted_prepared) = read_entry(&transaction, key, request_id)? else {
                return Err(journal_unavailable());
            };
            if inserted_prepared.as_bytes() != canonical.as_slice() {
                return Err(journal_unavailable());
            }

            let updated = scan_journal_membership(
                &transaction,
                &membership.incarnation,
                membership
                    .count
                    .checked_add(1)
                    .ok_or_else(journal_unavailable)?,
            )?;
            if updated.count
                != membership
                    .count
                    .checked_add(1)
                    .ok_or_else(journal_unavailable)?
            {
                return Err(journal_unavailable());
            }
            let updated_tag =
                membership_tag(key, &membership.incarnation, updated.count, &updated.root)?;
            let metadata_updated = transaction
                .execute(
                    "UPDATE prepared_fenced_transition_journal_metadata \
                     SET membership_count = ?1, membership_root = ?2, membership_tag = ?3 \
                     WHERE singleton = 1 \
                       AND membership_count = ?4 \
                       AND membership_root = ?5 \
                       AND membership_tag = ?6",
                    params![
                        updated.count,
                        updated.root.as_slice(),
                        updated_tag.as_slice(),
                        membership.count,
                        membership.root.as_slice(),
                        membership.tag.as_slice(),
                    ],
                )
                .map_err(|_| journal_unavailable())?;
            if metadata_updated != 1 {
                return Err(journal_unavailable());
            }
            verify_metadata(&transaction, key)?;
            verify_sqlite_main_file_binding(&transaction)?;
            transaction.commit().map_err(|_| journal_unavailable())
        })
        .await
    }

    pub(crate) async fn lookup(
        &self,
        request_id: FencedTransitionRequestId,
    ) -> Result<PreparedFencedTransitionLookup, StoreError> {
        self.with_connection(move |conn, key| {
            let transaction = journal_read_transaction(conn)?;
            verify_metadata(&transaction, key)?;
            let lookup = read_entry(&transaction, key, request_id).map(|entry| match entry {
                Some(prepared) => PreparedFencedTransitionLookup::Found(prepared),
                None => PreparedFencedTransitionLookup::Absent,
            })?;
            verify_sqlite_main_file_binding(&transaction)?;
            transaction.commit().map_err(|_| journal_unavailable())?;
            Ok(lookup)
        })
        .await
    }

    pub(crate) async fn require_exact(
        &self,
        supplied: &PreparedFencedTransition,
    ) -> Result<Option<PreparedFencedTransition>, StoreError> {
        match self.lookup(supplied.request_id()).await? {
            PreparedFencedTransitionLookup::Absent => Ok(None),
            PreparedFencedTransitionLookup::Found(stored)
                if stored.as_bytes() == supplied.as_bytes() =>
            {
                Ok(Some(stored))
            }
            PreparedFencedTransitionLookup::Found(_) => {
                Err(StoreError::FencedTransitionRequestConflict)
            }
        }
    }

    async fn with_connection<T, F>(&self, operation: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, &PreparedFencedTransitionJournalKey) -> Result<T, StoreError>
            + Send
            + 'static,
    {
        let permit = Arc::clone(&self.operation_permit)
            .acquire_owned()
            .await
            .map_err(|_| journal_unavailable())?;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut conn = inner.conn.lock().map_err(|_| journal_unavailable())?;
            #[cfg(unix)]
            inner.path_guard.verify_connection(&conn)?;
            let result = operation(&mut conn, &inner.key);
            #[cfg(unix)]
            inner.path_guard.verify_connection(&conn)?;
            result
        })
        .await
        .map_err(|_| journal_unavailable())?
    }
}

fn initialize_connection(
    conn: &mut Connection,
    key: &PreparedFencedTransitionJournalKey,
    mode: JournalOpenMode,
) -> Result<(), StoreError> {
    conn.busy_timeout(JOURNAL_BUSY_TIMEOUT)
        .map_err(|_| journal_unavailable())?;
    let initial_application_id = journal_application_id(conn)?;
    let initial_user_version = journal_user_version(conn)?;
    let initial_object_count = journal_schema_catalog_count(conn)?;
    if !((initial_application_id == 0 && initial_user_version == 0 && initial_object_count == 0)
        || (initial_application_id == JOURNAL_APPLICATION_ID
            && initial_user_version == JOURNAL_SCHEMA_VERSION
            && initial_object_count == JOURNAL_SCHEMA_OBJECT_COUNT))
    {
        return Err(journal_unavailable());
    }
    if mode == JournalOpenMode::OpenExisting && initial_application_id == 0 {
        return Err(journal_unavailable());
    }
    if initial_application_id == JOURNAL_APPLICATION_ID {
        verify_journal_schema(conn)?;
    }
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = EXTRA;
        PRAGMA foreign_keys = ON;
        PRAGMA locking_mode = NORMAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA secure_delete = ON;
        "#,
    )
    .map_err(|_| journal_unavailable())?;
    verify_connection_profile(conn)?;

    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| journal_unavailable())?;
    let application_id = journal_application_id(&transaction)?;
    let user_version = journal_user_version(&transaction)?;
    if application_id == 0 && user_version == 0 {
        if journal_schema_catalog_count(&transaction)? != 0 {
            return Err(journal_unavailable());
        }
        transaction
            .execute_batch(&format!(
                r#"
            CREATE TABLE prepared_fenced_transition_journal_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL CHECK (schema_version = {JOURNAL_SCHEMA_VERSION}),
                journal_incarnation BLOB NOT NULL CHECK (
                    typeof(journal_incarnation) = 'blob' AND length(journal_incarnation) = 32
                ),
                membership_count INTEGER NOT NULL CHECK (
                    membership_count >= 0
                    AND membership_count <= {FENCED_TRANSITION_MAX_HISTORY_ENTRIES}
                ),
                membership_root BLOB NOT NULL CHECK (
                    typeof(membership_root) = 'blob' AND length(membership_root) = 32
                ),
                membership_tag BLOB NOT NULL CHECK (
                    typeof(membership_tag) = 'blob' AND length(membership_tag) = 32
                ),
                key_check BLOB NOT NULL CHECK (
                    typeof(key_check) = 'blob' AND length(key_check) = 32
                )
            ) STRICT;
            CREATE TABLE prepared_fenced_transition_journal (
                request_id BLOB PRIMARY KEY CHECK (
                    typeof(request_id) = 'blob' AND length(request_id) = 16
                ),
                prepared_schema_version INTEGER NOT NULL CHECK (
                    prepared_schema_version = {FENCED_TRANSITION_PREPARED_SCHEMA_V1}
                ),
                prepared_token BLOB NOT NULL CHECK (
                    typeof(prepared_token) = 'blob'
                    AND length(prepared_token) <= {FENCED_TRANSITION_MAX_PREPARED_BYTES}
                ),
                integrity_tag BLOB NOT NULL CHECK (
                    typeof(integrity_tag) = 'blob' AND length(integrity_tag) = 32
                )
            ) STRICT;
            CREATE INDEX {JOURNAL_MEMBERSHIP_INDEX}
                ON prepared_fenced_transition_journal (request_id, integrity_tag);
            PRAGMA application_id = {JOURNAL_APPLICATION_ID};
            PRAGMA user_version = {JOURNAL_SCHEMA_VERSION};
            "#
            ))
            .map_err(|_| journal_unavailable())?;
        let key_check = key_check(key)?;
        let mut journal_incarnation = [0_u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES];
        SysRng
            .try_fill_bytes(&mut journal_incarnation)
            .map_err(|_| journal_unavailable())?;
        let empty_root = MembershipRoot::new(&journal_incarnation, 0)?.finalize();
        let empty_tag = membership_tag(key, &journal_incarnation, 0, &empty_root)?;
        transaction
            .execute(
                "INSERT INTO prepared_fenced_transition_journal_metadata \
                 (singleton, schema_version, journal_incarnation, membership_count, \
                  membership_root, membership_tag, key_check) \
                 VALUES (1, ?1, ?2, 0, ?3, ?4, ?5)",
                params![
                    JOURNAL_SCHEMA_VERSION,
                    journal_incarnation.as_slice(),
                    empty_root.as_slice(),
                    empty_tag.as_slice(),
                    key_check.as_slice(),
                ],
            )
            .map_err(|_| journal_unavailable())?;
    } else if application_id != JOURNAL_APPLICATION_ID || user_version != JOURNAL_SCHEMA_VERSION {
        return Err(journal_unavailable());
    }
    verify_metadata(&transaction, key)?;
    verify_sqlite_main_file_binding(&transaction)?;
    transaction.commit().map_err(|_| journal_unavailable())
}

fn verify_sqlite_main_file_binding(conn: &Connection) -> Result<(), StoreError> {
    #[cfg(unix)]
    if opc_sqlite_file_control_sys::main_file_has_moved(conn).map_err(|_| journal_unavailable())? {
        return Err(journal_unavailable());
    }
    #[cfg(not(unix))]
    let _ = conn;
    Ok(())
}

fn verify_metadata(
    conn: &Connection,
    key: &PreparedFencedTransitionJournalKey,
) -> Result<JournalMembership, StoreError> {
    verify_connection_profile(conn)?;
    if journal_application_id(conn)? != JOURNAL_APPLICATION_ID
        || journal_user_version(conn)? != JOURNAL_SCHEMA_VERSION
        || journal_schema_catalog_count(conn)? != JOURNAL_SCHEMA_OBJECT_COUNT
    {
        return Err(journal_unavailable());
    }
    verify_journal_schema(conn)?;
    let metadata_query = format!(
        "SELECT singleton, schema_version, key_check, journal_incarnation, membership_count, \
                membership_root, membership_tag \
         FROM prepared_fenced_transition_journal_metadata LIMIT {JOURNAL_METADATA_SCAN_LIMIT}"
    );
    let mut statement = conn
        .prepare(&metadata_query)
        .map_err(|_| journal_unavailable())?;
    let mut rows = statement.query([]).map_err(|_| journal_unavailable())?;
    let row = rows
        .next()
        .map_err(|_| journal_unavailable())?
        .ok_or_else(journal_unavailable)?;
    let singleton: i64 = row.get(0).map_err(|_| journal_unavailable())?;
    if singleton != 1 {
        return Err(journal_unavailable());
    }
    let ValueRef::Integer(schema_version) = row.get_ref(1).map_err(|_| journal_unavailable())?
    else {
        return Err(journal_unavailable());
    };
    let ValueRef::Integer(membership_count) = row.get_ref(4).map_err(|_| journal_unavailable())?
    else {
        return Err(journal_unavailable());
    };
    let metadata = JournalMetadata {
        schema_version,
        key_check: fixed_blob(row.get_ref(2).map_err(|_| journal_unavailable())?)
            .map_err(|_| journal_unavailable())?,
        membership: JournalMembership {
            incarnation: fixed_blob(row.get_ref(3).map_err(|_| journal_unavailable())?)
                .map_err(|_| journal_unavailable())?,
            count: membership_count,
            root: fixed_blob(row.get_ref(5).map_err(|_| journal_unavailable())?)
                .map_err(|_| journal_unavailable())?,
            tag: fixed_blob(row.get_ref(6).map_err(|_| journal_unavailable())?)
                .map_err(|_| journal_unavailable())?,
        },
    };
    if rows.next().map_err(|_| journal_unavailable())?.is_some() {
        return Err(journal_unavailable());
    }
    if metadata.schema_version != JOURNAL_SCHEMA_VERSION
        || !valid_membership_count(metadata.membership.count)
        || verify_key_check(key, &metadata.key_check).is_err()
    {
        return Err(journal_unavailable());
    }
    let actual = scan_journal_membership(
        conn,
        &metadata.membership.incarnation,
        metadata.membership.count,
    )?;
    if actual.count != metadata.membership.count || actual.root != metadata.membership.root {
        return Err(journal_unavailable());
    }
    verify_membership_tag(
        key,
        &metadata.membership.incarnation,
        metadata.membership.count,
        &metadata.membership.root,
        &metadata.membership.tag,
    )?;
    Ok(metadata.membership)
}

fn verify_connection_profile(conn: &Connection) -> Result<(), StoreError> {
    verify_journal_sqlite_limits(conn)?;
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())?;
    let synchronous: i64 = conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())?;
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())?;
    let locking_mode: String = conn
        .query_row("PRAGMA locking_mode", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())?;
    let temp_store: i64 = conn
        .query_row("PRAGMA temp_store", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())?;
    let secure_delete: i64 = conn
        .query_row("PRAGMA secure_delete", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous != 3
        || foreign_keys != 1
        || !locking_mode.eq_ignore_ascii_case("normal")
        || temp_store != 2
        || secure_delete != 1
    {
        return Err(journal_unavailable());
    }
    Ok(())
}

fn journal_sqlite_length_limit() -> Result<i32, StoreError> {
    let limit = FENCED_TRANSITION_MAX_PREPARED_BYTES
        .checked_add(JOURNAL_SQLITE_LENGTH_ROW_OVERHEAD_BYTES)
        .ok_or_else(journal_unavailable)?;
    i32::try_from(limit).map_err(|_| journal_unavailable())
}

fn configure_journal_sqlite_limits(conn: &Connection) -> Result<(), StoreError> {
    for (limit, requested) in journal_sqlite_limits()? {
        conn.set_limit(limit, requested);
    }
    verify_journal_sqlite_limits(conn)
}

fn journal_sqlite_limits() -> Result<[(Limit, i32); 9], StoreError> {
    Ok([
        (Limit::SQLITE_LIMIT_LENGTH, journal_sqlite_length_limit()?),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 16_384),
        (Limit::SQLITE_LIMIT_COLUMN, 16),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 32),
        (Limit::SQLITE_LIMIT_VDBE_OP, 10_000),
        (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 4),
        (Limit::SQLITE_LIMIT_FUNCTION_ARG, 16),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ])
}

fn verify_journal_sqlite_limits(conn: &Connection) -> Result<(), StoreError> {
    for (limit, requested) in journal_sqlite_limits()? {
        if conn.limit(limit) != requested {
            return Err(journal_unavailable());
        }
    }
    Ok(())
}

fn verify_journal_schema(conn: &Connection) -> Result<(), StoreError> {
    let expected = [
        (
            "table",
            "prepared_fenced_transition_journal_metadata",
            "prepared_fenced_transition_journal_metadata",
            format!(
                r#"CREATE TABLE prepared_fenced_transition_journal_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version = {JOURNAL_SCHEMA_VERSION}),
                    journal_incarnation BLOB NOT NULL CHECK (
                        typeof(journal_incarnation) = 'blob' AND length(journal_incarnation) = 32
                    ),
                    membership_count INTEGER NOT NULL CHECK (
                        membership_count >= 0
                        AND membership_count <= {FENCED_TRANSITION_MAX_HISTORY_ENTRIES}
                    ),
                    membership_root BLOB NOT NULL CHECK (
                        typeof(membership_root) = 'blob' AND length(membership_root) = 32
                    ),
                    membership_tag BLOB NOT NULL CHECK (
                        typeof(membership_tag) = 'blob' AND length(membership_tag) = 32
                    ),
                    key_check BLOB NOT NULL CHECK (
                        typeof(key_check) = 'blob' AND length(key_check) = 32
                    )
                ) STRICT"#
            ),
        ),
        (
            "table",
            "prepared_fenced_transition_journal",
            "prepared_fenced_transition_journal",
            format!(
                r#"CREATE TABLE prepared_fenced_transition_journal (
                    request_id BLOB PRIMARY KEY CHECK (
                        typeof(request_id) = 'blob' AND length(request_id) = 16
                    ),
                    prepared_schema_version INTEGER NOT NULL CHECK (
                        prepared_schema_version = {FENCED_TRANSITION_PREPARED_SCHEMA_V1}
                    ),
                    prepared_token BLOB NOT NULL CHECK (
                        typeof(prepared_token) = 'blob'
                        AND length(prepared_token) <= {FENCED_TRANSITION_MAX_PREPARED_BYTES}
                    ),
                    integrity_tag BLOB NOT NULL CHECK (
                        typeof(integrity_tag) = 'blob' AND length(integrity_tag) = 32
                    )
                ) STRICT"#
            ),
        ),
        (
            "index",
            "sqlite_autoindex_prepared_fenced_transition_journal_1",
            "prepared_fenced_transition_journal",
            String::new(),
        ),
        (
            "index",
            JOURNAL_MEMBERSHIP_INDEX,
            "prepared_fenced_transition_journal",
            format!(
                "CREATE INDEX {JOURNAL_MEMBERSHIP_INDEX} \
                 ON prepared_fenced_transition_journal (request_id, integrity_tag)"
            ),
        ),
    ];
    for (expected_type, name, expected_table_name, expected_sql) in expected {
        let row: Option<(String, String, Option<String>)> = conn
            .query_row(
                "SELECT type, tbl_name, sql FROM sqlite_schema WHERE name = ?1",
                params![name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| journal_unavailable())?;
        let Some((object_type, table_name, actual_sql)) = row else {
            return Err(journal_unavailable());
        };
        let sql_matches = if expected_sql.is_empty() {
            actual_sql.is_none()
        } else {
            actual_sql.is_some_and(|actual_sql| {
                canonical_schema_sql(&actual_sql) == canonical_schema_sql(&expected_sql)
            })
        };
        if object_type != expected_type || table_name != expected_table_name || !sql_matches {
            return Err(journal_unavailable());
        }
    }
    Ok(())
}

fn canonical_schema_sql(sql: &str) -> String {
    let trimmed = sql.trim();
    let trimmed = trimmed.strip_suffix(';').map_or(trimmed, str::trim_end);
    let mut normalized = String::with_capacity(trimmed.len());
    let mut quote = None;
    let mut whitespace_pending = false;
    let mut characters = trimmed.chars().peekable();
    while let Some(character) = characters.next() {
        if let Some(terminator) = quote {
            normalized.push(character);
            if character == terminator {
                if terminator != ']' && characters.peek() == Some(&terminator) {
                    if let Some(escaped) = characters.next() {
                        normalized.push(escaped);
                    }
                } else {
                    quote = None;
                }
            }
            continue;
        }
        if character.is_ascii_whitespace() {
            whitespace_pending = true;
            continue;
        }
        if whitespace_pending && !normalized.is_empty() {
            normalized.push(' ');
        }
        whitespace_pending = false;
        normalized.push(character);
        quote = match character {
            '\'' | '"' | '`' => Some(character),
            '[' => Some(']'),
            _ => None,
        };
    }
    normalized
}

fn journal_application_id(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())
}

fn journal_user_version(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())
}

fn journal_schema_catalog_count(conn: &Connection) -> Result<i64, StoreError> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT 1 FROM sqlite_schema LIMIT {JOURNAL_CATALOG_SCAN_LIMIT}"
        ))
        .map_err(|_| journal_unavailable())?;
    let mut rows = statement.query([]).map_err(|_| journal_unavailable())?;
    let mut count = 0_i64;
    while rows.next().map_err(|_| journal_unavailable())?.is_some() {
        count = count.checked_add(1).ok_or_else(journal_unavailable)?;
    }
    Ok(count)
}

fn journal_read_transaction(
    conn: &mut Connection,
) -> Result<rusqlite::Transaction<'_>, StoreError> {
    conn.transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| journal_unavailable())
}

struct JournalMetadata {
    schema_version: i64,
    key_check: [u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    membership: JournalMembership,
}

#[derive(Clone, Copy)]
struct JournalMembership {
    incarnation: [u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    count: i64,
    root: [u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    tag: [u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
}

struct JournalMembershipSnapshot {
    count: i64,
    root: [u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
}

struct MembershipRoot {
    hasher: Sha256,
}

impl MembershipRoot {
    fn new(
        incarnation: &[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
        count: i64,
    ) -> Result<Self, StoreError> {
        if !valid_membership_count(count) {
            return Err(journal_unavailable());
        }
        let mut hasher = Sha256::new();
        hasher.update(JOURNAL_MEMBERSHIP_ROOT_DOMAIN);
        hasher.update(incarnation);
        hasher.update(
            u64::try_from(count)
                .map_err(|_| journal_unavailable())?
                .to_be_bytes(),
        );
        Ok(Self { hasher })
    }

    fn include(
        &mut self,
        request_id: FencedTransitionRequestId,
        integrity_tag: &[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    ) {
        self.hasher.update(request_id.as_bytes());
        self.hasher.update(integrity_tag);
    }

    fn finalize(self) -> [u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES] {
        self.hasher.finalize().into()
    }
}

fn valid_membership_count(count: i64) -> bool {
    count >= 0
        && usize::try_from(count).is_ok_and(|count| count <= FENCED_TRANSITION_MAX_HISTORY_ENTRIES)
}

fn scan_journal_membership(
    conn: &Connection,
    incarnation: &[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    expected_count: i64,
) -> Result<JournalMembershipSnapshot, StoreError> {
    if !valid_membership_count(expected_count) {
        return Err(journal_unavailable());
    }
    let mut root = MembershipRoot::new(incarnation, expected_count)?;
    let mut statement = conn
        .prepare(&format!(
            "SELECT request_id, integrity_tag \
             FROM prepared_fenced_transition_journal \
             INDEXED BY prepared_fenced_transition_journal_membership_idx \
             ORDER BY request_id ASC \
             LIMIT {JOURNAL_MEMBERSHIP_SCAN_LIMIT}",
        ))
        .map_err(|_| journal_unavailable())?;
    let mut rows = statement.query([]).map_err(|_| journal_unavailable())?;
    let mut observed_count = 0_i64;
    while let Some(row) = rows.next().map_err(|_| journal_unavailable())? {
        if observed_count
            >= i64::try_from(FENCED_TRANSITION_MAX_HISTORY_ENTRIES)
                .map_err(|_| journal_unavailable())?
        {
            return Err(journal_unavailable());
        }
        let request_id = FencedTransitionRequestId::from_bytes(
            fixed_blob::<FENCED_TRANSITION_REQUEST_ID_BYTES>(
                row.get_ref(0).map_err(|_| journal_unavailable())?,
            )
            .map_err(|_| journal_unavailable())?,
        );
        let integrity_tag = fixed_blob(row.get_ref(1).map_err(|_| journal_unavailable())?)
            .map_err(|_| journal_unavailable())?;
        root.include(request_id, &integrity_tag);
        observed_count = observed_count
            .checked_add(1)
            .ok_or_else(journal_unavailable)?;
    }
    if observed_count != expected_count {
        return Err(journal_unavailable());
    }
    Ok(JournalMembershipSnapshot {
        count: expected_count,
        root: root.finalize(),
    })
}

fn read_entry(
    conn: &Connection,
    key: &PreparedFencedTransitionJournalKey,
    request_id: FencedTransitionRequestId,
) -> Result<Option<PreparedFencedTransition>, StoreError> {
    let row: Option<(
        Zeroizing<Vec<u8>>,
        [u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    )> = conn
        .query_row(
            "SELECT prepared_schema_version, prepared_token, integrity_tag \
             FROM prepared_fenced_transition_journal WHERE request_id = ?1",
            params![request_id.as_bytes().as_slice()],
            |row| {
                let ValueRef::Integer(schema_version) = row.get_ref(0)? else {
                    return Err(rusqlite::Error::InvalidQuery);
                };
                if schema_version != i64::from(FENCED_TRANSITION_PREPARED_SCHEMA_V1) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok((
                    bounded_token(row.get_ref(1)?)?,
                    fixed_blob(row.get_ref(2)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| journal_unavailable())?;
    let Some((token, stored_tag)) = row else {
        return Ok(None);
    };
    if verify_entry_tag(key, request_id, &token, &stored_tag).is_err() {
        return Err(journal_unavailable());
    }
    let prepared =
        PreparedFencedTransition::try_from_bytes(&token).map_err(|_| journal_unavailable())?;
    if prepared.request_id() != request_id {
        return Err(journal_unavailable());
    }
    Ok(Some(prepared))
}

fn fixed_blob<const N: usize>(value: ValueRef<'_>) -> rusqlite::Result<[u8; N]> {
    let ValueRef::Blob(bytes) = value else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn bounded_token(value: ValueRef<'_>) -> rusqlite::Result<Zeroizing<Vec<u8>>> {
    let ValueRef::Blob(bytes) = value else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    if bytes.is_empty() || bytes.len() > FENCED_TRANSITION_MAX_PREPARED_BYTES {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}

fn key_check(key: &PreparedFencedTransitionJournalKey) -> Result<[u8; 32], StoreError> {
    let mut mac = HmacSha256::new(key.as_bytes());
    mac.update(JOURNAL_KEY_CHECK_DOMAIN);
    Ok(*mac.finalize())
}

fn verify_key_check(
    key: &PreparedFencedTransitionJournalKey,
    stored: &[u8],
) -> Result<(), StoreError> {
    let mut mac = HmacSha256::new(key.as_bytes());
    mac.update(JOURNAL_KEY_CHECK_DOMAIN);
    if mac.verify_slice(stored) {
        Ok(())
    } else {
        Err(journal_unavailable())
    }
}

fn entry_tag(
    key: &PreparedFencedTransitionJournalKey,
    request_id: FencedTransitionRequestId,
    canonical: &[u8],
) -> Result<[u8; 32], StoreError> {
    let length = u32::try_from(canonical.len()).map_err(|_| journal_unavailable())?;
    let mut mac = HmacSha256::new(key.as_bytes());
    mac.update(JOURNAL_ENTRY_DOMAIN);
    mac.update(request_id.as_bytes());
    mac.update(&FENCED_TRANSITION_PREPARED_SCHEMA_V1.to_be_bytes());
    mac.update(&length.to_be_bytes());
    mac.update(canonical);
    Ok(*mac.finalize())
}

fn verify_entry_tag(
    key: &PreparedFencedTransitionJournalKey,
    request_id: FencedTransitionRequestId,
    canonical: &[u8],
    stored: &[u8],
) -> Result<(), StoreError> {
    let length = u32::try_from(canonical.len()).map_err(|_| journal_unavailable())?;
    let mut mac = HmacSha256::new(key.as_bytes());
    mac.update(JOURNAL_ENTRY_DOMAIN);
    mac.update(request_id.as_bytes());
    mac.update(&FENCED_TRANSITION_PREPARED_SCHEMA_V1.to_be_bytes());
    mac.update(&length.to_be_bytes());
    mac.update(canonical);
    if mac.verify_slice(stored) {
        Ok(())
    } else {
        Err(journal_unavailable())
    }
}

fn membership_tag(
    key: &PreparedFencedTransitionJournalKey,
    incarnation: &[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    count: i64,
    root: &[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
) -> Result<[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES], StoreError> {
    if !valid_membership_count(count) {
        return Err(journal_unavailable());
    }
    let mut mac = HmacSha256::new(key.as_bytes());
    mac.update(JOURNAL_MEMBERSHIP_TAG_DOMAIN);
    mac.update(incarnation);
    let encoded_count = u64::try_from(count)
        .map_err(|_| journal_unavailable())?
        .to_be_bytes();
    mac.update(&encoded_count);
    mac.update(root);
    Ok(*mac.finalize())
}

fn verify_membership_tag(
    key: &PreparedFencedTransitionJournalKey,
    incarnation: &[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    count: i64,
    root: &[u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    stored: &[u8],
) -> Result<(), StoreError> {
    if !valid_membership_count(count) {
        return Err(journal_unavailable());
    }
    let mut mac = HmacSha256::new(key.as_bytes());
    mac.update(JOURNAL_MEMBERSHIP_TAG_DOMAIN);
    mac.update(incarnation);
    let encoded_count = u64::try_from(count)
        .map_err(|_| journal_unavailable())?
        .to_be_bytes();
    mac.update(&encoded_count);
    mac.update(root);
    if mac.verify_slice(stored) {
        Ok(())
    } else {
        Err(journal_unavailable())
    }
}

fn journal_unavailable() -> StoreError {
    StoreError::BackendUnavailable(JOURNAL_UNAVAILABLE.into())
}

fn prepare_secure_journal_path(
    path: &Path,
    mode: JournalOpenMode,
) -> Result<PreparedJournalPath, StoreError> {
    if path.file_name().is_none() {
        return Err(journal_unavailable());
    }

    #[cfg(unix)]
    {
        prepare_secure_journal_path_unix(path, mode)
    }

    #[cfg(not(unix))]
    {
        let _ = mode;
        Err(journal_unavailable())
    }
}

#[cfg(unix)]
impl SecureJournalPathGuard {
    fn verify(&self) -> Result<(), StoreError> {
        use nix::{
            fcntl::AtFlags,
            sys::stat::{fstat, fstatat},
        };

        let root = fstat(&self.root).map_err(|_| journal_unavailable())?;
        let effective_uid = nix::unistd::geteuid().as_raw();
        if !is_trusted_ancestor(&root, effective_uid) {
            return Err(journal_unavailable());
        }
        let mut prior = &self.root;
        for (index, (directory, name)) in self.ancestors.iter().enumerate() {
            let actual = fstat(directory).map_err(|_| journal_unavailable())?;
            let visible = fstatat(prior, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| journal_unavailable())?;
            let final_parent = index + 1 == self.ancestors.len();
            if !same_file(&actual, &visible)
                || if final_parent {
                    !is_private_parent(&actual, effective_uid)
                } else {
                    !is_trusted_ancestor(&actual, effective_uid)
                }
            {
                return Err(journal_unavailable());
            }
            prior = directory;
        }
        let parent = fstat(&self.parent).map_err(|_| journal_unavailable())?;
        let leaf = fstat(&self.leaf).map_err(|_| journal_unavailable())?;
        let visible = fstatat(
            &self.parent,
            self.leaf_name.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|_| journal_unavailable())?;
        if !is_private_parent(&parent, effective_uid)
            || !is_private_leaf(&leaf, effective_uid)
            || !same_file(&leaf, &visible)
        {
            return Err(journal_unavailable());
        }
        Ok(())
    }

    fn verify_connection(&self, conn: &Connection) -> Result<(), StoreError> {
        self.verify()?;
        verify_sqlite_main_file_binding(conn)
    }
}

#[cfg(unix)]
fn prepare_secure_journal_path_unix(
    path: &Path,
    mode: JournalOpenMode,
) -> Result<PreparedJournalPath, StoreError> {
    use nix::{
        fcntl::{open, openat, AtFlags, OFlag},
        sys::stat::{fstat, fstatat, Mode},
    };

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| journal_unavailable())?
            .join(path)
    };
    let mut components = absolute.components();
    if components.next() != Some(std::path::Component::RootDir) {
        return Err(journal_unavailable());
    }
    let names: Vec<std::ffi::OsString> = components
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(journal_unavailable()),
        })
        .collect::<Result<_, _>>()?;
    let Some((leaf_name, parent_names)) = names.split_last() else {
        return Err(journal_unavailable());
    };

    let directory_flags =
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let effective_uid = nix::unistd::geteuid().as_raw();
    let mut parent =
        open(Path::new("/"), directory_flags, Mode::empty()).map_err(|_| journal_unavailable())?;
    let root = std::fs::File::from(parent.try_clone().map_err(|_| journal_unavailable())?);
    let mut ancestors = Vec::with_capacity(parent_names.len());
    if !is_trusted_ancestor(
        &fstat(&parent).map_err(|_| journal_unavailable())?,
        effective_uid,
    ) {
        return Err(journal_unavailable());
    }
    for (index, name) in parent_names.iter().enumerate() {
        let next = openat(&parent, name.as_os_str(), directory_flags, Mode::empty())
            .map_err(|_| journal_unavailable())?;
        let metadata = fstat(&next).map_err(|_| journal_unavailable())?;
        let is_immediate_parent = index + 1 == parent_names.len();
        if if is_immediate_parent {
            !is_private_parent(&metadata, effective_uid)
        } else {
            !is_trusted_ancestor(&metadata, effective_uid)
        } {
            return Err(journal_unavailable());
        }
        ancestors.push((
            std::fs::File::from(next.try_clone().map_err(|_| journal_unavailable())?),
            name.clone(),
        ));
        parent = next;
    }
    if parent_names.is_empty()
        && !is_private_parent(
            &fstat(&parent).map_err(|_| journal_unavailable())?,
            effective_uid,
        )
    {
        return Err(journal_unavailable());
    }

    let existing = fstatat(&parent, leaf_name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW);
    let leaf = match existing {
        Ok(metadata) => {
            if mode == JournalOpenMode::CreateNew {
                return Err(journal_unavailable());
            }
            if !is_private_leaf(&metadata, effective_uid) {
                return Err(journal_unavailable());
            }
            openat(
                &parent,
                leaf_name.as_os_str(),
                OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| journal_unavailable())?
        }
        Err(nix::errno::Errno::ENOENT) if mode == JournalOpenMode::CreateNew => {
            let leaf = openat(
                &parent,
                leaf_name.as_os_str(),
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|_| journal_unavailable())?;
            std::fs::File::from(parent.try_clone().map_err(|_| journal_unavailable())?)
                .sync_all()
                .map_err(|_| journal_unavailable())?;
            leaf
        }
        Err(_) => return Err(journal_unavailable()),
    };
    let leaf_metadata = fstat(&leaf).map_err(|_| journal_unavailable())?;
    let visible = fstatat(&parent, leaf_name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|_| journal_unavailable())?;
    if !is_private_leaf(&leaf_metadata, effective_uid) || !same_file(&leaf_metadata, &visible) {
        return Err(journal_unavailable());
    }

    let sqlite_path = sqlite_descriptor_path(&parent, leaf_name, &leaf_metadata)?;
    Ok(PreparedJournalPath {
        sqlite_path,
        path_guard: SecureJournalPathGuard {
            root,
            ancestors,
            parent: std::fs::File::from(parent),
            leaf: std::fs::File::from(leaf),
            leaf_name: leaf_name.clone(),
        },
    })
}

#[cfg(unix)]
fn sqlite_descriptor_path(
    parent: &std::os::fd::OwnedFd,
    leaf_name: &std::ffi::OsStr,
    expected_leaf: &nix::sys::stat::FileStat,
) -> Result<PathBuf, StoreError> {
    use std::os::fd::AsRawFd;

    use nix::{
        fcntl::{open, OFlag},
        sys::stat::{fstat, Mode},
    };

    #[cfg(target_os = "linux")]
    let anchor = PathBuf::from("/proc/self/fd").join(parent.as_raw_fd().to_string());
    #[cfg(not(target_os = "linux"))]
    let anchor = PathBuf::from("/dev/fd").join(parent.as_raw_fd().to_string());

    let anchor_metadata = std::fs::metadata(&anchor).map_err(|_| journal_unavailable())?;
    let held_parent = std::fs::File::from(parent.try_clone().map_err(|_| journal_unavailable())?);
    if !same_metadata_file(
        &anchor_metadata,
        &held_parent.metadata().map_err(|_| journal_unavailable())?,
    ) {
        return Err(journal_unavailable());
    }
    let candidate = anchor.join(leaf_name);
    let visible = open(
        &candidate,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| journal_unavailable())?;
    if !same_file(
        &fstat(&visible).map_err(|_| journal_unavailable())?,
        expected_leaf,
    ) {
        return Err(journal_unavailable());
    }
    Ok(candidate)
}

#[cfg(unix)]
fn is_trusted_ancestor(metadata: &nix::sys::stat::FileStat, effective_uid: u32) -> bool {
    let mode = metadata.st_mode as libc::mode_t;
    (mode & libc::S_IFMT == libc::S_IFDIR)
        && (metadata.st_uid == effective_uid || metadata.st_uid == 0)
        && (mode & 0o022 == 0 || (metadata.st_uid == 0 && mode & libc::S_ISVTX != 0))
}

#[cfg(unix)]
fn is_private_parent(metadata: &nix::sys::stat::FileStat, effective_uid: u32) -> bool {
    let mode = metadata.st_mode as libc::mode_t;
    mode & libc::S_IFMT == libc::S_IFDIR && metadata.st_uid == effective_uid && mode & 0o7077 == 0
}

#[cfg(unix)]
fn is_private_leaf(metadata: &nix::sys::stat::FileStat, effective_uid: u32) -> bool {
    let mode = metadata.st_mode as libc::mode_t;
    mode & libc::S_IFMT == libc::S_IFREG
        && metadata.st_uid == effective_uid
        && mode & 0o7177 == 0
        && metadata.st_nlink == 1
}

#[cfg(unix)]
fn same_file(left: &nix::sys::stat::FileStat, right: &nix::sys::stat::FileStat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

#[cfg(unix)]
fn same_metadata_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc, time::Duration};

    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    use super::*;
    use crate::{
        FenceToken, FencedTransitionLease, FencedTransitionMutation, FencedTransitionRequest,
        Generation, LeaseGuard, OwnerId, SessionKey, SessionKeyType, StableId,
    };

    struct JournalFixture {
        _directory: tempfile::TempDir,
        path: PathBuf,
        key: [u8; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
    }

    impl JournalFixture {
        fn new(fill: u8) -> Self {
            let directory = tempfile::tempdir().expect("journal test directory");
            make_private(directory.path());
            let path = directory.path().join("prepared.sqlite3");
            Self {
                _directory: directory,
                path,
                key: [fill; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
            }
        }

        fn open(&self) -> PreparedFencedTransitionJournal {
            let key = PreparedFencedTransitionJournalKey::from_bytes(self.key);
            if self.path.exists() {
                PreparedFencedTransitionJournal::open_existing(&self.path, key)
            } else {
                PreparedFencedTransitionJournal::create_new(&self.path, key)
            }
            .expect("open journal fixture")
        }
    }

    fn make_private(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("set private fixture permissions");
        }
    }

    fn prepared(request_id: u8) -> PreparedFencedTransition {
        prepared_with_request_id([request_id; FENCED_TRANSITION_REQUEST_ID_BYTES])
    }

    fn prepared_with_request_id(
        request_id: [u8; FENCED_TRANSITION_REQUEST_ID_BYTES],
    ) -> PreparedFencedTransition {
        let key = SessionKey {
            tenant: TenantId::from_static("journal-test"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"journal-test-id")).expect("stable ID"),
        };
        let owner = OwnerId::new("journal-test-owner").expect("owner");
        let acquired_at = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(10),
        );
        let expires_at = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(70),
        );
        let guard = LeaseGuard::new(key, owner, FenceToken::new(9), acquired_at, expires_at, 1);
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes(request_id),
            FencedTransitionLease::renew(guard, Duration::from_secs(30)).expect("renewal"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("record-free request");
        PreparedFencedTransition::from_unprotected_request(request).expect("prepared request")
    }

    #[test]
    fn open_existing_missing_journal_never_creates_a_pristine_database() {
        let fixture = JournalFixture::new(0x11);
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        ));
        assert!(!fixture.path.exists());
    }

    #[tokio::test]
    async fn create_new_provisions_once_and_open_existing_reopens() {
        let fixture = JournalFixture::new(0x12);
        let journal = PreparedFencedTransitionJournal::create_new(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        )
        .expect("provision journal");
        assert_coarse_unavailable(PreparedFencedTransitionJournal::create_new(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        ));
        drop(journal);
        PreparedFencedTransitionJournal::open_existing(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        )
        .expect("reopen provisioned journal")
        .health_check()
        .await
        .expect("reopened journal health");
    }

    #[test]
    fn open_existing_rejects_same_inode_truncate_instead_of_reinitializing() {
        let fixture = JournalFixture::new(0x13);
        drop(fixture.open());
        std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .expect("open provisioned journal")
            .set_len(0)
            .expect("truncate provisioned journal");
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        ));
    }

    fn assert_coarse_unavailable<T>(result: Result<T, StoreError>) {
        match result {
            Err(StoreError::BackendUnavailable(message)) => {
                assert_eq!(message, JOURNAL_UNAVAILABLE);
            }
            Ok(_) | Err(_) => panic!("journal failure was not coarsely classified"),
        }
    }

    async fn assert_live_integrity_failure(
        journal: &PreparedFencedTransitionJournal,
        request_id: FencedTransitionRequestId,
    ) {
        assert_coarse_unavailable(journal.health_check().await);
        assert_coarse_unavailable(journal.lookup(request_id).await);
    }

    #[tokio::test]
    async fn prepared_journal_recovers_exact_token_after_reopen_and_rejects_rebinding() {
        let fixture = JournalFixture::new(0x41);
        let first = fixture.open();
        let retained = prepared(0x51);
        first.insert(&retained).await.expect("durable insert");
        assert_eq!(
            first.lookup(retained.request_id()).await.expect("lookup"),
            PreparedFencedTransitionLookup::Found(retained.clone())
        );
        assert_eq!(
            first.insert(&retained).await,
            Err(StoreError::FencedTransitionRequestConflict)
        );
        drop(first);

        let reopened = fixture.open();
        assert_eq!(
            reopened
                .lookup(retained.request_id())
                .await
                .expect("restart lookup"),
            PreparedFencedTransitionLookup::Found(retained.clone())
        );
        let replacement = prepared(0x52);
        assert_eq!(
            reopened
                .lookup(replacement.request_id())
                .await
                .expect("unbound lookup"),
            PreparedFencedTransitionLookup::Absent
        );
        assert!(reopened
            .require_exact(&retained)
            .await
            .expect("exact binding")
            .is_some());
        reopened
            .health_check()
            .await
            .expect("reopen integrity check");
    }

    #[tokio::test]
    async fn prepared_journal_read_snapshot_does_not_reserve_the_wal_writer() {
        let fixture = JournalFixture::new(0x68);
        let reader = fixture.open();
        let writer = fixture.open();
        let retained = prepared(0x69);
        let (snapshot_started_tx, snapshot_started_rx) = tokio::sync::oneshot::channel();
        let (release_snapshot_tx, release_snapshot_rx) = tokio::sync::oneshot::channel();

        let held_snapshot = tokio::spawn(async move {
            reader
                .with_connection(move |conn, key| {
                    let transaction = journal_read_transaction(conn)?;
                    verify_metadata(&transaction, key)?;
                    snapshot_started_tx
                        .send(())
                        .map_err(|_| journal_unavailable())?;
                    release_snapshot_rx
                        .blocking_recv()
                        .map_err(|_| journal_unavailable())?;
                    transaction.commit().map_err(|_| journal_unavailable())
                })
                .await
        });

        snapshot_started_rx
            .await
            .expect("reader reached a stable WAL snapshot");
        writer
            .insert(&retained)
            .await
            .expect("writer proceeds beside a read snapshot");
        release_snapshot_tx
            .send(())
            .expect("release the read snapshot");
        held_snapshot
            .await
            .expect("join read snapshot task")
            .expect("finish read snapshot");
    }

    #[tokio::test]
    async fn prepared_journal_public_reads_do_not_request_the_wal_writer() {
        let fixture = JournalFixture::new(0x6a);
        let journal = fixture.open();
        let retained = prepared(0x6b);
        journal.insert(&retained).await.expect("durable insert");

        let mut writer = Connection::open(&fixture.path).expect("open reserved writer fixture");
        let reserved_writer = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("reserve the WAL writer");
        assert!(matches!(
            journal.lookup(retained.request_id()).await,
            Ok(PreparedFencedTransitionLookup::Found(_))
        ));
        journal
            .health_check()
            .await
            .expect("health remains a read transaction");
        reserved_writer
            .rollback()
            .expect("release reserved WAL writer");
    }

    #[tokio::test]
    async fn prepared_journal_enforces_membership_capacity_boundary() {
        let fixture = JournalFixture::new(0x69);
        drop(fixture.open());
        let mut connection = Connection::open(&fixture.path).expect("open capacity fixture");
        let transaction = connection
            .transaction()
            .expect("start capacity transaction");
        let incarnation = transaction
            .query_row(
                "SELECT journal_incarnation FROM prepared_fenced_transition_journal_metadata",
                [],
                |row| fixed_blob(row.get_ref(0)?),
            )
            .expect("read journal incarnation");
        let capacity = i64::try_from(FENCED_TRANSITION_MAX_HISTORY_ENTRIES)
            .expect("history capacity is representable");
        let key = PreparedFencedTransitionJournalKey::from_bytes(fixture.key);
        let mut root = MembershipRoot::new(&incarnation, capacity).expect("start capacity root");
        for ordinal in 0..FENCED_TRANSITION_MAX_HISTORY_ENTRIES {
            let mut request_id = [0_u8; FENCED_TRANSITION_REQUEST_ID_BYTES];
            request_id[8..].copy_from_slice(
                &u64::try_from(ordinal + 1)
                    .expect("ordinal is representable")
                    .to_be_bytes(),
            );
            let retained = prepared_with_request_id(request_id);
            let tag = entry_tag(&key, retained.request_id(), retained.as_bytes())
                .expect("capacity row tag");
            transaction
                .execute(
                    "INSERT INTO prepared_fenced_transition_journal \
                     (request_id, prepared_schema_version, prepared_token, integrity_tag) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        retained.request_id().as_bytes().as_slice(),
                        i64::from(FENCED_TRANSITION_PREPARED_SCHEMA_V1),
                        retained.as_bytes(),
                        tag.as_slice(),
                    ],
                )
                .expect("insert capacity row");
            root.include(retained.request_id(), &tag);
        }
        let root = root.finalize();
        let tag = membership_tag(&key, &incarnation, capacity, &root).expect("capacity tag");
        transaction
            .execute(
                "UPDATE prepared_fenced_transition_journal_metadata \
                 SET membership_count = ?1, membership_root = ?2, membership_tag = ?3",
                params![capacity, root.as_slice(), tag.as_slice()],
            )
            .expect("commit capacity membership");
        transaction.commit().expect("finish capacity transaction");
        drop(connection);

        let journal = fixture.open();
        let overflow = prepared_with_request_id([0xff; FENCED_TRANSITION_REQUEST_ID_BYTES]);
        assert_eq!(
            journal.ensure_absent(overflow.request_id()).await,
            Err(StoreError::FencedTransitionHistoryFull)
        );
        assert_eq!(
            journal.insert(&overflow).await,
            Err(StoreError::FencedTransitionHistoryFull)
        );
    }

    #[tokio::test]
    async fn prepared_journal_rejects_deleted_membership_at_health_lookup_and_absence_check() {
        let fixture = JournalFixture::new(0x70);
        let journal = fixture.open();
        let retained = prepared(0x71);
        journal.insert(&retained).await.expect("durable insert");

        let connection = Connection::open(&fixture.path).expect("open deletion fixture");
        connection
            .execute("DELETE FROM prepared_fenced_transition_journal", [])
            .expect("delete retained row");
        drop(connection);

        assert_live_integrity_failure(&journal, retained.request_id()).await;
        assert_coarse_unavailable(journal.ensure_absent(retained.request_id()).await);
    }

    #[tokio::test]
    async fn prepared_journal_rejects_primary_key_membership_replacement() {
        let fixture = JournalFixture::new(0x72);
        let journal = fixture.open();
        let retained = prepared(0x73);
        let replacement = prepared(0x74);
        journal.insert(&retained).await.expect("durable insert");
        let replacement_tag = entry_tag(
            &PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
            replacement.request_id(),
            replacement.as_bytes(),
        )
        .expect("replacement tag");

        let connection = Connection::open(&fixture.path).expect("open primary-key fixture");
        connection
            .execute(
                "UPDATE prepared_fenced_transition_journal \
                 SET request_id = ?1, prepared_token = ?2, integrity_tag = ?3",
                params![
                    replacement.request_id().as_bytes().as_slice(),
                    replacement.as_bytes(),
                    replacement_tag.as_slice(),
                ],
            )
            .expect("replace valid row under a different primary key");
        drop(connection);

        assert_live_integrity_failure(&journal, replacement.request_id()).await;
    }

    #[tokio::test]
    async fn prepared_journal_rejects_extra_valid_membership_row() {
        let fixture = JournalFixture::new(0x75);
        let journal = fixture.open();
        let retained = prepared(0x76);
        let extra = prepared(0x77);
        journal.insert(&retained).await.expect("durable insert");
        let extra_tag = entry_tag(
            &PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
            extra.request_id(),
            extra.as_bytes(),
        )
        .expect("extra row tag");

        let connection = Connection::open(&fixture.path).expect("open addition fixture");
        connection
            .execute(
                "INSERT INTO prepared_fenced_transition_journal \
                 (request_id, prepared_schema_version, prepared_token, integrity_tag) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    extra.request_id().as_bytes().as_slice(),
                    i64::from(FENCED_TRANSITION_PREPARED_SCHEMA_V1),
                    extra.as_bytes(),
                    extra_tag.as_slice(),
                ],
            )
            .expect("insert independently valid extra row");
        drop(connection);

        assert_live_integrity_failure(&journal, retained.request_id()).await;
    }

    #[tokio::test]
    async fn prepared_journal_rejects_tag_globally_and_body_for_the_selected_identity() {
        let tag_fixture = JournalFixture::new(0x78);
        let tag_journal = tag_fixture.open();
        let tag_retained = prepared(0x79);
        tag_journal
            .insert(&tag_retained)
            .await
            .expect("durable insert");
        let connection = Connection::open(&tag_fixture.path).expect("open tag fixture");
        connection
            .execute(
                "UPDATE prepared_fenced_transition_journal SET integrity_tag = zeroblob(32)",
                [],
            )
            .expect("corrupt row tag");
        drop(connection);
        assert_live_integrity_failure(&tag_journal, tag_retained.request_id()).await;

        let body_fixture = JournalFixture::new(0x7a);
        let body_journal = body_fixture.open();
        let body_retained = prepared(0x7b);
        let substituted = prepared(0x7c);
        body_journal
            .insert(&body_retained)
            .await
            .expect("durable insert");
        let connection = Connection::open(&body_fixture.path).expect("open body fixture");
        connection
            .execute(
                "UPDATE prepared_fenced_transition_journal SET prepared_token = ?1",
                params![substituted.as_bytes()],
            )
            .expect("corrupt row body");
        drop(connection);
        body_journal
            .health_check()
            .await
            .expect("membership remains authenticated");
        assert_coarse_unavailable(body_journal.lookup(body_retained.request_id()).await);
        assert_coarse_unavailable(body_journal.ensure_absent(body_retained.request_id()).await);
    }

    #[tokio::test]
    async fn prepared_journal_wrong_key_and_corruption_fail_with_fixed_diagnostics() {
        let fixture = JournalFixture::new(0x42);
        let journal = fixture.open();
        let retained = prepared(0x53);
        journal.insert(&retained).await.expect("durable insert");
        drop(journal);

        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(
                [0x43; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
            ),
        ));

        let connection = Connection::open(&fixture.path).expect("open fixture for corruption");
        connection
            .execute(
                "UPDATE prepared_fenced_transition_journal SET integrity_tag = zeroblob(32)",
                [],
            )
            .expect("corrupt integrity tag");
        drop(connection);

        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        ));
    }

    #[test]
    fn prepared_journal_rejects_foreign_schema_and_partial_initialization() {
        let foreign = JournalFixture::new(0x44);
        {
            let connection = Connection::open(&foreign.path).expect("open foreign fixture");
            connection
                .execute("CREATE TABLE foreign_table (value INTEGER) STRICT", [])
                .expect("create foreign schema");
            let journal_mode: String = connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .expect("read foreign journal mode");
            assert_eq!(journal_mode, "delete");
        }
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &foreign.path,
            PreparedFencedTransitionJournalKey::from_bytes(foreign.key),
        ));
        {
            let connection = Connection::open(&foreign.path).expect("reopen foreign fixture");
            let journal_mode: String = connection
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .expect("re-read foreign journal mode");
            assert_eq!(journal_mode, "delete");
        }

        let versioned = JournalFixture::new(0x45);
        drop(versioned.open());
        {
            let connection = Connection::open(&versioned.path).expect("open version fixture");
            connection
                .pragma_update(None, "user_version", JOURNAL_SCHEMA_VERSION + 1)
                .expect("advance incompatible version");
        }
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &versioned.path,
            PreparedFencedTransitionJournalKey::from_bytes(versioned.key),
        ));
    }

    #[test]
    fn prepared_journal_rejects_schema_replacement_and_non_durable_profile() {
        let replaced = JournalFixture::new(0x49);
        drop(replaced.open());
        {
            let connection = Connection::open(&replaced.path).expect("open schema fixture");
            connection
                .execute_batch(
                    r#"
                    DROP TABLE prepared_fenced_transition_journal;
                    CREATE TABLE prepared_fenced_transition_journal (
                        request_id BLOB PRIMARY KEY,
                        prepared_schema_version INTEGER NOT NULL,
                        prepared_token BLOB NOT NULL,
                        integrity_tag BLOB NOT NULL
                    ) STRICT;
                    "#,
                )
                .expect("replace journal table with query-compatible schema");
        }
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &replaced.path,
            PreparedFencedTransitionJournalKey::from_bytes(replaced.key),
        ));

        let missing_index = JournalFixture::new(0x5e);
        drop(missing_index.open());
        {
            let connection = Connection::open(&missing_index.path).expect("open index fixture");
            connection
                .execute(&format!("DROP INDEX {JOURNAL_MEMBERSHIP_INDEX}"), [])
                .expect("drop required membership index");
        }
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &missing_index.path,
            PreparedFencedTransitionJournalKey::from_bytes(missing_index.key),
        ));

        let profile = Connection::open_in_memory().expect("open profile fixture");
        assert_coarse_unavailable(verify_connection_profile(&profile));
    }

    #[test]
    fn prepared_journal_schema_normalization_preserves_sql_boundaries_and_literals() {
        let expected = "CREATE TABLE journal (value TEXT CHECK (value = 'a b')) STRICT;";
        let whitespace_variant =
            "  CREATE   TABLE journal (value TEXT CHECK (value = 'a b')) STRICT  ;  ";
        let statement_boundary = "CREATE TABLE journal (value TEXT CHECK (value = 'a b')); STRICT";
        let changed_literal = "CREATE TABLE journal (value TEXT CHECK (value = 'ab')) STRICT";

        assert_eq!(
            canonical_schema_sql(expected),
            canonical_schema_sql(whitespace_variant)
        );
        assert_ne!(
            canonical_schema_sql(expected),
            canonical_schema_sql(statement_boundary)
        );
        assert_ne!(
            canonical_schema_sql(expected),
            canonical_schema_sql(changed_literal)
        );
    }

    #[test]
    fn prepared_journal_membership_scan_uses_the_exact_covering_index() {
        let fixture = JournalFixture::new(0x5d);
        drop(fixture.open());
        let connection = Connection::open(&fixture.path).expect("open query-plan fixture");
        let detail: String = connection
            .query_row(
                "EXPLAIN QUERY PLAN \
                 SELECT request_id, integrity_tag \
                 FROM prepared_fenced_transition_journal \
                 INDEXED BY prepared_fenced_transition_journal_membership_idx \
                 ORDER BY request_id ASC",
                [],
                |row| row.get(3),
            )
            .expect("read membership query plan");
        assert!(detail.contains(&format!("COVERING INDEX {JOURNAL_MEMBERSHIP_INDEX}")));
    }

    #[test]
    fn prepared_journal_rejects_sqlitex_user_objects() {
        let fixture = JournalFixture::new(0x4a);
        drop(fixture.open());
        {
            let connection = Connection::open(&fixture.path).expect("open schema fixture");
            connection
                .execute_batch(
                    r#"
                    CREATE TABLE sqliteX_extra (value INTEGER) STRICT;
                    CREATE TRIGGER sqliteX_extra_trigger
                    AFTER INSERT ON prepared_fenced_transition_journal
                    BEGIN
                        DELETE FROM prepared_fenced_transition_journal
                        WHERE request_id = NEW.request_id;
                    END;
                    "#,
                )
                .expect("create non-internal sqliteX objects");
        }
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        ));
    }

    #[tokio::test]
    async fn prepared_journal_rejects_reserved_prefix_catalog_trigger_before_profile_setup() {
        let fixture = JournalFixture::new(0x4f);
        drop(fixture.open());
        {
            let connection = Connection::open(&fixture.path).expect("open catalog fixture");
            let journal_mode: String = connection
                .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
                .expect("set baseline journal mode");
            assert_eq!(journal_mode, "delete");
            connection
                .execute_batch(
                    r#"
                    PRAGMA writable_schema = ON;
                    INSERT INTO sqlite_schema (type, name, tbl_name, rootpage, sql)
                    VALUES (
                        'trigger',
                        'sqlite_prepared_journal_insert_guard',
                        'prepared_fenced_transition_journal',
                        0,
                        'CREATE TRIGGER sqlite_prepared_journal_insert_guard
                         BEFORE INSERT ON prepared_fenced_transition_journal
                         BEGIN SELECT RAISE(ABORT, ''blocked''); END'
                    );
                    PRAGMA writable_schema = OFF;
                    "#,
                )
                .expect("offline-craft reserved catalog trigger");
        }

        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        ));
        let connection = Connection::open(&fixture.path).expect("reopen catalog fixture");
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("read unchanged journal mode");
        assert_eq!(journal_mode, "delete");
        drop(connection);

        let live_fixture = JournalFixture::new(0x5f);
        let live_journal = live_fixture.open();
        let connection = Connection::open(&live_fixture.path).expect("open live catalog fixture");
        connection
            .execute_batch(
                r#"
                PRAGMA writable_schema = ON;
                INSERT INTO sqlite_schema (type, name, tbl_name, rootpage, sql)
                VALUES (
                    'trigger',
                    'sqlite_prepared_journal_live_guard',
                    'prepared_fenced_transition_journal',
                    0,
                    'CREATE TRIGGER sqlite_prepared_journal_live_guard
                     BEFORE INSERT ON prepared_fenced_transition_journal
                     BEGIN SELECT RAISE(ABORT, ''blocked''); END'
                );
                PRAGMA writable_schema = OFF;
                "#,
            )
            .expect("offline-craft live reserved catalog trigger");
        drop(connection);
        assert_coarse_unavailable(live_journal.health_check().await);
    }

    #[test]
    fn prepared_journal_rejects_check_bypassed_oversized_metadata_blob() {
        let fixture = JournalFixture::new(0x4f);
        drop(fixture.open());
        {
            let connection = Connection::open(&fixture.path).expect("open metadata fixture");
            connection
                .execute_batch(
                    r#"
                    PRAGMA ignore_check_constraints = ON;
                    UPDATE prepared_fenced_transition_journal_metadata
                    SET key_check = zeroblob(1048576);
                    "#,
                )
                .expect("bypass metadata check constraint");
        }
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        ));
    }

    #[test]
    fn prepared_journal_rejects_sqlite_length_limit_drift() {
        let fixture = JournalFixture::new(0x50);
        let mut connection = Connection::open(&fixture.path).expect("open length-limit fixture");
        configure_journal_sqlite_limits(&connection).expect("configure journal limits");
        initialize_connection(
            &mut connection,
            &PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
            JournalOpenMode::CreateNew,
        )
        .expect("initialize length-limit fixture");
        let lowered_limit = journal_sqlite_length_limit()
            .expect("journal length limit is representable")
            .checked_sub(1)
            .expect("journal length limit is positive");
        connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, lowered_limit);
        assert_coarse_unavailable(verify_connection_profile(&connection));
    }

    #[tokio::test]
    async fn prepared_journal_rejects_check_bypassed_oversized_entry_blobs() {
        let token_fixture = JournalFixture::new(0x51);
        let token = prepared(0x60);
        let token_journal = token_fixture.open();
        token_journal
            .insert(&token)
            .await
            .expect("insert token fixture");
        drop(token_journal);
        let beyond_connection_limit = usize::try_from(
            journal_sqlite_length_limit().expect("journal length limit is representable"),
        )
        .expect("journal length limit is nonnegative")
        .checked_add(1)
        .expect("test blob length is representable");
        {
            let connection = Connection::open(&token_fixture.path).expect("open token fixture");
            connection
                .execute_batch(&format!(
                    r#"
                    PRAGMA ignore_check_constraints = ON;
                    UPDATE prepared_fenced_transition_journal
                    SET prepared_token = zeroblob({});
                    "#,
                    beyond_connection_limit,
                ))
                .expect("bypass prepared-token check constraint");
        }
        let token_journal = PreparedFencedTransitionJournal::open_existing(
            &token_fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(token_fixture.key),
        )
        .expect("open membership-only token fixture");
        assert_coarse_unavailable(token_journal.lookup(token.request_id()).await);
        assert_coarse_unavailable(token_journal.ensure_absent(token.request_id()).await);

        let tag_fixture = JournalFixture::new(0x52);
        let tag = prepared(0x61);
        let tag_journal = tag_fixture.open();
        tag_journal.insert(&tag).await.expect("insert tag fixture");
        drop(tag_journal);
        {
            let connection = Connection::open(&tag_fixture.path).expect("open tag fixture");
            connection
                .execute_batch(
                    r#"
                    PRAGMA ignore_check_constraints = ON;
                    UPDATE prepared_fenced_transition_journal
                    SET integrity_tag = zeroblob(1048576);
                    "#,
                )
                .expect("bypass integrity-tag check constraint");
        }
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &tag_fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(tag_fixture.key),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_journal_rejects_public_directories_and_symlink_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let public_directory = tempfile::tempdir().expect("public fixture directory");
        std::fs::set_permissions(
            public_directory.path(),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("set public fixture permissions");
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            public_directory.path().join("prepared.sqlite3"),
            PreparedFencedTransitionJournalKey::from_bytes(
                [0x46; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
            ),
        ));

        let fixture = JournalFixture::new(0x47);
        let target = fixture.path.with_file_name("target.sqlite3");
        std::fs::File::create(&target).expect("create symlink target");
        symlink(&target, &fixture.path).expect("create fixture symlink");
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_journal_rejects_symlinked_parent_and_hardlinked_leaf() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let symlink_fixture = JournalFixture::new(0x4b);
        let real_parent = symlink_fixture._directory.path().join("real");
        std::fs::create_dir(&real_parent).expect("create real parent");
        make_private(&real_parent);
        let linked_parent = symlink_fixture._directory.path().join("linked");
        symlink(&real_parent, &linked_parent).expect("create parent symlink");
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            linked_parent.join("prepared.sqlite3"),
            PreparedFencedTransitionJournalKey::from_bytes(symlink_fixture.key),
        ));

        let hardlink_fixture = JournalFixture::new(0x4c);
        let original = hardlink_fixture.path.with_file_name("original.sqlite3");
        std::fs::File::create(&original).expect("create hardlink source");
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600))
            .expect("make hardlink source private");
        std::fs::hard_link(&original, &hardlink_fixture.path).expect("create hardlink leaf");
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
            &hardlink_fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(hardlink_fixture.key),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_journal_rejects_unowned_parent_when_testable() {
        use nix::unistd::{chown, geteuid, Uid};

        if geteuid().is_root() {
            let fixture = JournalFixture::new(0x4d);
            chown(fixture._directory.path(), Some(Uid::from_raw(1)), None)
                .expect("make parent unowned");
            assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
                &fixture.path,
                PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
            ));
        } else {
            assert_coarse_unavailable(PreparedFencedTransitionJournal::open_existing(
                Path::new("/").join("prepared.sqlite3"),
                PreparedFencedTransitionJournalKey::from_bytes(
                    [0x4d; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
                ),
            ));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_journal_fails_closed_after_live_leaf_swap() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = JournalFixture::new(0x4e);
        let journal = fixture.open();
        let replacement = fixture.path.with_file_name("replacement.sqlite3");
        std::fs::File::create(&replacement).expect("create replacement leaf");
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))
            .expect("make replacement leaf private");
        std::fs::rename(&replacement, &fixture.path).expect("replace journal leaf");

        assert_coarse_unavailable(
            journal
                .lookup(FencedTransitionRequestId::from_bytes([0x4e; 16]))
                .await,
        );
    }

    #[test]
    fn prepared_journal_debug_never_exposes_path_or_key() {
        let fixture = JournalFixture::new(0x48);
        let journal = Arc::new(fixture.open());
        assert_eq!(
            format!(
                "{:?}",
                PreparedFencedTransitionJournalKey::from_bytes(fixture.key)
            ),
            "PreparedFencedTransitionJournalKey(<redacted>)"
        );
        let debug = format!("{journal:?}");
        assert!(!debug.contains("prepared.sqlite3"));
        assert!(!debug.contains(&fixture.path.to_string_lossy().into_owned()));
    }
}
