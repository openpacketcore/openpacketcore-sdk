//! Durable caller-side retention for protected atomic-transition requests.
//!
//! The journal is deliberately separate from application session state. It
//! binds one caller-stable transition identity to the exact opaque prepared
//! request before any transport or consensus proposal can observe that
//! request. A later process can therefore recover the same protected bytes
//! without invoking a key or remote-seal provider again.

use std::{
    fmt,
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    FencedTransitionRequestId, PreparedFencedTransition, PreparedFencedTransitionLookup,
    StoreError, FENCED_TRANSITION_MAX_HISTORY_ENTRIES, FENCED_TRANSITION_MAX_PREPARED_BYTES,
    FENCED_TRANSITION_PREPARED_SCHEMA_V1,
};

/// Width of the independent integrity key protecting one prepared journal.
pub const PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES: usize = 32;

const JOURNAL_APPLICATION_ID: i64 = 0x4f50_464a;
const JOURNAL_SCHEMA_VERSION: i64 = 1;
const JOURNAL_BUSY_TIMEOUT: Duration = Duration::from_millis(100);
const JOURNAL_UNAVAILABLE: &str = "prepared fenced-transition journal unavailable";
const JOURNAL_KEY_CHECK_DOMAIN: &[u8] =
    b"openpacketcore/session-store/prepared-journal/key-check/v1\0";
const JOURNAL_ENTRY_DOMAIN: &[u8] = b"openpacketcore/session-store/prepared-journal/entry/v1\0";

type HmacSha256 = Hmac<Sha256>;

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
    /// Open or create one dedicated durable journal database.
    ///
    /// On Unix the containing directory and database must deny all group and
    /// other access. The path must not be a symlink. Other platforms must
    /// provide equivalent access control outside the SDK.
    pub fn open(
        path: impl AsRef<Path>,
        key: PreparedFencedTransitionJournalKey,
    ) -> Result<Self, StoreError> {
        let path = prepare_secure_journal_path(path.as_ref())?;
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
        #[cfg(unix)]
        {
            flags |= OpenFlags::SQLITE_OPEN_NOFOLLOW;
        }
        let mut conn =
            Connection::open_with_flags(&path, flags).map_err(|_| journal_unavailable())?;
        initialize_connection(&mut conn, &key)?;
        Ok(Self {
            inner: Arc::new(PreparedFencedTransitionJournalInner {
                conn: Mutex::new(conn),
                key,
            }),
            operation_permit: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }

    pub(crate) async fn health_check(&self) -> Result<(), StoreError> {
        self.with_connection(|conn, key| verify_metadata(conn, key))
            .await
    }

    pub(crate) async fn ensure_absent(
        &self,
        request_id: FencedTransitionRequestId,
    ) -> Result<(), StoreError> {
        match self.lookup(request_id).await? {
            PreparedFencedTransitionLookup::Absent => Ok(()),
            PreparedFencedTransitionLookup::Found(_) => {
                Err(StoreError::FencedTransitionRequestConflict)
            }
        }
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
            verify_metadata(&transaction, key)?;

            let existing = read_entry(&transaction, key, request_id)?;
            if existing.is_some() {
                return Err(StoreError::FencedTransitionRequestConflict);
            }
            let count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM prepared_fenced_transition_journal",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| journal_unavailable())?;
            if count < 0
                || usize::try_from(count).map_err(|_| journal_unavailable())?
                    >= FENCED_TRANSITION_MAX_HISTORY_ENTRIES
            {
                return Err(StoreError::FencedTransitionHistoryFull);
            }

            let tag = entry_tag(key, request_id, &canonical)?;
            transaction
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
            transaction.commit().map_err(|_| journal_unavailable())
        })
        .await
    }

    pub(crate) async fn lookup(
        &self,
        request_id: FencedTransitionRequestId,
    ) -> Result<PreparedFencedTransitionLookup, StoreError> {
        self.with_connection(move |conn, key| {
            verify_metadata(conn, key)?;
            read_entry(conn, key, request_id).map(|entry| match entry {
                Some(prepared) => PreparedFencedTransitionLookup::Found(prepared),
                None => PreparedFencedTransitionLookup::Absent,
            })
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
            operation(&mut conn, &inner.key)
        })
        .await
        .map_err(|_| journal_unavailable())?
    }
}

fn initialize_connection(
    conn: &mut Connection,
    key: &PreparedFencedTransitionJournalKey,
) -> Result<(), StoreError> {
    conn.busy_timeout(JOURNAL_BUSY_TIMEOUT)
        .map_err(|_| journal_unavailable())?;
    let initial_application_id = journal_application_id(conn)?;
    let initial_user_version = journal_user_version(conn)?;
    let initial_object_count = journal_user_object_count(conn)?;
    if !((initial_application_id == 0 && initial_user_version == 0 && initial_object_count == 0)
        || (initial_application_id == JOURNAL_APPLICATION_ID
            && initial_user_version == JOURNAL_SCHEMA_VERSION
            && initial_object_count == 2))
    {
        return Err(journal_unavailable());
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

    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| journal_unavailable())?;
    let application_id = journal_application_id(&transaction)?;
    let user_version = journal_user_version(&transaction)?;
    if application_id == 0 && user_version == 0 {
        if journal_user_object_count(&transaction)? != 0 {
            return Err(journal_unavailable());
        }
        transaction
            .execute_batch(&format!(
                r#"
            CREATE TABLE prepared_fenced_transition_journal_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL CHECK (schema_version = {JOURNAL_SCHEMA_VERSION}),
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
            PRAGMA application_id = {JOURNAL_APPLICATION_ID};
            PRAGMA user_version = {JOURNAL_SCHEMA_VERSION};
            "#
            ))
            .map_err(|_| journal_unavailable())?;
        let key_check = key_check(key)?;
        transaction
            .execute(
                "INSERT INTO prepared_fenced_transition_journal_metadata \
                 (singleton, schema_version, key_check) VALUES (1, ?1, ?2)",
                params![JOURNAL_SCHEMA_VERSION, key_check.as_slice()],
            )
            .map_err(|_| journal_unavailable())?;
    } else if application_id != JOURNAL_APPLICATION_ID || user_version != JOURNAL_SCHEMA_VERSION {
        return Err(journal_unavailable());
    }
    verify_metadata(&transaction, key)?;
    transaction.commit().map_err(|_| journal_unavailable())
}

fn verify_metadata(
    conn: &Connection,
    key: &PreparedFencedTransitionJournalKey,
) -> Result<(), StoreError> {
    if journal_application_id(conn)? != JOURNAL_APPLICATION_ID
        || journal_user_version(conn)? != JOURNAL_SCHEMA_VERSION
        || journal_user_object_count(conn)? != 2
    {
        return Err(journal_unavailable());
    }
    let row: Option<(i64, Vec<u8>)> = conn
        .query_row(
            "SELECT schema_version, key_check \
             FROM prepared_fenced_transition_journal_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| journal_unavailable())?;
    let Some((schema_version, stored_check)) = row else {
        return Err(journal_unavailable());
    };
    if schema_version != JOURNAL_SCHEMA_VERSION || verify_key_check(key, &stored_check).is_err() {
        return Err(journal_unavailable());
    }
    Ok(())
}

fn journal_application_id(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())
}

fn journal_user_version(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| journal_unavailable())
}

fn journal_user_object_count(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )
    .map_err(|_| journal_unavailable())
}

fn read_entry(
    conn: &Connection,
    key: &PreparedFencedTransitionJournalKey,
    request_id: FencedTransitionRequestId,
) -> Result<Option<PreparedFencedTransition>, StoreError> {
    let row: Option<(i64, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT prepared_schema_version, prepared_token, integrity_tag \
             FROM prepared_fenced_transition_journal WHERE request_id = ?1",
            params![request_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| journal_unavailable())?;
    let Some((schema_version, token, stored_tag)) = row else {
        return Ok(None);
    };
    if schema_version != i64::from(FENCED_TRANSITION_PREPARED_SCHEMA_V1) {
        return Err(journal_unavailable());
    }
    let token = Zeroizing::new(token);
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

fn key_check(key: &PreparedFencedTransitionJournalKey) -> Result<[u8; 32], StoreError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| journal_unavailable())?;
    mac.update(JOURNAL_KEY_CHECK_DOMAIN);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_key_check(
    key: &PreparedFencedTransitionJournalKey,
    stored: &[u8],
) -> Result<(), StoreError> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| journal_unavailable())?;
    mac.update(JOURNAL_KEY_CHECK_DOMAIN);
    mac.verify_slice(stored).map_err(|_| journal_unavailable())
}

fn entry_tag(
    key: &PreparedFencedTransitionJournalKey,
    request_id: FencedTransitionRequestId,
    canonical: &[u8],
) -> Result<[u8; 32], StoreError> {
    let length = u32::try_from(canonical.len()).map_err(|_| journal_unavailable())?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| journal_unavailable())?;
    mac.update(JOURNAL_ENTRY_DOMAIN);
    mac.update(request_id.as_bytes());
    mac.update(&FENCED_TRANSITION_PREPARED_SCHEMA_V1.to_be_bytes());
    mac.update(&length.to_be_bytes());
    mac.update(canonical);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_entry_tag(
    key: &PreparedFencedTransitionJournalKey,
    request_id: FencedTransitionRequestId,
    canonical: &[u8],
    stored: &[u8],
) -> Result<(), StoreError> {
    let length = u32::try_from(canonical.len()).map_err(|_| journal_unavailable())?;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| journal_unavailable())?;
    mac.update(JOURNAL_ENTRY_DOMAIN);
    mac.update(request_id.as_bytes());
    mac.update(&FENCED_TRANSITION_PREPARED_SCHEMA_V1.to_be_bytes());
    mac.update(&length.to_be_bytes());
    mac.update(canonical);
    mac.verify_slice(stored).map_err(|_| journal_unavailable())
}

fn journal_unavailable() -> StoreError {
    StoreError::BackendUnavailable(JOURNAL_UNAVAILABLE.into())
}

fn prepare_secure_journal_path(path: &Path) -> Result<PathBuf, StoreError> {
    if path.file_name().is_none() {
        return Err(journal_unavailable());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    #[cfg(unix)]
    {
        use std::os::unix::{fs::OpenOptionsExt, fs::PermissionsExt};

        let parent_metadata = std::fs::metadata(parent).map_err(|_| journal_unavailable())?;
        if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o077 != 0 {
            return Err(journal_unavailable());
        }
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(journal_unavailable());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut options = OpenOptions::new();
                options.read(true).write(true).create_new(true).mode(0o600);
                options.open(path).map_err(|_| journal_unavailable())?;
                std::fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| journal_unavailable())?;
            }
            Err(_) => return Err(journal_unavailable()),
        }
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(|_| journal_unavailable())?;
    }

    std::fs::canonicalize(path).map_err(|_| journal_unavailable())
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
            PreparedFencedTransitionJournal::open(
                &self.path,
                PreparedFencedTransitionJournalKey::from_bytes(self.key),
            )
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
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::renew(guard, Duration::from_secs(30)).expect("renewal"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("record-free request");
        PreparedFencedTransition::from_unprotected_request(request).expect("prepared request")
    }

    fn assert_coarse_unavailable<T>(result: Result<T, StoreError>) {
        match result {
            Err(StoreError::BackendUnavailable(message)) => {
                assert_eq!(message, JOURNAL_UNAVAILABLE);
            }
            Ok(_) | Err(_) => panic!("journal failure was not coarsely classified"),
        }
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
    }

    #[tokio::test]
    async fn prepared_journal_wrong_key_and_corruption_fail_with_fixed_diagnostics() {
        let fixture = JournalFixture::new(0x42);
        let journal = fixture.open();
        let retained = prepared(0x53);
        journal.insert(&retained).await.expect("durable insert");
        drop(journal);

        assert_coarse_unavailable(PreparedFencedTransitionJournal::open(
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

        let reopened = fixture.open();
        assert_coarse_unavailable(reopened.lookup(retained.request_id()).await);
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
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open(
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
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open(
            &versioned.path,
            PreparedFencedTransitionJournalKey::from_bytes(versioned.key),
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
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open(
            public_directory.path().join("prepared.sqlite3"),
            PreparedFencedTransitionJournalKey::from_bytes(
                [0x46; PREPARED_FENCED_TRANSITION_JOURNAL_KEY_BYTES],
            ),
        ));

        let fixture = JournalFixture::new(0x47);
        let target = fixture.path.with_file_name("target.sqlite3");
        std::fs::File::create(&target).expect("create symlink target");
        symlink(&target, &fixture.path).expect("create fixture symlink");
        assert_coarse_unavailable(PreparedFencedTransitionJournal::open(
            &fixture.path,
            PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
        ));
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
