//! Caller-keyed durable retention for protected V2 fenced transitions.
//!
//! The protected V2 consumer facade binds one caller-stable
//! [`FencedTransitionRequestId`] to the complete sealed
//! [`FencedTransitionV2Request`] before any transport can observe it. A
//! restarted caller that retains only its stable ID can therefore recover the
//! exact physical request and read its receipt, even though the request's
//! 56-byte V2 identity commits to a sealed body the caller never kept.
//!
//! Unlike the #701 journal, rows are removable. The live row count is an
//! authenticated admission fence rather than a lifetime cap: callers remove a
//! row only after its transition is resolved or proved unable to bind.

use std::{fmt, path::Path, sync::Arc, sync::Mutex};

use rand::{rngs::SysRng, TryRng};
use rusqlite::{
    limits::Limit, params, types::ValueRef, Connection, OpenFlags, OptionalExtension,
    TransactionBehavior,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    canonical_schema_sql, fixed_blob, install_journal_progress_handler, journal_application_id,
    journal_user_version, prepare_secure_journal_path_with_bounds, verify_sqlite_main_file_binding,
    with_journal_progress_budget_limit, JournalOpenMode, JournalSqliteProgressBudget,
    ZeroizingHmacSha256, JOURNAL_SQLITE_CACHE_KIB,
};
#[cfg(unix)]
use super::{SecureJournalFileBounds, SecureJournalPathGuard};
use crate::{
    FencedTransitionRequestId, FencedTransitionV2HistoryEpoch, FencedTransitionV2Request,
    StoreError, FENCED_TRANSITION_MAX_PREPARED_BYTES, FENCED_TRANSITION_REQUEST_ID_BYTES,
};

/// Width of the independent integrity key protecting one recovery journal.
pub const FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES: usize = 32;

/// Maximum number of live rows one protected V2 recovery journal retains.
///
/// This is an authenticated admission fence, not an absorbing lifetime cap.
/// A full journal rejects a new caller ID with
/// `StoreError::FencedTransitionHistoryFull` before provider or transport
/// work, and admits new IDs again once resolved rows are removed.
pub const FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES: usize = 4_096;

/// Maximum rows one bounded recovery-journal page or retired-floor removal
/// visits, and therefore the largest batch one reclamation call examines.
pub const FENCED_TRANSITION_V2_RECOVERY_RECLAIM_BATCH_MAX: usize = 256;
const RECOVERY_JOURNAL_MAX_PAGE_ENTRIES: usize = FENCED_TRANSITION_V2_RECOVERY_RECLAIM_BATCH_MAX;

const RECOVERY_APPLICATION_ID: i64 = 0x4f50_4652;
const RECOVERY_SCHEMA_VERSION: i64 = 1;
const RECOVERY_SCHEMA_OBJECT_COUNT: i64 = 4;
const RECOVERY_METADATA_TABLE: &str = "protected_fenced_transition_v2_recovery_metadata";
const RECOVERY_TABLE: &str = "protected_fenced_transition_v2_recovery_journal";
const RECOVERY_PRIMARY_INDEX: &str =
    "sqlite_autoindex_protected_fenced_transition_v2_recovery_journal_1";
const RECOVERY_MEMBERSHIP_INDEX: &str = "protected_fenced_transition_v2_recovery_membership_idx";
const RECOVERY_UNAVAILABLE: &str = "protected fenced-transition V2 recovery journal unavailable";
const RECOVERY_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
const RECOVERY_CATALOG_SCAN_LIMIT: usize = RECOVERY_SCHEMA_OBJECT_COUNT as usize + 1;
const RECOVERY_METADATA_SCAN_LIMIT: usize = 2;
const RECOVERY_MEMBERSHIP_SCAN_LIMIT: usize = FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES + 1;
// The canonical row body is the bounded consensus binary encoding of one
// sealed V2 request. Its fixed ceiling matches the #701 prepared-token bound.
const RECOVERY_REQUEST_MAX_BYTES: usize = FENCED_TRANSITION_MAX_PREPARED_BYTES;
// SQLite's length limit covers a complete record as well as its largest BLOB:
// a 16-byte request ID, an INTEGER epoch, the 32-byte tag, and generous
// record-header varint space.
const RECOVERY_ROW_OVERHEAD_BYTES: usize = FENCED_TRANSITION_REQUEST_ID_BYTES
    + std::mem::size_of::<i64>()
    + FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES
    + 64;
const RECOVERY_PAGE_SIZE_BYTES: u64 = 4_096;
const RECOVERY_MAIN_FIXED_OVERHEAD_BYTES: u64 = 16 * 1024 * 1024;
const RECOVERY_PER_ENTRY_FILE_OVERHEAD_BYTES: u64 =
    RECOVERY_ROW_OVERHEAD_BYTES as u64 + 2 * RECOVERY_PAGE_SIZE_BYTES;
const RECOVERY_MAIN_MAX_BYTES: u64 = (RECOVERY_REQUEST_MAX_BYTES as u64
    + RECOVERY_PER_ENTRY_FILE_OVERHEAD_BYTES)
    * FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES as u64
    + RECOVERY_MAIN_FIXED_OVERHEAD_BYTES;
const RECOVERY_MAX_PAGE_COUNT: i64 =
    RECOVERY_MAIN_MAX_BYTES.div_ceil(RECOVERY_PAGE_SIZE_BYTES) as i64;
// A long-lived read snapshot may defer checkpoints while every bounded row is
// appended; the WAL ceiling therefore covers the full main-file bound plus
// repeated B-tree and metadata frames, as for the #701 journal.
const RECOVERY_WAL_MAX_BYTES: u64 = RECOVERY_MAIN_MAX_BYTES + 512 * 1024 * 1024;
const RECOVERY_SHM_MAX_BYTES: u64 = 128 * 1024 * 1024;
const RECOVERY_WAL_AUTOCHECKPOINT_PAGES: i64 = 1_000;
// Schema initialization runs under a tight fixed budget, as for the #701
// journal. Every later top-level operation authenticates the complete bounded
// membership at most four times (before, during, and after one mutation, plus
// one retired-floor candidate scan) and performs at most one bounded page of
// point mutations. The budget bounds corrupt-catalog work; it is deliberately
// generous for valid state at the admission fence.
const RECOVERY_INITIALIZE_MAX_PROGRESS_CALLBACKS: usize = 8;
const RECOVERY_OPERATION_MAX_PROGRESS_CALLBACKS: usize = 4
    * (FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES + 1)
    + RECOVERY_JOURNAL_MAX_PAGE_ENTRIES * 64;
const RECOVERY_UNBOUND_SCOPE: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] = [0; 32];
const RECOVERY_KEY_CHECK_DOMAIN: &[u8] =
    b"openpacketcore/session-store/protected-v2-recovery-journal/schema-1/key-check/v1\0";
const RECOVERY_PATH_KEY_DOMAIN: &[u8] =
    b"openpacketcore/session-store/protected-v2-recovery-journal/schema-1/path-key/v1\0";
const RECOVERY_ENTRY_DOMAIN: &[u8] =
    b"openpacketcore/session-store/protected-v2-recovery-journal/schema-1/entry/v1\0";
const RECOVERY_MEMBERSHIP_ROOT_DOMAIN: &[u8] =
    b"openpacketcore/session-store/protected-v2-recovery-journal/schema-1/membership-root/v1\0";
const RECOVERY_MEMBERSHIP_TAG_DOMAIN: &[u8] =
    b"openpacketcore/session-store/protected-v2-recovery-journal/schema-1/membership-tag/v1\0";
const RECOVERY_SCOPE_TAG_DOMAIN: &[u8] =
    b"openpacketcore/session-store/protected-v2-recovery-journal/schema-1/scope-tag/v1\0";

/// Stable secret used only to authenticate one protected V2 recovery journal.
///
/// The key must be independent of record-protection, remote-provider, TLS,
/// and every other journal key. Restore the same value with the same journal
/// path after a process restart; it is never stored in the database.
pub struct FencedTransitionV2RecoveryJournalKey(
    Zeroizing<[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES]>,
);

impl FencedTransitionV2RecoveryJournalKey {
    /// Import the stable recovery-journal integrity key from secret
    /// configuration.
    pub fn from_bytes(bytes: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] {
        &self.0
    }

    #[cfg(unix)]
    fn bind_to_checked_path(self, path: &Path) -> Result<Self, StoreError> {
        use std::os::unix::ffi::OsStrExt;

        let path = path.as_os_str().as_bytes();
        let path_length = u32::try_from(path.len()).map_err(|_| recovery_unavailable())?;
        let mut mac = ZeroizingHmacSha256::new(self.as_bytes());
        mac.update(RECOVERY_PATH_KEY_DOMAIN);
        mac.update(&RECOVERY_APPLICATION_ID.to_be_bytes());
        mac.update(&RECOVERY_SCHEMA_VERSION.to_be_bytes());
        mac.update(&path_length.to_be_bytes());
        mac.update(path);
        Ok(Self(mac.finalize()))
    }
}

impl Clone for FencedTransitionV2RecoveryJournalKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for FencedTransitionV2RecoveryJournalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionV2RecoveryJournalKey(<redacted>)")
    }
}

struct RecoveryJournalInner {
    conn: Mutex<Connection>,
    key: FencedTransitionV2RecoveryJournalKey,
    progress_budget: Arc<JournalSqliteProgressBudget>,
    #[cfg(unix)]
    path_guard: SecureJournalPathGuard,
}

/// SDK-owned durable binding of caller-stable IDs to sealed V2 requests.
///
/// The database contains complete sealed physical requests, never caller
/// plaintext. Every row is authenticated with a stable key independent of
/// payload key or provider rotation, and an authenticated membership count and
/// root cover the complete bounded row set. The journal binds on first use to
/// one protection-wrapper scope; a different scope fails closed and can never
/// turn a retained row into an absence decision.
///
/// Rows are removed only through the protected V2 facade's resolution rules.
/// The journal itself never ages out or garbage-collects a row.
#[derive(Clone)]
pub struct FencedTransitionV2RecoveryJournal {
    inner: Arc<RecoveryJournalInner>,
    operation_permit: Arc<tokio::sync::Semaphore>,
}

impl fmt::Debug for FencedTransitionV2RecoveryJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FencedTransitionV2RecoveryJournal")
            .field("path", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// One authenticated retained binding witness returned by a bounded page.
#[derive(Clone, Copy)]
pub(crate) struct RecoveryJournalEntry {
    pub(crate) request_id: FencedTransitionRequestId,
    pub(crate) history_epoch: FencedTransitionV2HistoryEpoch,
}

#[derive(Clone, Copy)]
struct RecoveryMembership {
    incarnation: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
    count: i64,
    root: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
    tag: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
}

struct RecoveryMetadata {
    membership: RecoveryMembership,
    scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
}

/// Fixed-width membership witness of one row.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RecoveryMember {
    request_id: [u8; FENCED_TRANSITION_REQUEST_ID_BYTES],
    epoch: i64,
    tag: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
    rowid: i64,
}

impl FencedTransitionV2RecoveryJournal {
    /// Provision one missing dedicated protected V2 recovery journal.
    ///
    /// This has the same local-filesystem, private-path, locking, fsync, and
    /// restart requirements as the V1 prepared journal, but uses a separate
    /// file, application ID, schema, and key namespace. Call it exactly once
    /// for a missing path; every restart must use [`Self::open_existing`].
    pub fn create_new(
        path: impl AsRef<Path>,
        key: FencedTransitionV2RecoveryJournalKey,
    ) -> Result<Self, StoreError> {
        Self::open_with_mode(path.as_ref(), key, JournalOpenMode::CreateNew)
    }

    /// Open an already provisioned protected V2 recovery journal.
    ///
    /// This never creates or initializes a missing, pristine, truncated,
    /// foreign, or partial database.
    pub fn open_existing(
        path: impl AsRef<Path>,
        key: FencedTransitionV2RecoveryJournalKey,
    ) -> Result<Self, StoreError> {
        Self::open_with_mode(path.as_ref(), key, JournalOpenMode::OpenExisting)
    }

    fn open_with_mode(
        path: &Path,
        key: FencedTransitionV2RecoveryJournalKey,
        mode: JournalOpenMode,
    ) -> Result<Self, StoreError> {
        let path = prepare_secure_journal_path_with_bounds(
            path,
            mode,
            #[cfg(unix)]
            SecureJournalFileBounds {
                main: RECOVERY_MAIN_MAX_BYTES,
                wal: RECOVERY_WAL_MAX_BYTES,
                shm: RECOVERY_SHM_MAX_BYTES,
            },
        )
        .map_err(|_| recovery_unavailable())?;
        #[cfg(unix)]
        let key = key
            .bind_to_checked_path(&path.binding_path)
            .map_err(|_| recovery_unavailable())?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
        let mut conn = Connection::open_with_flags(&path.sqlite_path, flags)
            .map_err(|_| recovery_unavailable())?;
        configure_recovery_sqlite_limits(&conn)?;
        let progress_budget = install_journal_progress_handler(&conn);
        #[cfg(unix)]
        path.path_guard
            .verify_connection(&conn)
            .map_err(|_| recovery_unavailable())?;
        initialize_recovery_connection(&mut conn, &key, mode, &progress_budget)?;
        #[cfg(unix)]
        {
            path.path_guard
                .verify_connection(&conn)
                .map_err(|_| recovery_unavailable())?;
            path.path_guard
                .sync_parent_directory()
                .map_err(|_| recovery_unavailable())?;
        }
        Ok(Self {
            inner: Arc::new(RecoveryJournalInner {
                conn: Mutex::new(conn),
                key,
                progress_budget,
                #[cfg(unix)]
                path_guard: path.path_guard,
            }),
            operation_permit: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }

    /// Authenticate the journal and bind it to `scope` on first use.
    ///
    /// The compare-and-set includes the unbound sentinel and runs in the same
    /// immediate transaction as the metadata verification, so concurrent
    /// first users converge on one scope.
    pub(crate) async fn ensure_scope(
        &self,
        scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
    ) -> Result<(), StoreError> {
        if scope == RECOVERY_UNBOUND_SCOPE {
            return Err(recovery_unavailable());
        }
        self.with_connection(true, move |conn, key| {
            let transaction = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| recovery_unavailable())?;
            let metadata = verify_recovery_metadata(&transaction, key, None)?;
            if metadata.scope == RECOVERY_UNBOUND_SCOPE {
                let changed = transaction
                    .execute(
                        &format!(
                            "UPDATE {RECOVERY_METADATA_TABLE} \
                             SET scope_commitment = ?1, scope_tag = ?2 \
                             WHERE singleton = 1 AND scope_commitment = ?3 AND scope_tag = ?4"
                        ),
                        params![
                            scope.as_slice(),
                            recovery_scope_tag(key, &scope).as_slice(),
                            RECOVERY_UNBOUND_SCOPE.as_slice(),
                            recovery_scope_tag(key, &RECOVERY_UNBOUND_SCOPE).as_slice(),
                        ],
                    )
                    .map_err(|_| recovery_unavailable())?;
                if changed != 1 {
                    return Err(recovery_unavailable());
                }
            }
            verify_recovery_metadata(&transaction, key, Some(&scope))?;
            verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
            transaction.commit().map_err(|_| recovery_unavailable())
        })
        .await
    }

    /// Authenticate the complete bounded journal for `scope` and return its
    /// live row count.
    pub(crate) async fn live_entries(
        &self,
        scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
    ) -> Result<usize, StoreError> {
        self.with_connection(false, move |conn, key| {
            let transaction = recovery_read_transaction(conn)?;
            let metadata = verify_recovery_metadata(&transaction, key, Some(&scope))?;
            verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
            transaction.commit().map_err(|_| recovery_unavailable())?;
            usize::try_from(metadata.membership.count).map_err(|_| recovery_unavailable())
        })
        .await
    }

    /// Reject a retained ID or a full journal before provider work.
    pub(crate) async fn ensure_absent(
        &self,
        scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
        request_id: FencedTransitionRequestId,
    ) -> Result<(), StoreError> {
        self.with_connection(false, move |conn, key| {
            let transaction = recovery_read_transaction(conn)?;
            let metadata = verify_recovery_metadata(&transaction, key, Some(&scope))?;
            if read_recovery_entry(&transaction, key, request_id)?.is_some() {
                return Err(StoreError::FencedTransitionRequestConflict);
            }
            if recovery_journal_full(metadata.membership.count)? {
                return Err(StoreError::FencedTransitionHistoryFull);
            }
            verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
            transaction.commit().map_err(|_| recovery_unavailable())
        })
        .await
    }

    /// Durably bind `request_id` to the exact sealed request, create-only.
    ///
    /// A retained ID is a conflict and a full journal is
    /// `FencedTransitionHistoryFull`; neither changes the journal. The new row
    /// and the updated membership commitment are verified in the same
    /// transaction before commit, and the parent directory is synced before
    /// returning.
    pub(crate) async fn insert(
        &self,
        scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
        request_id: FencedTransitionRequestId,
        request: &FencedTransitionV2Request,
    ) -> Result<(), StoreError> {
        let canonical = canonical_recovery_request(request)?;
        let epoch = recovery_epoch(request.request_id().epoch())?;
        self.with_connection(true, move |conn, key| {
            let transaction = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| recovery_unavailable())?;
            let metadata = verify_recovery_metadata(&transaction, key, Some(&scope))?;
            if read_recovery_entry(&transaction, key, request_id)?.is_some() {
                return Err(StoreError::FencedTransitionRequestConflict);
            }
            if recovery_journal_full(metadata.membership.count)? {
                return Err(StoreError::FencedTransitionHistoryFull);
            }
            let tag = recovery_entry_tag(key, request_id, epoch, &canonical)?;
            let inserted = transaction
                .execute(
                    &format!(
                        "INSERT INTO {RECOVERY_TABLE} \
                         (request_id, history_epoch, integrity_tag, prepared_request) \
                         VALUES (?1, ?2, ?3, ?4)"
                    ),
                    params![
                        request_id.as_bytes().as_slice(),
                        epoch,
                        tag.as_slice(),
                        canonical.as_slice(),
                    ],
                )
                .map_err(|_| recovery_unavailable())?;
            if inserted != 1 {
                return Err(recovery_unavailable());
            }
            let Some(stored) = read_recovery_entry(&transaction, key, request_id)? else {
                return Err(recovery_unavailable());
            };
            if canonical_recovery_request(&stored)?.as_slice() != canonical.as_slice() {
                return Err(recovery_unavailable());
            }
            let expected_count = metadata
                .membership
                .count
                .checked_add(1)
                .ok_or_else(recovery_unavailable)?;
            publish_recovery_membership(&transaction, key, metadata.membership, expected_count)?;
            verify_recovery_metadata(&transaction, key, Some(&scope))?;
            verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
            transaction.commit().map_err(|_| recovery_unavailable())
        })
        .await
    }

    /// Return the exact sealed request retained for `request_id`, if any.
    pub(crate) async fn lookup(
        &self,
        scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
        request_id: FencedTransitionRequestId,
    ) -> Result<Option<FencedTransitionV2Request>, StoreError> {
        self.with_connection(false, move |conn, key| {
            let transaction = recovery_read_transaction(conn)?;
            verify_recovery_metadata(&transaction, key, Some(&scope))?;
            let request = read_recovery_entry(&transaction, key, request_id)?;
            verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
            transaction.commit().map_err(|_| recovery_unavailable())?;
            Ok(request)
        })
        .await
    }

    /// Remove the row for `request_id` only when it still holds exactly
    /// `expected`. Returns whether this call removed it.
    ///
    /// The compare-and-delete includes the canonical sealed bytes and the
    /// authenticated tag, so a stale caller can never remove a replacement
    /// binding made after an earlier removal.
    pub(crate) async fn remove_if_exact(
        &self,
        scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
        request_id: FencedTransitionRequestId,
        expected: &FencedTransitionV2Request,
    ) -> Result<bool, StoreError> {
        let canonical = canonical_recovery_request(expected)?;
        let epoch = recovery_epoch(expected.request_id().epoch())?;
        self.with_connection(true, move |conn, key| {
            let transaction = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| recovery_unavailable())?;
            let metadata = verify_recovery_metadata(&transaction, key, Some(&scope))?;
            let Some(stored) = read_recovery_entry(&transaction, key, request_id)? else {
                verify_sqlite_main_file_binding(&transaction)
                    .map_err(|_| recovery_unavailable())?;
                transaction.commit().map_err(|_| recovery_unavailable())?;
                return Ok(false);
            };
            if canonical_recovery_request(&stored)?.as_slice() != canonical.as_slice() {
                verify_sqlite_main_file_binding(&transaction)
                    .map_err(|_| recovery_unavailable())?;
                transaction.commit().map_err(|_| recovery_unavailable())?;
                return Ok(false);
            }
            let tag = recovery_entry_tag(key, request_id, epoch, &canonical)?;
            let deleted = transaction
                .execute(
                    &format!(
                        "DELETE FROM {RECOVERY_TABLE} \
                         WHERE request_id = ?1 AND history_epoch = ?2 \
                           AND integrity_tag = ?3 AND prepared_request = ?4"
                    ),
                    params![
                        request_id.as_bytes().as_slice(),
                        epoch,
                        tag.as_slice(),
                        canonical.as_slice(),
                    ],
                )
                .map_err(|_| recovery_unavailable())?;
            if deleted != 1 {
                return Err(recovery_unavailable());
            }
            let expected_count = metadata
                .membership
                .count
                .checked_sub(1)
                .ok_or_else(recovery_unavailable)?;
            publish_recovery_membership(&transaction, key, metadata.membership, expected_count)?;
            verify_recovery_metadata(&transaction, key, Some(&scope))?;
            verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
            transaction.commit().map_err(|_| recovery_unavailable())?;
            Ok(true)
        })
        .await
    }

    /// Remove at most `limit` rows whose history epoch is at or below the
    /// linearized retired floor `retired_through`.
    ///
    /// Such a request can never execute again: V2 classifies every request at
    /// or below the floor as retired. Callers supply only a floor returned by
    /// a linearized history-state read.
    pub(crate) async fn remove_retired_through(
        &self,
        scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
        retired_through: FencedTransitionV2HistoryEpoch,
        limit: usize,
    ) -> Result<usize, StoreError> {
        if limit == 0 || limit > RECOVERY_JOURNAL_MAX_PAGE_ENTRIES {
            return Err(recovery_unavailable());
        }
        let floor = recovery_epoch(retired_through)?;
        self.with_connection(true, move |conn, key| {
            let transaction = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| recovery_unavailable())?;
            let metadata = verify_recovery_metadata(&transaction, key, Some(&scope))?;
            let members = scan_recovery_members(&transaction)?;
            let retired = members
                .iter()
                .filter(|member| member.epoch <= floor)
                .take(limit)
                .copied()
                .collect::<Vec<_>>();
            if retired.is_empty() {
                verify_sqlite_main_file_binding(&transaction)
                    .map_err(|_| recovery_unavailable())?;
                transaction.commit().map_err(|_| recovery_unavailable())?;
                return Ok(0);
            }
            for member in &retired {
                let deleted = transaction
                    .execute(
                        &format!(
                            "DELETE FROM {RECOVERY_TABLE} \
                             WHERE rowid = ?1 AND request_id = ?2 AND history_epoch = ?3 \
                               AND integrity_tag = ?4"
                        ),
                        params![
                            member.rowid,
                            member.request_id.as_slice(),
                            member.epoch,
                            member.tag.as_slice(),
                        ],
                    )
                    .map_err(|_| recovery_unavailable())?;
                if deleted != 1 {
                    return Err(recovery_unavailable());
                }
            }
            let removed = i64::try_from(retired.len()).map_err(|_| recovery_unavailable())?;
            let expected_count = metadata
                .membership
                .count
                .checked_sub(removed)
                .ok_or_else(recovery_unavailable)?;
            publish_recovery_membership(&transaction, key, metadata.membership, expected_count)?;
            verify_recovery_metadata(&transaction, key, Some(&scope))?;
            verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
            transaction.commit().map_err(|_| recovery_unavailable())?;
            Ok(retired.len())
        })
        .await
    }

    /// Return at most `limit` authenticated retained caller IDs and their
    /// history epochs in ascending caller-ID order, strictly after `after`
    /// when supplied. No request body is read, so a page stays fixed-width.
    pub(crate) async fn page_after(
        &self,
        scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
        after: Option<FencedTransitionRequestId>,
        limit: usize,
    ) -> Result<Vec<RecoveryJournalEntry>, StoreError> {
        if limit == 0 || limit > RECOVERY_JOURNAL_MAX_PAGE_ENTRIES {
            return Err(recovery_unavailable());
        }
        self.with_connection(false, move |conn, key| {
            let transaction = recovery_read_transaction(conn)?;
            verify_recovery_metadata(&transaction, key, Some(&scope))?;
            let members = scan_recovery_members(&transaction)?;
            let mut page = Vec::with_capacity(limit.min(members.len()));
            for member in members
                .iter()
                .filter(|member| after.is_none_or(|after| member.request_id > *after.as_bytes()))
                .take(limit)
            {
                page.push(RecoveryJournalEntry {
                    request_id: FencedTransitionRequestId::from_bytes(member.request_id),
                    history_epoch: FencedTransitionV2HistoryEpoch::new(
                        u64::try_from(member.epoch).map_err(|_| recovery_unavailable())?,
                    )
                    .map_err(|_| recovery_unavailable())?,
                });
            }
            verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
            transaction.commit().map_err(|_| recovery_unavailable())?;
            Ok(page)
        })
        .await
    }

    async fn with_connection<T, F>(
        &self,
        sync_parent_on_success: bool,
        operation: F,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection, &FencedTransitionV2RecoveryJournalKey) -> Result<T, StoreError>
            + Send
            + 'static,
    {
        let permit = Arc::clone(&self.operation_permit)
            .acquire_owned()
            .await
            .map_err(|_| recovery_unavailable())?;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut conn = inner.conn.lock().map_err(|_| recovery_unavailable())?;
            #[cfg(unix)]
            inner
                .path_guard
                .verify_connection(&conn)
                .map_err(|_| recovery_unavailable())?;
            let result = with_journal_progress_budget_limit(
                &mut conn,
                &inner.progress_budget,
                RECOVERY_OPERATION_MAX_PROGRESS_CALLBACKS,
                |conn| operation(conn, &inner.key),
            );
            #[cfg(unix)]
            if result.is_ok() && sync_parent_on_success {
                inner
                    .path_guard
                    .sync_parent_directory()
                    .map_err(|_| recovery_unavailable())?;
            }
            #[cfg(unix)]
            inner
                .path_guard
                .verify_connection(&conn)
                .map_err(|_| recovery_unavailable())?;
            #[cfg(not(unix))]
            let _ = sync_parent_on_success;
            result
        })
        .await
        .map_err(|_| recovery_unavailable())?
    }
}

fn recovery_unavailable() -> StoreError {
    StoreError::BackendUnavailable(RECOVERY_UNAVAILABLE.into())
}

fn recovery_journal_full(count: i64) -> Result<bool, StoreError> {
    Ok(count
        >= i64::try_from(FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES)
            .map_err(|_| recovery_unavailable())?)
}

fn recovery_epoch(epoch: FencedTransitionV2HistoryEpoch) -> Result<i64, StoreError> {
    i64::try_from(epoch.get()).map_err(|_| recovery_unavailable())
}

/// Encode one validated sealed request with the bounded consensus binary
/// codec. Decoding re-encodes and compares, so only canonical rows survive.
pub(crate) fn canonical_recovery_request(
    request: &FencedTransitionV2Request,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    request.validate().map_err(|_| recovery_unavailable())?;
    let encoded =
        Zeroizing::new(opc_consensus::encode_bounded(request).map_err(|_| recovery_unavailable())?);
    if encoded.is_empty() || encoded.len() > RECOVERY_REQUEST_MAX_BYTES {
        return Err(recovery_unavailable());
    }
    Ok(encoded)
}

fn decode_recovery_request(canonical: &[u8]) -> Result<FencedTransitionV2Request, StoreError> {
    if canonical.is_empty() || canonical.len() > RECOVERY_REQUEST_MAX_BYTES {
        return Err(recovery_unavailable());
    }
    let request: FencedTransitionV2Request =
        opc_consensus::decode_bounded(canonical).map_err(|_| recovery_unavailable())?;
    if canonical_recovery_request(&request)?.as_slice() != canonical {
        return Err(recovery_unavailable());
    }
    Ok(request)
}

fn recovery_key_check(
    key: &FencedTransitionV2RecoveryJournalKey,
) -> Zeroizing<[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES]> {
    let mut mac = ZeroizingHmacSha256::new(key.as_bytes());
    mac.update(RECOVERY_KEY_CHECK_DOMAIN);
    mac.update(&RECOVERY_APPLICATION_ID.to_be_bytes());
    mac.update(&RECOVERY_SCHEMA_VERSION.to_be_bytes());
    mac.finalize()
}

fn recovery_scope_tag(
    key: &FencedTransitionV2RecoveryJournalKey,
    scope: &[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
) -> Zeroizing<[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES]> {
    let mut mac = ZeroizingHmacSha256::new(key.as_bytes());
    mac.update(RECOVERY_SCOPE_TAG_DOMAIN);
    mac.update(&RECOVERY_APPLICATION_ID.to_be_bytes());
    mac.update(&RECOVERY_SCHEMA_VERSION.to_be_bytes());
    mac.update(scope);
    mac.finalize()
}

fn recovery_entry_tag(
    key: &FencedTransitionV2RecoveryJournalKey,
    request_id: FencedTransitionRequestId,
    epoch: i64,
    canonical: &[u8],
) -> Result<Zeroizing<[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES]>, StoreError> {
    let length = u64::try_from(canonical.len()).map_err(|_| recovery_unavailable())?;
    let epoch = u64::try_from(epoch).map_err(|_| recovery_unavailable())?;
    let mut mac = ZeroizingHmacSha256::new(key.as_bytes());
    mac.update(RECOVERY_ENTRY_DOMAIN);
    mac.update(&RECOVERY_APPLICATION_ID.to_be_bytes());
    mac.update(&RECOVERY_SCHEMA_VERSION.to_be_bytes());
    mac.update(request_id.as_bytes());
    mac.update(&epoch.to_be_bytes());
    mac.update(&length.to_be_bytes());
    mac.update(canonical);
    Ok(mac.finalize())
}

fn recovery_membership_tag(
    key: &FencedTransitionV2RecoveryJournalKey,
    incarnation: &[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
    count: i64,
    root: &[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
) -> Result<Zeroizing<[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES]>, StoreError> {
    if !valid_recovery_count(count) {
        return Err(recovery_unavailable());
    }
    let encoded_count = u64::try_from(count)
        .map_err(|_| recovery_unavailable())?
        .to_be_bytes();
    let mut mac = ZeroizingHmacSha256::new(key.as_bytes());
    mac.update(RECOVERY_MEMBERSHIP_TAG_DOMAIN);
    mac.update(&RECOVERY_APPLICATION_ID.to_be_bytes());
    mac.update(&RECOVERY_SCHEMA_VERSION.to_be_bytes());
    mac.update(incarnation);
    mac.update(&encoded_count);
    mac.update(root);
    Ok(mac.finalize())
}

fn valid_recovery_count(count: i64) -> bool {
    count >= 0
        && usize::try_from(count)
            .is_ok_and(|count| count <= FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES)
}

/// Commit the complete ordered member set (ID, epoch, tag) to one root.
fn recovery_membership_root(
    incarnation: &[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
    members: &[RecoveryMember],
) -> Result<[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES], StoreError> {
    let count = i64::try_from(members.len()).map_err(|_| recovery_unavailable())?;
    if !valid_recovery_count(count) {
        return Err(recovery_unavailable());
    }
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_MEMBERSHIP_ROOT_DOMAIN);
    hasher.update(incarnation);
    hasher.update(
        u64::try_from(count)
            .map_err(|_| recovery_unavailable())?
            .to_be_bytes(),
    );
    for member in members {
        hasher.update(member.request_id);
        hasher.update(
            u64::try_from(member.epoch)
                .map_err(|_| recovery_unavailable())?
                .to_be_bytes(),
        );
        hasher.update(member.tag);
    }
    Ok(hasher.finalize().into())
}

fn recovery_read_transaction(
    conn: &mut Connection,
) -> Result<rusqlite::Transaction<'_>, StoreError> {
    conn.transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| recovery_unavailable())
}

fn recovery_sqlite_limits() -> Result<[(Limit, i32); 9], StoreError> {
    let length = RECOVERY_REQUEST_MAX_BYTES
        .checked_add(RECOVERY_ROW_OVERHEAD_BYTES)
        .and_then(|length| i32::try_from(length).ok())
        .ok_or_else(recovery_unavailable)?;
    Ok([
        (Limit::SQLITE_LIMIT_LENGTH, length),
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

fn configure_recovery_sqlite_limits(conn: &Connection) -> Result<(), StoreError> {
    for (limit, requested) in recovery_sqlite_limits()? {
        conn.set_limit(limit, requested)
            .map_err(|_| recovery_unavailable())?;
    }
    verify_recovery_sqlite_limits(conn)
}

fn verify_recovery_sqlite_limits(conn: &Connection) -> Result<(), StoreError> {
    for (limit, requested) in recovery_sqlite_limits()? {
        if conn.limit(limit).map_err(|_| recovery_unavailable())? != requested {
            return Err(recovery_unavailable());
        }
    }
    Ok(())
}

fn verify_recovery_profile(conn: &Connection) -> Result<(), StoreError> {
    verify_recovery_sqlite_limits(conn)?;
    let integer = |pragma: &str| -> Result<i64, StoreError> {
        conn.query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
            .map_err(|_| recovery_unavailable())
    };
    let text = |pragma: &str| -> Result<String, StoreError> {
        conn.query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
            .map_err(|_| recovery_unavailable())
    };
    if integer("page_size")?
        != i64::try_from(RECOVERY_PAGE_SIZE_BYTES).map_err(|_| recovery_unavailable())?
        || integer("max_page_count")? != RECOVERY_MAX_PAGE_COUNT
        || integer("cache_size")? != -JOURNAL_SQLITE_CACHE_KIB
        || integer("cache_spill")? != 0
        || integer("mmap_size")? != 0
        || integer("wal_autocheckpoint")? != RECOVERY_WAL_AUTOCHECKPOINT_PAGES
        || integer("journal_size_limit")?
            != i64::try_from(RECOVERY_WAL_MAX_BYTES).map_err(|_| recovery_unavailable())?
        || !text("journal_mode")?.eq_ignore_ascii_case("wal")
        || integer("synchronous")? != 3
        || integer("fullfsync")? != 1
        || integer("checkpoint_fullfsync")? != 1
        || integer("foreign_keys")? != 1
        || !text("locking_mode")?.eq_ignore_ascii_case("normal")
        || integer("temp_store")? != 2
        || integer("secure_delete")? != 1
    {
        return Err(recovery_unavailable());
    }
    Ok(())
}

fn recovery_metadata_table_sql() -> String {
    format!(
        r#"CREATE TABLE {RECOVERY_METADATA_TABLE} (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema_version INTEGER NOT NULL CHECK (schema_version = {RECOVERY_SCHEMA_VERSION}),
            journal_incarnation BLOB NOT NULL CHECK (
                typeof(journal_incarnation) = 'blob' AND length(journal_incarnation) = 32
            ),
            membership_count INTEGER NOT NULL CHECK (
                membership_count >= 0
                AND membership_count <= {FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES}
            ),
            membership_root BLOB NOT NULL CHECK (
                typeof(membership_root) = 'blob' AND length(membership_root) = 32
            ),
            membership_tag BLOB NOT NULL CHECK (
                typeof(membership_tag) = 'blob' AND length(membership_tag) = 32
            ),
            scope_commitment BLOB NOT NULL CHECK (
                typeof(scope_commitment) = 'blob' AND length(scope_commitment) = 32
            ),
            scope_tag BLOB NOT NULL CHECK (
                typeof(scope_tag) = 'blob' AND length(scope_tag) = 32
            ),
            key_check BLOB NOT NULL CHECK (
                typeof(key_check) = 'blob' AND length(key_check) = 32
            )
        ) STRICT"#
    )
}

fn recovery_table_sql() -> String {
    format!(
        r#"CREATE TABLE {RECOVERY_TABLE} (
            request_id BLOB PRIMARY KEY CHECK (
                typeof(request_id) = 'blob' AND length(request_id) = {FENCED_TRANSITION_REQUEST_ID_BYTES}
            ),
            history_epoch INTEGER NOT NULL CHECK (history_epoch > 0),
            integrity_tag BLOB NOT NULL CHECK (
                typeof(integrity_tag) = 'blob' AND length(integrity_tag) = 32
            ),
            prepared_request BLOB NOT NULL CHECK (
                typeof(prepared_request) = 'blob'
                AND length(prepared_request) > 0
                AND length(prepared_request) <= {RECOVERY_REQUEST_MAX_BYTES}
            )
        ) STRICT"#
    )
}

fn recovery_membership_index_sql() -> String {
    format!(
        "CREATE INDEX {RECOVERY_MEMBERSHIP_INDEX} \
         ON {RECOVERY_TABLE} (request_id, history_epoch, integrity_tag)"
    )
}

fn initialize_recovery_connection(
    conn: &mut Connection,
    key: &FencedTransitionV2RecoveryJournalKey,
    mode: JournalOpenMode,
    budget: &JournalSqliteProgressBudget,
) -> Result<(), StoreError> {
    with_journal_progress_budget_limit(
        conn,
        budget,
        RECOVERY_INITIALIZE_MAX_PROGRESS_CALLBACKS,
        |conn| initialize_recovery_schema_and_profile(conn, key, mode),
    )?;
    with_journal_progress_budget_limit(
        conn,
        budget,
        RECOVERY_OPERATION_MAX_PROGRESS_CALLBACKS,
        |conn| {
            let transaction = recovery_read_transaction(conn)?;
            verify_recovery_metadata(&transaction, key, None)?;
            verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
            transaction.commit().map_err(|_| recovery_unavailable())
        },
    )
}

fn initialize_recovery_schema_and_profile(
    conn: &mut Connection,
    key: &FencedTransitionV2RecoveryJournalKey,
    mode: JournalOpenMode,
) -> Result<(), StoreError> {
    conn.busy_timeout(RECOVERY_BUSY_TIMEOUT)
        .map_err(|_| recovery_unavailable())?;
    let application_id = journal_application_id(conn).map_err(|_| recovery_unavailable())?;
    let user_version = journal_user_version(conn).map_err(|_| recovery_unavailable())?;
    let object_count = recovery_schema_catalog_count(conn)?;
    let empty = application_id == 0 && user_version == 0 && object_count == 0;
    if !(empty
        || (application_id == RECOVERY_APPLICATION_ID
            && user_version == RECOVERY_SCHEMA_VERSION
            && object_count == RECOVERY_SCHEMA_OBJECT_COUNT))
    {
        return Err(recovery_unavailable());
    }
    if mode == JournalOpenMode::OpenExisting && empty {
        return Err(recovery_unavailable());
    }
    if application_id == RECOVERY_APPLICATION_ID {
        verify_recovery_schema(conn)?;
    }
    conn.execute_batch(&format!(
        "PRAGMA page_size = {RECOVERY_PAGE_SIZE_BYTES}; \
         PRAGMA max_page_count = {RECOVERY_MAX_PAGE_COUNT}; \
         PRAGMA cache_size = -{JOURNAL_SQLITE_CACHE_KIB}; \
         PRAGMA cache_spill = OFF; PRAGMA mmap_size = 0; \
         PRAGMA journal_mode = WAL; \
         PRAGMA wal_autocheckpoint = {RECOVERY_WAL_AUTOCHECKPOINT_PAGES}; \
         PRAGMA journal_size_limit = {RECOVERY_WAL_MAX_BYTES}; \
         PRAGMA synchronous = EXTRA; PRAGMA fullfsync = ON; \
         PRAGMA checkpoint_fullfsync = ON; PRAGMA foreign_keys = ON; \
         PRAGMA locking_mode = NORMAL; PRAGMA temp_store = MEMORY; \
         PRAGMA secure_delete = ON;"
    ))
    .map_err(|_| recovery_unavailable())?;
    verify_recovery_profile(conn)?;
    let transaction = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| recovery_unavailable())?;
    let application_id =
        journal_application_id(&transaction).map_err(|_| recovery_unavailable())?;
    let user_version = journal_user_version(&transaction).map_err(|_| recovery_unavailable())?;
    if application_id == 0 && user_version == 0 {
        if recovery_schema_catalog_count(&transaction)? != 0 {
            return Err(recovery_unavailable());
        }
        transaction
            .execute_batch(&format!(
                "{metadata}; {table}; {index}; \
                 PRAGMA application_id = {RECOVERY_APPLICATION_ID}; \
                 PRAGMA user_version = {RECOVERY_SCHEMA_VERSION};",
                metadata = recovery_metadata_table_sql(),
                table = recovery_table_sql(),
                index = recovery_membership_index_sql(),
            ))
            .map_err(|_| recovery_unavailable())?;
        let mut incarnation = [0_u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES];
        SysRng
            .try_fill_bytes(&mut incarnation)
            .map_err(|_| recovery_unavailable())?;
        let root = recovery_membership_root(&incarnation, &[])?;
        let tag = recovery_membership_tag(key, &incarnation, 0, &root)?;
        transaction
            .execute(
                &format!(
                    "INSERT INTO {RECOVERY_METADATA_TABLE} \
                     (singleton, schema_version, journal_incarnation, membership_count, \
                      membership_root, membership_tag, scope_commitment, scope_tag, key_check) \
                     VALUES (1, ?1, ?2, 0, ?3, ?4, ?5, ?6, ?7)"
                ),
                params![
                    RECOVERY_SCHEMA_VERSION,
                    incarnation.as_slice(),
                    root.as_slice(),
                    tag.as_slice(),
                    RECOVERY_UNBOUND_SCOPE.as_slice(),
                    recovery_scope_tag(key, &RECOVERY_UNBOUND_SCOPE).as_slice(),
                    recovery_key_check(key).as_slice(),
                ],
            )
            .map_err(|_| recovery_unavailable())?;
        // A freshly created journal has no rows, so its complete proof fits
        // the tight initialization budget. An existing journal is proved by
        // the caller under the full operation budget.
        verify_recovery_metadata(&transaction, key, None)?;
    } else if application_id != RECOVERY_APPLICATION_ID || user_version != RECOVERY_SCHEMA_VERSION {
        return Err(recovery_unavailable());
    }
    verify_sqlite_main_file_binding(&transaction).map_err(|_| recovery_unavailable())?;
    transaction.commit().map_err(|_| recovery_unavailable())
}

fn recovery_schema_catalog_count(conn: &Connection) -> Result<i64, StoreError> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT 1 FROM sqlite_schema LIMIT {RECOVERY_CATALOG_SCAN_LIMIT}"
        ))
        .map_err(|_| recovery_unavailable())?;
    let mut rows = statement.query([]).map_err(|_| recovery_unavailable())?;
    let mut count = 0_i64;
    while rows.next().map_err(|_| recovery_unavailable())?.is_some() {
        count = count.checked_add(1).ok_or_else(recovery_unavailable)?;
    }
    Ok(count)
}

/// Accept only the exact SDK catalog: both tables, the generated primary-key
/// index, and the covering membership index.
fn verify_recovery_schema(conn: &Connection) -> Result<(), StoreError> {
    if recovery_schema_catalog_count(conn)? != RECOVERY_SCHEMA_OBJECT_COUNT {
        return Err(recovery_unavailable());
    }
    let expected = [
        (
            "table",
            RECOVERY_METADATA_TABLE,
            RECOVERY_METADATA_TABLE,
            recovery_metadata_table_sql(),
        ),
        (
            "table",
            RECOVERY_TABLE,
            RECOVERY_TABLE,
            recovery_table_sql(),
        ),
        (
            "index",
            RECOVERY_PRIMARY_INDEX,
            RECOVERY_TABLE,
            String::new(),
        ),
        (
            "index",
            RECOVERY_MEMBERSHIP_INDEX,
            RECOVERY_TABLE,
            recovery_membership_index_sql(),
        ),
    ];
    for (expected_type, name, expected_table_name, expected_sql) in expected {
        let actual: Option<(String, String, Option<String>)> = conn
            .query_row(
                "SELECT type, tbl_name, sql FROM sqlite_schema WHERE name = ?1",
                [name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| recovery_unavailable())?;
        let Some((object_type, table_name, actual_sql)) = actual else {
            return Err(recovery_unavailable());
        };
        let sql_matches = if expected_sql.is_empty() {
            actual_sql.is_none()
        } else {
            actual_sql.as_ref().is_some_and(|actual_sql| {
                canonical_schema_sql(actual_sql) == canonical_schema_sql(&expected_sql)
            })
        };
        if object_type != expected_type || table_name != expected_table_name || !sql_matches {
            return Err(recovery_unavailable());
        }
    }
    Ok(())
}

/// Authenticate the metadata row, the complete bounded member set, and the
/// optional expected scope in the caller's transaction.
fn verify_recovery_metadata(
    conn: &Connection,
    key: &FencedTransitionV2RecoveryJournalKey,
    expected_scope: Option<&[u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES]>,
) -> Result<RecoveryMetadata, StoreError> {
    verify_recovery_profile(conn)?;
    if journal_application_id(conn).map_err(|_| recovery_unavailable())? != RECOVERY_APPLICATION_ID
        || journal_user_version(conn).map_err(|_| recovery_unavailable())?
            != RECOVERY_SCHEMA_VERSION
    {
        return Err(recovery_unavailable());
    }
    verify_recovery_schema(conn)?;
    let mut statement = conn
        .prepare(&format!(
            "SELECT singleton, schema_version, key_check, journal_incarnation, \
                    membership_count, membership_root, membership_tag, \
                    scope_commitment, scope_tag \
             FROM {RECOVERY_METADATA_TABLE} LIMIT {RECOVERY_METADATA_SCAN_LIMIT}"
        ))
        .map_err(|_| recovery_unavailable())?;
    let mut rows = statement.query([]).map_err(|_| recovery_unavailable())?;
    let row = rows
        .next()
        .map_err(|_| recovery_unavailable())?
        .ok_or_else(recovery_unavailable)?;
    let ValueRef::Integer(singleton) = row.get_ref(0).map_err(|_| recovery_unavailable())? else {
        return Err(recovery_unavailable());
    };
    let ValueRef::Integer(schema_version) = row.get_ref(1).map_err(|_| recovery_unavailable())?
    else {
        return Err(recovery_unavailable());
    };
    let key_check: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] =
        fixed_blob(row.get_ref(2).map_err(|_| recovery_unavailable())?)
            .map_err(|_| recovery_unavailable())?;
    let incarnation: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] =
        fixed_blob(row.get_ref(3).map_err(|_| recovery_unavailable())?)
            .map_err(|_| recovery_unavailable())?;
    let ValueRef::Integer(count) = row.get_ref(4).map_err(|_| recovery_unavailable())? else {
        return Err(recovery_unavailable());
    };
    let root: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] =
        fixed_blob(row.get_ref(5).map_err(|_| recovery_unavailable())?)
            .map_err(|_| recovery_unavailable())?;
    let tag: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] =
        fixed_blob(row.get_ref(6).map_err(|_| recovery_unavailable())?)
            .map_err(|_| recovery_unavailable())?;
    let scope: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] =
        fixed_blob(row.get_ref(7).map_err(|_| recovery_unavailable())?)
            .map_err(|_| recovery_unavailable())?;
    let scope_tag: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] =
        fixed_blob(row.get_ref(8).map_err(|_| recovery_unavailable())?)
            .map_err(|_| recovery_unavailable())?;
    if rows.next().map_err(|_| recovery_unavailable())?.is_some()
        || singleton != 1
        || schema_version != RECOVERY_SCHEMA_VERSION
        || !valid_recovery_count(count)
        || !bool::from(key_check.ct_eq(recovery_key_check(key).as_slice()))
        || !bool::from(scope_tag.ct_eq(recovery_scope_tag(key, &scope).as_slice()))
        || !bool::from(
            tag.ct_eq(recovery_membership_tag(key, &incarnation, count, &root)?.as_slice()),
        )
    {
        return Err(recovery_unavailable());
    }
    let members = scan_recovery_members(conn)?;
    if i64::try_from(members.len()).map_err(|_| recovery_unavailable())? != count
        || recovery_membership_root(&incarnation, &members)? != root
    {
        return Err(recovery_unavailable());
    }
    if expected_scope.is_some_and(|expected| !bool::from(expected.ct_eq(&scope))) {
        return Err(recovery_unavailable());
    }
    Ok(RecoveryMetadata {
        membership: RecoveryMembership {
            incarnation,
            count,
            root,
            tag,
        },
        scope,
    })
}

/// Scan the bounded authoritative member set in caller-ID order.
///
/// The covering membership index is the presence authority. Every index entry
/// is cross-checked against its table row by rowid, and independent bounded
/// table and primary-key scans must agree, so divergent storage fails closed
/// instead of becoming an absence decision. The scan never reads a retained
/// request body.
fn scan_recovery_members(conn: &Connection) -> Result<Vec<RecoveryMember>, StoreError> {
    let mut table_statement = conn
        .prepare(&format!(
            "SELECT request_id, history_epoch, integrity_tag \
             FROM {RECOVERY_TABLE} NOT INDEXED WHERE rowid = ?1"
        ))
        .map_err(|_| recovery_unavailable())?;
    let mut statement = conn
        .prepare(&format!(
            "SELECT request_id, history_epoch, integrity_tag, rowid \
             FROM {RECOVERY_TABLE} INDEXED BY {RECOVERY_MEMBERSHIP_INDEX} \
             ORDER BY request_id ASC LIMIT {RECOVERY_MEMBERSHIP_SCAN_LIMIT}"
        ))
        .map_err(|_| recovery_unavailable())?;
    let mut rows = statement.query([]).map_err(|_| recovery_unavailable())?;
    let mut members = Vec::new();
    let mut previous: Option<[u8; FENCED_TRANSITION_REQUEST_ID_BYTES]> = None;
    while let Some(row) = rows.next().map_err(|_| recovery_unavailable())? {
        if members.len() >= FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES {
            return Err(recovery_unavailable());
        }
        let request_id: [u8; FENCED_TRANSITION_REQUEST_ID_BYTES] =
            fixed_blob(row.get_ref(0).map_err(|_| recovery_unavailable())?)
                .map_err(|_| recovery_unavailable())?;
        let ValueRef::Integer(epoch) = row.get_ref(1).map_err(|_| recovery_unavailable())? else {
            return Err(recovery_unavailable());
        };
        let tag: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] =
            fixed_blob(row.get_ref(2).map_err(|_| recovery_unavailable())?)
                .map_err(|_| recovery_unavailable())?;
        let ValueRef::Integer(rowid) = row.get_ref(3).map_err(|_| recovery_unavailable())? else {
            return Err(recovery_unavailable());
        };
        if rowid <= 0 || epoch <= 0 || previous.is_some_and(|previous| previous >= request_id) {
            return Err(recovery_unavailable());
        }
        let table_entry: Option<(
            [u8; FENCED_TRANSITION_REQUEST_ID_BYTES],
            i64,
            [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
        )> = table_statement
            .query_row(params![rowid], |table_row| {
                let ValueRef::Integer(epoch) = table_row.get_ref(1)? else {
                    return Err(rusqlite::Error::InvalidQuery);
                };
                Ok((
                    fixed_blob(table_row.get_ref(0)?)?,
                    epoch,
                    fixed_blob(table_row.get_ref(2)?)?,
                ))
            })
            .optional()
            .map_err(|_| recovery_unavailable())?;
        if table_entry != Some((request_id, epoch, tag)) {
            return Err(recovery_unavailable());
        }
        previous = Some(request_id);
        members.push(RecoveryMember {
            request_id,
            epoch,
            tag,
            rowid,
        });
    }
    drop(rows);
    if scan_recovery_table_count(conn)? != members.len()
        || !recovery_primary_index_matches(conn, &members)?
    {
        return Err(recovery_unavailable());
    }
    Ok(members)
}

fn scan_recovery_table_count(conn: &Connection) -> Result<usize, StoreError> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT rowid FROM {RECOVERY_TABLE} NOT INDEXED LIMIT {RECOVERY_MEMBERSHIP_SCAN_LIMIT}"
        ))
        .map_err(|_| recovery_unavailable())?;
    let mut rows = statement.query([]).map_err(|_| recovery_unavailable())?;
    let mut count = 0_usize;
    while let Some(row) = rows.next().map_err(|_| recovery_unavailable())? {
        let ValueRef::Integer(rowid) = row.get_ref(0).map_err(|_| recovery_unavailable())? else {
            return Err(recovery_unavailable());
        };
        if rowid <= 0 || count >= FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES {
            return Err(recovery_unavailable());
        }
        count = count.checked_add(1).ok_or_else(recovery_unavailable)?;
    }
    Ok(count)
}

fn recovery_primary_index_matches(
    conn: &Connection,
    members: &[RecoveryMember],
) -> Result<bool, StoreError> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT request_id, rowid FROM {RECOVERY_TABLE} \
             INDEXED BY {RECOVERY_PRIMARY_INDEX} \
             ORDER BY request_id ASC LIMIT {RECOVERY_MEMBERSHIP_SCAN_LIMIT}"
        ))
        .map_err(|_| recovery_unavailable())?;
    let mut rows = statement.query([]).map_err(|_| recovery_unavailable())?;
    let mut index = 0_usize;
    while let Some(row) = rows.next().map_err(|_| recovery_unavailable())? {
        let request_id: [u8; FENCED_TRANSITION_REQUEST_ID_BYTES] =
            fixed_blob(row.get_ref(0).map_err(|_| recovery_unavailable())?)
                .map_err(|_| recovery_unavailable())?;
        let ValueRef::Integer(rowid) = row.get_ref(1).map_err(|_| recovery_unavailable())? else {
            return Err(recovery_unavailable());
        };
        let Some(member) = members.get(index) else {
            return Ok(false);
        };
        if member.request_id != request_id || member.rowid != rowid {
            return Ok(false);
        }
        index = index.checked_add(1).ok_or_else(recovery_unavailable)?;
    }
    Ok(index == members.len())
}

/// Recompute and publish the membership commitment after one mutation.
///
/// The update is a compare-and-set against the previously authenticated
/// commitment, and the recomputed member count must equal `expected_count`.
fn publish_recovery_membership(
    transaction: &rusqlite::Transaction<'_>,
    key: &FencedTransitionV2RecoveryJournalKey,
    previous: RecoveryMembership,
    expected_count: i64,
) -> Result<(), StoreError> {
    let members = scan_recovery_members(transaction)?;
    if i64::try_from(members.len()).map_err(|_| recovery_unavailable())? != expected_count {
        return Err(recovery_unavailable());
    }
    let root = recovery_membership_root(&previous.incarnation, &members)?;
    let tag = recovery_membership_tag(key, &previous.incarnation, expected_count, &root)?;
    let changed = transaction
        .execute(
            &format!(
                "UPDATE {RECOVERY_METADATA_TABLE} \
                 SET membership_count = ?1, membership_root = ?2, membership_tag = ?3 \
                 WHERE singleton = 1 AND membership_count = ?4 AND membership_root = ?5 \
                   AND membership_tag = ?6"
            ),
            params![
                expected_count,
                root.as_slice(),
                tag.as_slice(),
                previous.count,
                previous.root.as_slice(),
                previous.tag.as_slice(),
            ],
        )
        .map_err(|_| recovery_unavailable())?;
    if changed != 1 {
        return Err(recovery_unavailable());
    }
    Ok(())
}

/// Read and authenticate the exact row for `request_id`.
///
/// Callers invoke this only after `verify_recovery_metadata` authenticated the
/// complete covering index in the same transaction; that index is the
/// presence authority and the table is dereferenced by its rowid.
fn read_recovery_entry(
    conn: &Connection,
    key: &FencedTransitionV2RecoveryJournalKey,
    request_id: FencedTransitionRequestId,
) -> Result<Option<FencedTransitionV2Request>, StoreError> {
    let (rowid, indexed_epoch, indexed_tag) = {
        let mut statement = conn
            .prepare(&format!(
                "SELECT rowid, history_epoch, integrity_tag FROM {RECOVERY_TABLE} \
                 INDEXED BY {RECOVERY_MEMBERSHIP_INDEX} WHERE request_id = ?1 LIMIT 2"
            ))
            .map_err(|_| recovery_unavailable())?;
        let mut rows = statement
            .query(params![request_id.as_bytes().as_slice()])
            .map_err(|_| recovery_unavailable())?;
        let Some(row) = rows.next().map_err(|_| recovery_unavailable())? else {
            return Ok(None);
        };
        let ValueRef::Integer(rowid) = row.get_ref(0).map_err(|_| recovery_unavailable())? else {
            return Err(recovery_unavailable());
        };
        let ValueRef::Integer(epoch) = row.get_ref(1).map_err(|_| recovery_unavailable())? else {
            return Err(recovery_unavailable());
        };
        let tag: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES] =
            fixed_blob(row.get_ref(2).map_err(|_| recovery_unavailable())?)
                .map_err(|_| recovery_unavailable())?;
        if rowid <= 0 || epoch <= 0 || rows.next().map_err(|_| recovery_unavailable())?.is_some() {
            return Err(recovery_unavailable());
        }
        (rowid, epoch, tag)
    };
    let row: Option<(
        i64,
        [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
        Zeroizing<Vec<u8>>,
    )> = conn
        .query_row(
            &format!(
                "SELECT history_epoch, integrity_tag, prepared_request FROM {RECOVERY_TABLE} \
                 NOT INDEXED WHERE rowid = ?1 AND request_id = ?2"
            ),
            params![rowid, request_id.as_bytes().as_slice()],
            |row| {
                let ValueRef::Integer(epoch) = row.get_ref(0)? else {
                    return Err(rusqlite::Error::InvalidQuery);
                };
                let ValueRef::Blob(canonical) = row.get_ref(2)? else {
                    return Err(rusqlite::Error::InvalidQuery);
                };
                if canonical.is_empty() || canonical.len() > RECOVERY_REQUEST_MAX_BYTES {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok((
                    epoch,
                    fixed_blob(row.get_ref(1)?)?,
                    Zeroizing::new(canonical.to_vec()),
                ))
            },
        )
        .optional()
        .map_err(|_| recovery_unavailable())?;
    let Some((epoch, tag, canonical)) = row else {
        return Err(recovery_unavailable());
    };
    if epoch != indexed_epoch
        || !bool::from(tag.ct_eq(&indexed_tag))
        || !bool::from(
            recovery_entry_tag(key, request_id, epoch, &canonical)?
                .as_slice()
                .ct_eq(&tag),
        )
    {
        return Err(recovery_unavailable());
    }
    let request = decode_recovery_request(&canonical)?;
    if recovery_epoch(request.request_id().epoch())? != epoch {
        return Err(recovery_unavailable());
    }
    Ok(Some(request))
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::Duration};

    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    use super::*;
    use crate::{
        FenceToken, FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2CallerNonce,
        Generation, LeaseGuard, OwnerId, PreparedFencedTransitionJournal,
        PreparedFencedTransitionJournalKey, SessionKey, SessionKeyType, StableId,
    };

    struct RecoveryFixture {
        _directory: tempfile::TempDir,
        path: PathBuf,
        key: [u8; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
    }

    impl RecoveryFixture {
        fn new(fill: u8) -> Self {
            let directory = tempfile::tempdir().expect("recovery journal directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                    .expect("private recovery journal directory");
            }
            let path = directory.path().join("recovery.sqlite3");
            Self {
                _directory: directory,
                path,
                key: [fill; FENCED_TRANSITION_V2_RECOVERY_JOURNAL_KEY_BYTES],
            }
        }

        fn journal_key(&self) -> FencedTransitionV2RecoveryJournalKey {
            FencedTransitionV2RecoveryJournalKey::from_bytes(self.key)
        }

        fn create(&self) -> FencedTransitionV2RecoveryJournal {
            FencedTransitionV2RecoveryJournal::create_new(&self.path, self.journal_key())
                .expect("provision recovery journal")
        }

        fn reopen(&self) -> Result<FencedTransitionV2RecoveryJournal, StoreError> {
            FencedTransitionV2RecoveryJournal::open_existing(&self.path, self.journal_key())
        }

        fn bound_key(&self) -> FencedTransitionV2RecoveryJournalKey {
            self.journal_key()
                .bind_to_checked_path(&self.path)
                .expect("bind recovery fixture key")
        }

        fn raw(&self) -> Connection {
            Connection::open(&self.path).expect("open raw recovery journal")
        }
    }

    const SCOPE: [u8; 32] = [0x5c; 32];

    fn request_id(ordinal: u64) -> FencedTransitionRequestId {
        let mut bytes = [0x11_u8; FENCED_TRANSITION_REQUEST_ID_BYTES];
        bytes[8..].copy_from_slice(&ordinal.to_be_bytes());
        FencedTransitionRequestId::from_bytes(bytes)
    }

    fn sealed(epoch: u64, nonce: u8) -> FencedTransitionV2Request {
        let key = SessionKey {
            tenant: TenantId::from_static("recovery-journal-test"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"recovery-journal-test-id"))
                .expect("stable ID"),
        };
        let owner = OwnerId::new("recovery-journal-test-owner").expect("owner");
        let acquired_at = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(10),
        );
        let expires_at = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(70),
        );
        let guard = LeaseGuard::new(key, owner, FenceToken::new(9), acquired_at, expires_at, 1);
        FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(epoch).expect("history epoch"),
            FencedTransitionV2CallerNonce::from_bytes([nonce; 16]),
            FencedTransitionLease::renew(guard, Duration::from_secs(30)).expect("renewal"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("sealed-shape V2 request")
    }

    fn assert_unavailable<T>(result: Result<T, StoreError>) {
        assert!(matches!(
            result,
            Err(StoreError::BackendUnavailable(message)) if message == RECOVERY_UNAVAILABLE
        ));
    }

    #[tokio::test]
    async fn recovery_journal_round_trips_exact_rows_across_reopen_and_removal() {
        let fixture = RecoveryFixture::new(0x21);
        let journal = fixture.create();
        journal.ensure_scope(SCOPE).await.expect("bind scope");
        let first = sealed(3, 0x31);
        journal
            .insert(SCOPE, request_id(1), &first)
            .await
            .expect("durable create-only insert");
        assert_eq!(
            journal.insert(SCOPE, request_id(1), &sealed(3, 0x32)).await,
            Err(StoreError::FencedTransitionRequestConflict),
            "a retained caller ID is never rebound"
        );
        assert_eq!(
            journal.ensure_absent(SCOPE, request_id(1)).await,
            Err(StoreError::FencedTransitionRequestConflict)
        );
        drop(journal);

        let journal = fixture.reopen().expect("reopen existing journal");
        journal.ensure_scope(SCOPE).await.expect("same scope");
        let stored = journal
            .lookup(SCOPE, request_id(1))
            .await
            .expect("lookup")
            .expect("row survives reopen");
        assert!(stored.matches(&first), "the exact sealed request survives");
        assert_eq!(journal.live_entries(SCOPE).await.expect("count"), 1);
        assert_eq!(
            journal
                .remove_if_exact(SCOPE, request_id(1), &sealed(3, 0x32))
                .await,
            Ok(false),
            "a different body can never remove the retained row"
        );
        assert_eq!(
            journal.remove_if_exact(SCOPE, request_id(1), &first).await,
            Ok(true)
        );
        assert_eq!(
            journal.remove_if_exact(SCOPE, request_id(1), &first).await,
            Ok(false),
            "removal is exactly once"
        );
        assert!(journal
            .lookup(SCOPE, request_id(1))
            .await
            .expect("lookup")
            .is_none());
        assert_eq!(journal.live_entries(SCOPE).await.expect("count"), 0);
        journal
            .insert(SCOPE, request_id(1), &sealed(4, 0x33))
            .await
            .expect("a removed caller ID may name a new transition");
        drop(journal);
        let journal = fixture.reopen().expect("reopen after reuse");
        assert!(journal
            .lookup(SCOPE, request_id(1))
            .await
            .expect("lookup")
            .is_some_and(|stored| stored.matches(&sealed(4, 0x33))));
    }

    #[tokio::test]
    async fn recovery_journal_binds_one_scope_and_fails_closed_for_another() {
        let fixture = RecoveryFixture::new(0x22);
        let journal = fixture.create();
        assert_unavailable(journal.lookup(SCOPE, request_id(1)).await);
        assert_unavailable(journal.ensure_scope(RECOVERY_UNBOUND_SCOPE).await);
        journal.ensure_scope(SCOPE).await.expect("bind first scope");
        journal
            .insert(SCOPE, request_id(1), &sealed(1, 0x41))
            .await
            .expect("insert");
        let other = [0x5d; 32];
        assert_unavailable(journal.ensure_scope(other).await);
        assert_unavailable(journal.lookup(other, request_id(1)).await);
        assert_unavailable(journal.ensure_absent(other, request_id(2)).await);
        assert_unavailable(journal.insert(other, request_id(2), &sealed(1, 0x42)).await);
        drop(journal);
        let journal = fixture.reopen().expect("reopen");
        assert_unavailable(journal.ensure_scope(other).await);
        journal
            .ensure_scope(SCOPE)
            .await
            .expect("original scope persists");
        assert!(journal
            .lookup(SCOPE, request_id(1))
            .await
            .expect("lookup")
            .is_some());
    }

    #[tokio::test]
    async fn recovery_journal_provisioning_and_foreign_state_fail_closed() {
        let fixture = RecoveryFixture::new(0x23);
        assert_unavailable(fixture.reopen());
        assert!(!fixture.path.exists(), "open_existing never creates a leaf");
        drop(fixture.create());
        assert_unavailable(FencedTransitionV2RecoveryJournal::create_new(
            &fixture.path,
            fixture.journal_key(),
        ));
        assert_unavailable(FencedTransitionV2RecoveryJournal::open_existing(
            &fixture.path,
            FencedTransitionV2RecoveryJournalKey::from_bytes([0x24; 32]),
        ));
        let v1_path = fixture.path.with_file_name("prepared-v1.sqlite3");
        drop(
            PreparedFencedTransitionJournal::create_new(
                &v1_path,
                PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
            )
            .expect("provision a V1 journal"),
        );
        assert_unavailable(FencedTransitionV2RecoveryJournal::open_existing(
            &v1_path,
            fixture.journal_key(),
        ));
        assert!(
            PreparedFencedTransitionJournal::open_existing(
                &fixture.path,
                PreparedFencedTransitionJournalKey::from_bytes(fixture.key),
            )
            .is_err(),
            "a recovery journal is never readable as a V1 journal"
        );
    }

    #[tokio::test]
    async fn recovery_journal_detects_offline_row_deletion_addition_and_substitution() {
        let fixture = RecoveryFixture::new(0x25);
        let journal = fixture.create();
        journal.ensure_scope(SCOPE).await.expect("bind scope");
        journal
            .insert(SCOPE, request_id(1), &sealed(1, 0x51))
            .await
            .expect("insert first");
        journal
            .insert(SCOPE, request_id(2), &sealed(1, 0x52))
            .await
            .expect("insert second");
        drop(journal);

        // Substituting one authenticated row under another caller ID keeps
        // every tag well formed, but breaks the row and membership proofs.
        {
            let raw = fixture.raw();
            raw.execute(
                &format!(
                    "UPDATE {RECOVERY_TABLE} SET prepared_request = \
                     (SELECT prepared_request FROM {RECOVERY_TABLE} WHERE request_id = ?1), \
                     integrity_tag = (SELECT integrity_tag FROM {RECOVERY_TABLE} WHERE request_id = ?1) \
                     WHERE request_id = ?2"
                ),
                params![request_id(1).as_bytes(), request_id(2).as_bytes()],
            )
            .expect("substitute an authenticated row");
        }
        assert_unavailable(fixture.reopen());

        let fixture = RecoveryFixture::new(0x26);
        let journal = fixture.create();
        journal.ensure_scope(SCOPE).await.expect("bind scope");
        journal
            .insert(SCOPE, request_id(1), &sealed(1, 0x53))
            .await
            .expect("insert");
        drop(journal);
        fixture
            .raw()
            .execute(&format!("DELETE FROM {RECOVERY_TABLE}"), [])
            .expect("delete the row offline");
        assert_unavailable(fixture.reopen());

        let fixture = RecoveryFixture::new(0x27);
        drop(fixture.create());
        let row = sealed(1, 0x54);
        let canonical = canonical_recovery_request(&row).expect("canonical row");
        let tag = recovery_entry_tag(&fixture.bound_key(), request_id(9), 1, &canonical)
            .expect("row tag");
        fixture
            .raw()
            .execute(
                &format!(
                    "INSERT INTO {RECOVERY_TABLE} \
                     (request_id, history_epoch, integrity_tag, prepared_request) \
                     VALUES (?1, 1, ?2, ?3)"
                ),
                params![
                    request_id(9).as_bytes(),
                    tag.as_slice(),
                    canonical.as_slice()
                ],
            )
            .expect("add a validly tagged row outside the membership proof");
        assert_unavailable(fixture.reopen());
    }

    #[tokio::test]
    async fn recovery_journal_admission_fence_is_exact_and_not_absorbing() {
        let fixture = RecoveryFixture::new(0x28);
        drop(fixture.create());
        let key = fixture.bound_key();
        let row = sealed(2, 0x61);
        let canonical = canonical_recovery_request(&row).expect("canonical row");
        {
            let mut raw = fixture.raw();
            let transaction = raw.transaction().expect("capacity transaction");
            let incarnation: [u8; 32] = transaction
                .query_row(
                    &format!("SELECT journal_incarnation FROM {RECOVERY_METADATA_TABLE}"),
                    [],
                    |row| fixed_blob(row.get_ref(0)?),
                )
                .expect("read incarnation");
            let mut members = Vec::with_capacity(FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES);
            for ordinal in 1..=FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES as u64 {
                let id = request_id(ordinal);
                let tag = recovery_entry_tag(&key, id, 2, &canonical).expect("row tag");
                transaction
                    .execute(
                        &format!(
                            "INSERT INTO {RECOVERY_TABLE} \
                             (request_id, history_epoch, integrity_tag, prepared_request) \
                             VALUES (?1, 2, ?2, ?3)"
                        ),
                        params![id.as_bytes(), tag.as_slice(), canonical.as_slice()],
                    )
                    .expect("capacity row");
                members.push(RecoveryMember {
                    request_id: *id.as_bytes(),
                    epoch: 2,
                    tag: *tag,
                    rowid: 1,
                });
            }
            let count = i64::try_from(members.len()).expect("capacity count");
            let root = recovery_membership_root(&incarnation, &members).expect("capacity root");
            let tag = recovery_membership_tag(&key, &incarnation, count, &root).expect("tag");
            transaction
                .execute(
                    &format!(
                        "UPDATE {RECOVERY_METADATA_TABLE} SET membership_count = ?1, \
                         membership_root = ?2, membership_tag = ?3, scope_commitment = ?4, \
                         scope_tag = ?5"
                    ),
                    params![
                        count,
                        root.as_slice(),
                        tag.as_slice(),
                        SCOPE.as_slice(),
                        recovery_scope_tag(&key, &SCOPE).as_slice(),
                    ],
                )
                .expect("publish capacity membership");
            transaction.commit().expect("commit capacity fixture");
        }

        let journal = fixture.reopen().expect("reopen a journal at its fence");
        assert_eq!(
            journal.live_entries(SCOPE).await.expect("count"),
            FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES
        );
        let overflow = request_id(u64::MAX);
        assert_eq!(
            journal.ensure_absent(SCOPE, overflow).await,
            Err(StoreError::FencedTransitionHistoryFull)
        );
        assert_eq!(
            journal.insert(SCOPE, overflow, &sealed(2, 0x62)).await,
            Err(StoreError::FencedTransitionHistoryFull),
            "one over the admission fence is rejected without a row"
        );
        assert_eq!(
            journal.insert(SCOPE, request_id(1), &sealed(2, 0x62)).await,
            Err(StoreError::FencedTransitionRequestConflict),
            "a retained row keeps conflict precedence at the fence"
        );
        assert!(
            journal
                .inner
                .progress_budget
                .observed_callbacks()
                .saturating_mul(2)
                < RECOVERY_OPERATION_MAX_PROGRESS_CALLBACKS,
            "a complete proof at the fence stays well inside the operation budget"
        );
        assert_eq!(
            journal.remove_if_exact(SCOPE, request_id(7), &row).await,
            Ok(true),
            "a resolved row is removable at the fence"
        );
        journal
            .insert(SCOPE, overflow, &sealed(2, 0x62))
            .await
            .expect("removing one resolved row readmits exactly one new ID");
        assert_eq!(
            journal
                .insert(SCOPE, request_id(u64::MAX - 1), &sealed(2, 0x63))
                .await,
            Err(StoreError::FencedTransitionHistoryFull)
        );
        assert_eq!(
            journal
                .remove_retired_through(
                    SCOPE,
                    FencedTransitionV2HistoryEpoch::new(2).expect("floor"),
                    RECOVERY_JOURNAL_MAX_PAGE_ENTRIES,
                )
                .await,
            Ok(RECOVERY_JOURNAL_MAX_PAGE_ENTRIES),
            "retired-floor removal is bounded per call"
        );
        assert_eq!(
            journal.live_entries(SCOPE).await.expect("count"),
            FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES - RECOVERY_JOURNAL_MAX_PAGE_ENTRIES
        );
    }

    #[tokio::test]
    async fn recovery_journal_retired_floor_and_pages_are_bounded_and_ordered() {
        let fixture = RecoveryFixture::new(0x29);
        let journal = fixture.create();
        journal.ensure_scope(SCOPE).await.expect("bind scope");
        for (ordinal, epoch) in [(5_u64, 3_u64), (1, 1), (4, 2), (2, 2), (3, 1)] {
            journal
                .insert(SCOPE, request_id(ordinal), &sealed(epoch, ordinal as u8))
                .await
                .expect("insert");
        }
        let page = journal
            .page_after(SCOPE, None, 2)
            .await
            .expect("first page");
        assert_eq!(
            page.iter()
                .map(|entry| entry.request_id)
                .collect::<Vec<_>>(),
            vec![request_id(1), request_id(2)]
        );
        let page = journal
            .page_after(SCOPE, Some(request_id(2)), 256)
            .await
            .expect("next page");
        assert_eq!(
            page.iter()
                .map(|entry| (entry.request_id, entry.history_epoch.get()))
                .collect::<Vec<_>>(),
            vec![(request_id(3), 1), (request_id(4), 2), (request_id(5), 3)]
        );
        assert_unavailable(journal.page_after(SCOPE, None, 0).await);
        assert_unavailable(
            journal
                .page_after(SCOPE, None, RECOVERY_JOURNAL_MAX_PAGE_ENTRIES + 1)
                .await,
        );
        assert_eq!(
            journal
                .remove_retired_through(
                    SCOPE,
                    FencedTransitionV2HistoryEpoch::new(2).expect("floor"),
                    RECOVERY_JOURNAL_MAX_PAGE_ENTRIES,
                )
                .await,
            Ok(4),
            "only rows at or below the retired floor are removed"
        );
        let remaining = journal.page_after(SCOPE, None, 256).await.expect("page");
        assert_eq!(
            remaining
                .iter()
                .map(|entry| entry.request_id)
                .collect::<Vec<_>>(),
            vec![request_id(5)]
        );
        assert_eq!(
            journal
                .remove_retired_through(
                    SCOPE,
                    FencedTransitionV2HistoryEpoch::new(2).expect("floor"),
                    RECOVERY_JOURNAL_MAX_PAGE_ENTRIES,
                )
                .await,
            Ok(0)
        );
    }
}
