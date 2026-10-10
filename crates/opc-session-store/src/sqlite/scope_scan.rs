//! Dedicated, descriptor-bound SQLite read transactions for scope scans.

use super::*;
use crate::consensus::snapshot::PinnedSqliteFile;
use crate::consensus::{SessionConsensusIdentity, SessionConsensusNodeId};
use opc_consensus::engine::LogId;
use std::io;
use std::sync::Weak;

pub(crate) mod schema;

#[cfg(test)]
std::thread_local! {
    pub(crate) static RAW_RECORD_STATEMENT_BYTES: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

pub(crate) fn read_raw_record(
    connection: &Connection,
    key: &crate::SessionKey,
    maximum_payload_bytes: usize,
) -> io::Result<crate::scope_scan::headers::RawScopeRecord> {
    use crate::scope_scan::headers::RawScopeRecord;
    use rusqlite::types::ValueRef;
    #[cfg(test)]
    RAW_RECORD_STATEMENT_BYTES.set(0);

    // Project bounded values before rusqlite can materialize owned strings or
    // bytes. Invalid types and overlong fields become a final corrupt record;
    // SQL execution failures remain operational errors, never missing rows.
    let mut statement = connection
        .prepare(
            "SELECT
                CASE WHEN typeof(generation)='integer' AND generation>=0 THEN generation END,
                CASE WHEN typeof(owner)='text' AND octet_length(owner) BETWEEN 1 AND ?6 THEN owner END,
                CASE WHEN typeof(fence)='integer' AND fence>=0 THEN fence END,
                CASE WHEN typeof(state_class)='text' AND octet_length(state_class)=21 THEN state_class='authoritative-session' ELSE 0 END,
                CASE WHEN typeof(state_type)='text' AND octet_length(state_type) BETWEEN 1 AND ?7 THEN state_type END,
                typeof(expires_at)='null',
                CASE WHEN typeof(payload)='blob' AND octet_length(payload)<=?5 THEN payload END,
                CASE WHEN typeof(encoding)='integer' THEN encoding=0 ELSE 0 END
             FROM session_records
             WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3 AND stable_id=?4",
        )
        .map_err(consensus::db_error)?;
    let maximum = i64::try_from(maximum_payload_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "scope row bound is invalid"))?;
    let mut rows = statement
        .query(params![
            key.tenant.as_str(),
            key.nf_kind.as_str(),
            key.key_type.as_str(),
            key.stable_id.as_ref(),
            maximum,
            crate::OwnerId::MAX_BYTES as i64,
            crate::StateType::MAX_BYTES as i64,
        ])
        .map_err(consensus::db_error)?;
    let Some(row) = rows.next().map_err(consensus::db_error)? else {
        return Ok(RawScopeRecord::Missing);
    };
    #[cfg(test)]
    RAW_RECORD_STATEMENT_BYTES.set(row.as_ref().get_status(rusqlite::StatementStatus::MemUsed));
    let (
        ValueRef::Integer(generation),
        ValueRef::Text(owner),
        ValueRef::Integer(fence),
        ValueRef::Integer(1),
        ValueRef::Text(state_type),
        ValueRef::Integer(1),
        ValueRef::Blob(payload),
        ValueRef::Integer(1),
    ) = (
        row.get_ref(0).map_err(consensus::db_error)?,
        row.get_ref(1).map_err(consensus::db_error)?,
        row.get_ref(2).map_err(consensus::db_error)?,
        row.get_ref(3).map_err(consensus::db_error)?,
        row.get_ref(4).map_err(consensus::db_error)?,
        row.get_ref(5).map_err(consensus::db_error)?,
        row.get_ref(6).map_err(consensus::db_error)?,
        row.get_ref(7).map_err(consensus::db_error)?,
    )
    else {
        return Ok(RawScopeRecord::Corrupt);
    };
    let (Ok(owner), Ok(state_type)) = (std::str::from_utf8(owner), std::str::from_utf8(state_type))
    else {
        return Ok(RawScopeRecord::Corrupt);
    };
    let (Ok(owner), Ok(state_type)) = (
        crate::OwnerId::new(owner),
        crate::StateType::new(state_type),
    ) else {
        return Ok(RawScopeRecord::Corrupt);
    };
    Ok(RawScopeRecord::Present(crate::StoredSessionRecord {
        key: key.clone(),
        generation: crate::Generation::new(generation as u64),
        owner,
        fence: crate::FenceToken::new(fence as u64),
        state_class: crate::StateClass::AuthoritativeSession,
        state_type,
        expires_at: None,
        payload: crate::EncryptedSessionPayload::new(payload),
    }))
}

impl SqliteSessionBackend {
    /// Configure the next consensus generation's node-wide scan retention.
    /// Backend clones share this setting. An existing generation keeps its
    /// limits until reinitialization and its active views are never evicted.
    pub fn with_scope_scan_limits(self, limits: crate::scope_scan::ScopeScanLimits) -> Self {
        *self
            .scope_scan_limits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = limits;
        self
    }

    /// The primary connection supplies a short local observation, never a
    /// retained reader or an unadmitted immutable root. Writer contention
    /// waits fairly until the owning restore or local guard is cancelled.
    pub(crate) async fn scope_scan_current_headers(
        &self,
        source: &PinnedSqliteFile,
        identity: SessionConsensusIdentity,
        namespace: &crate::scope_authority::ScopeNamespace,
        stamp: &crate::scope_authority::ScopeAuthorityStamp,
        cancelled: &crate::scope_scan::runtime::ViewCancellation,
    ) -> io::Result<
        Result<crate::scope_scan::headers::CapturedHeaders, crate::scope_scan::ScopeScanError>,
    > {
        let connection = tokio::select! {
            biased;
            () = cancelled.cancelled() => return Err(io::Error::new(
                io::ErrorKind::Interrupted, "scope scan guard ended")),
            connection = self.conn.lock() => connection,
        };
        consensus::verify_pinned_snapshot_descriptor(source, &connection)?;
        let transaction = connection
            .unchecked_transaction()
            .map_err(consensus::db_error)?;
        if consensus::read_storage_identity_sync(&transaction)
            .map_err(|_| io::Error::other("scope scan storage identity is unavailable"))?
            != identity
        {
            return Err(io::Error::other("scope scan storage identity differs"));
        }
        let result =
            crate::scope_scan::headers::decode_headers(namespace, stamp, |key, maximum| {
                read_raw_record(&transaction, key, maximum)
                    .map_err(|_| crate::scope_scan::ScopeScanError::Unavailable)
            });
        transaction.rollback().map_err(consensus::db_error)?;
        consensus::verify_pinned_snapshot_descriptor(source, &connection)?;
        Ok(result)
    }
}

pub(crate) fn wal_probe(
    connection: Weak<tokio::sync::Mutex<Connection>>,
    source: Arc<PinnedSqliteFile>,
) -> crate::scope_scan::registry::WalProbe {
    Arc::new(move || {
        let connection = connection.clone();
        let source = Arc::clone(&source);
        Box::pin(async move {
            let connection = connection.upgrade()?;
            let connection = connection.lock().await;
            measure_wal(&connection, &source).ok()
        })
    })
}

fn measure_wal(connection: &Connection, source: &PinnedSqliteFile) -> io::Result<u64> {
    consensus::verify_pinned_snapshot_descriptor(source, connection)?;
    let mut path = source.path().as_os_str().to_os_string();
    path.push("-wal");
    let wal = PinnedSqliteFile::from_file(
        opc_sqlite_file_control_sys::main_journal_descriptor(connection)
            .map_err(|_| io::Error::other("scope scan WAL descriptor is unavailable"))?,
        path.into(),
    )?;
    #[cfg(target_os = "linux")]
    wal.verify_linked_identity()?;
    // A zero length is valid only when measured from the actual linked WAL
    // descriptor, for example after TRUNCATE. Failure is never empty state.
    Ok(wal.file().metadata()?.len())
}

pub(crate) struct SqliteScopeScan {
    reader: consensus::SnapshotReadConnection,
    applied: Option<LogId<SessionConsensusNodeId>>,
}

impl SqliteScopeScan {
    pub(crate) fn capture(
        source: &PinnedSqliteFile,
        identity: SessionConsensusIdentity,
        check: &dyn Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        let reader = consensus::open_snapshot_read_connection(source)?;
        // Busy work is retried by the bounded scan client. Never let SQLite's
        // default busy sleep retain a page worker beyond its work budget.
        reader
            .connection
            .busy_timeout(Duration::ZERO)
            .map_err(consensus::db_error)?;
        check()?;
        let (applied, _) = consensus::begin_snapshot_read_sync(&reader, identity)?;
        if schema::optional_object_count(&reader.connection, false)? != schema::INDEX_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "scope scan indexes are unavailable",
            ));
        }
        let scan = Self { reader, applied };
        check()?;
        scan.wal_bytes()?;
        Ok(scan)
    }

    pub(crate) fn applied(&self) -> Option<LogId<SessionConsensusNodeId>> {
        self.applied
    }

    pub(crate) fn wal_bytes(&self) -> io::Result<u64> {
        if self.reader.connection.is_autocommit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "scope scan read transaction ended",
            ));
        }
        consensus::verify_snapshot_read_connection(&self.reader)?;
        // This is a descriptor measurement, with no active-reader ceiling.
        // The registry uses the high-water mark only for new admissions.
        consensus::verify_snapshot_reader_wal(&self.reader)
    }

    pub(crate) fn read<T, I: Fn() -> bool + Clone + Send + 'static>(
        &self,
        interrupted: I,
        read: impl FnOnce(&Connection, &dyn Fn() -> io::Result<()>) -> io::Result<T>,
    ) -> io::Result<T> {
        let check = || {
            if interrupted() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "scope scan page work interrupted",
                ));
            }
            self.wal_bytes().map(|_| ())
        };
        check()?;
        self.reader
            .connection
            .progress_handler(4096, Some(interrupted.clone()))
            .map_err(consensus::db_error)?;
        let _progress = Progress(&self.reader.connection);
        let result = read(&self.reader.connection, &check);
        // Cancellation, budget and source-identity checks also guard the
        // finished result, including a VM interruption reported as SQL error.
        check()?;
        result
    }

    /// Bounded page work may return its completed prefix after exhausting
    /// work capacity. Cancellation and descriptor invalidation still discard
    /// every late result, including a completed prefix.
    pub(crate) fn read_bounded<
        T,
        C: Fn() -> bool + Clone + Send + 'static,
        W: Fn() -> bool + Clone + Send + 'static,
    >(
        &self,
        cancelled: C,
        work_exhausted: W,
        read: impl FnOnce(&Connection, &dyn Fn() -> io::Result<()>, &dyn Fn() -> bool) -> io::Result<T>,
    ) -> io::Result<T> {
        let check = || {
            if cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "scope scan page cancelled",
                ));
            }
            self.wal_bytes().map(|_| ())
        };
        check()?;
        use std::sync::atomic::{AtomicUsize, Ordering};
        const VM_INTERVAL: usize = 4096;
        // Round down, so the callback quantum never exceeds the hard ceiling.
        const MAX_TICKS: usize = crate::RESTORE_SCAN_MAX_SQLITE_VM_STEPS / VM_INTERVAL;
        let ticks = Arc::new(AtomicUsize::new(0));
        let vm_ticks = Arc::clone(&ticks);
        let vm_cancelled = cancelled.clone();
        let vm_work_exhausted = work_exhausted.clone();
        self.reader
            .connection
            .progress_handler(
                VM_INTERVAL as i32,
                Some(move || {
                    // Saturation keeps a caught interruption exhausted even if a
                    // callback elects to issue another query in this operation.
                    let mut count = vm_ticks.load(Ordering::Relaxed);
                    loop {
                        match vm_ticks.compare_exchange_weak(
                            count,
                            count.saturating_add(1).min(MAX_TICKS),
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(actual) => count = actual,
                        }
                    }
                    vm_cancelled()
                        || vm_work_exhausted()
                        || vm_ticks.load(Ordering::Relaxed) >= MAX_TICKS
                }),
            )
            .map_err(consensus::db_error)?;
        let _progress = Progress(&self.reader.connection);
        let bounded_work = || work_exhausted() || ticks.load(Ordering::Relaxed) >= MAX_TICKS;
        let result = read(&self.reader.connection, &check, &bounded_work);
        // The engine may have caught a VM budget error and retained its fully
        // inspected prefix. Only cancellation or lost descriptor ownership
        // suppresses that prefix at this boundary.
        check()?;
        result
    }
}

struct Progress<'a>(&'a Connection);

impl Drop for Progress<'_> {
    fn drop(&mut self) {
        // Hook installation proved this is an owning connection. Removal's
        // only possible error rejects a borrowed raw handle; that ownership
        // cannot change through this shared borrow. Also clear during unwind.
        let _ = self.0.progress_handler(0, None::<fn() -> bool>);
    }
}

impl Drop for SqliteScopeScan {
    fn drop(&mut self) {
        // Unconditionally release, even after replacement, unlink or a work
        // failure. Connection destruction then closes every owned descriptor.
        let _ = consensus::release_snapshot_read_sync(&self.reader);
    }
}
