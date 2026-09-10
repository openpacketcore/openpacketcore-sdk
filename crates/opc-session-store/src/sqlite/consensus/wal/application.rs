//! SQLite application cache bound to an acknowledged WAL commit cut.
//!
//! All business effects, receipts, notifications, the applied pointer and the
//! cache marker share the original state-machine transaction. The SQL log is
//! a materialized committed prefix for existing validation/snapshot readers;
//! it cannot authorize Raft acknowledgement. Recovery reconstructs the pending
//! view by replay and compares every non-log table, not only a high-water mark.

use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::super::{
    self as consensus, AppliedBatch, BackendCapabilities, SessionConsensusNodeId,
    SessionRaftTypeConfig,
};
use super::{
    append_logs_in_tx, db_error, decode_json, encode_json, ensure_readable, invalid_data,
    lock_state, read_applied_sync, read_committed_sync, read_log_range_sync,
    read_storage_identity_sync, save_committed_in_tx, validate_exact_log_prefix_through_sync,
    Binding, Digest, Entry, LogId, Operation, Sha256, State, Status, Wal, MAX_ENTRIES,
};
use std::io;
use std::time::{Duration, Instant};

const MARKER_SCHEMA: &str = "CREATE TABLE consensus_wal_application (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), marker_json BLOB NOT NULL)";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Marker {
    pub(super) binding: [u8; 32],
    pub(super) cut_sequence: u64,
    pub(super) cut_chain: [u8; 32],
    pub(super) applied: LogId<SessionConsensusNodeId>,
}

/// Bound to one live connection by a temporary nonce. The two SQLite change
/// counters cover writes on that connection and commits by other connections;
/// schema_version covers DDL. They are checked again under the Immediate
/// transaction. This is writer-exclusion evidence, not a content checksum.
pub(super) struct CacheGuard {
    token: [u8; 16],
    changes: u64,
    data_version: i64,
    schema_version: i64,
}

/// A full audit (or an audited extension) proved this exact applied prefix.
/// The connection is the private, unshared anonymous projection of this State;
/// no connection reference escapes the state mutex. These counters bind the
/// proof to its sole-writer lineage, not to an unchecked applied pointer.
/// Durable authorization still comes from the acknowledged cut on each apply.
pub(super) struct AppliedPrefix {
    binding: [u8; 32],
    applied: LogId<SessionConsensusNodeId>,
    changes: u64,
    data_version: i64,
    schema_version: i64,
}

impl AppliedPrefix {
    // Only restore's complete comparison and apply's successful pair of
    // original transactions may establish or advance an applied proof.
    fn after_audit(
        state: &State,
        binding: Binding,
        applied: LogId<SessionConsensusNodeId>,
    ) -> io::Result<Self> {
        let proof = Self {
            binding: binding.digest()?,
            applied,
            changes: state.conn.total_changes(),
            data_version: projection_data_version(&state.conn)?,
            schema_version: projection_schema_version(&state.conn)?,
        };
        proof.validate(state, binding)?;
        Ok(proof)
    }

    fn validate_metadata(&self, state: &State, binding: Binding) -> io::Result<()> {
        if !state.conn.is_autocommit()
            || self.binding != binding.digest()?
            || read_applied_sync(&state.conn, binding.identity)? != Some(self.applied)
            || projection_data_version(&state.conn)? != self.data_version
            || projection_schema_version(&state.conn)? != self.schema_version
        {
            return Err(invalid_data("private WAL applied-prefix lineage differs"));
        }
        Ok(())
    }

    fn validate(&self, state: &State, binding: Binding) -> io::Result<()> {
        self.validate_metadata(state, binding)?;
        if state.conn.total_changes() != self.changes {
            return Err(invalid_data(
                "private WAL applied prefix changed outside its owner",
            ));
        }
        Ok(())
    }
}

fn projection_schema_version(conn: &Connection) -> io::Result<i64> {
    conn.pragma_query_value(
        Some(rusqlite::DatabaseName::Main),
        "schema_version",
        |row| row.get(0),
    )
    .map_err(db_error)
}

fn projection_data_version(conn: &Connection) -> io::Result<i64> {
    conn.pragma_query_value(Some(rusqlite::DatabaseName::Main), "data_version", |row| {
        row.get(0)
    })
    .map_err(db_error)
}

pub(super) fn validate_applied_prefix(state: &State, binding: Binding) -> io::Result<()> {
    if let Some(proof) = &state.applied_prefix {
        proof.validate(state, binding)?;
    }
    Ok(())
}

/// The only live log-projection mutation boundary. Original append inserts
/// strictly after the last log and replays the complete unapplied projection;
/// vote/commit/barrier never change applied rows, compaction markers or schema.
/// Preserve a proof only after one of those original transactions succeeds.
/// Destructive attempts and all projection errors discard it, including a
/// rolled-back write whose total_changes counter still increased. Recovery
/// replays without a proof and establishes one only after its full audit.
pub(super) fn project_operation(
    state: &mut State,
    binding: Binding,
    operation: &Operation,
) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
    if let Some(native) = &mut state.native {
        return native
            .log
            .project(operation, &native.business, state.authority.frozen_applied);
    }
    if let Err(error) = validate_applied_prefix(state, binding) {
        fence(state);
        return Err(error);
    }
    let inherited = state.applied_prefix.take().filter(|_| {
        matches!(
            operation,
            Operation::Append(_)
                | Operation::Vote(_)
                | Operation::Committed(_)
                | Operation::Barrier
        )
    });
    let committed =
        operation.validate_and_project(&state.conn, binding.identity, &state.authority)?;
    if let Some(mut proof) = inherited {
        if let Err(error) = proof.validate_metadata(state, binding) {
            fence(state);
            return Err(error);
        }
        // This refresh follows a successful, prefix-preserving transaction
        // under the same State lock. It cannot mint a missing proof.
        proof.changes = state.conn.total_changes();
        state.applied_prefix = Some(proof);
    }
    Ok(committed)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ApplyControl {
    #[default]
    Normal,
    BeforeSqliteCommit,
    AfterSqliteCommit,
}

impl Wal {
    pub(crate) fn validate_application_cache(&self, conn: &Connection) -> io::Result<()> {
        if self.is_native() {
            return self.with_native_read(|_| Ok(()));
        }
        let started = Instant::now();
        let mut state = self.wait_for_snapshot(lock_state(&self.shared)?)?;
        let lock_wait = started.elapsed();
        ensure_readable(&state)?;
        let validation_started = Instant::now();
        let result = validate_live_cache(conn, &state, self.binding);
        let validation = validation_started.elapsed();
        if result.is_err() {
            fence(&mut state);
            self.shared.ready.notify_all();
        }
        let costs = &mut state.cache_validation_costs;
        costs.calls += 1;
        costs.guard_failures += u64::from(result.is_err());
        costs.lock_wait += lock_wait;
        costs.validation += validation;
        costs.total += started.elapsed();
        result
    }

    /// Keep detection and the returned physical read under the same WAL
    /// fence. A foreign commit during the read invalidates the result before
    /// any waiting durability callback can succeed. The closure must finish
    /// its own read transaction before returning, so data_version is fresh.
    pub(crate) fn with_application_read<T>(
        &self,
        conn: &Connection,
        read: impl FnOnce() -> T,
    ) -> io::Result<T> {
        if self.is_native() {
            return self.reject_native_sql_fallback();
        }
        let started = Instant::now();
        let mut state = self.wait_for_snapshot(lock_state(&self.shared)?)?;
        let lock_wait = started.elapsed();
        ensure_readable(&state)?;
        let mut validation = Duration::ZERO;
        let mut read_duration = Duration::ZERO;
        let result = (|| {
            if !conn.is_autocommit() {
                return Err(invalid_data(
                    "private WAL read entered with an active transaction",
                ));
            }
            let validation_started = Instant::now();
            let validated = validate_live_cache(conn, &state, self.binding);
            validation += validation_started.elapsed();
            validated?;
            let read_started = Instant::now();
            let value = read();
            read_duration = read_started.elapsed();
            if !conn.is_autocommit() {
                return Err(invalid_data(
                    "private WAL read retained an active transaction",
                ));
            }
            let validation_started = Instant::now();
            let validated = validate_live_cache(conn, &state, self.binding);
            validation += validation_started.elapsed();
            validated?;
            Ok(value)
        })();
        if result.is_err() {
            fence(&mut state);
            self.shared.ready.notify_all();
        }
        let costs = &mut state.cache_read_costs;
        costs.calls += 1;
        costs.guard_failures += u64::from(result.is_err());
        costs.lock_wait += lock_wait;
        costs.validation += validation;
        costs.read += read_duration;
        costs.total += started.elapsed();
        result
    }

    pub(in crate::sqlite::consensus) fn restore_application(
        &self,
        conn: &Connection,
        caps: &BackendCapabilities,
    ) -> io::Result<()> {
        let mut state = self.wait_for_snapshot(lock_state(&self.shared)?)?;
        ensure_readable(&state)?;
        let result = restore(&mut state, conn, caps, self.binding);
        if result.is_err() {
            fence(&mut state);
            self.shared.ready.notify_all();
        }
        result
    }

    pub(crate) fn apply_committed(
        &self,
        conn: &Connection,
        caps: &BackendCapabilities,
        entries: Vec<Entry<SessionRaftTypeConfig>>,
        control: ApplyControl,
    ) -> io::Result<AppliedBatch> {
        let started = Instant::now();
        let mut state = self.wait_for_snapshot(lock_state(&self.shared)?)?;
        let lock_wait = started.elapsed();
        let preflight_started = Instant::now();
        ensure_readable(&state)?;
        if state.application_guard.is_none() {
            if let Err(error) = restore(&mut state, conn, caps, self.binding) {
                fence(&mut state);
                self.shared.ready.notify_all();
                return Err(error);
            }
        }
        if let Err(error) = validate_cache_guard(conn, &state)
            .and_then(|()| validate_cache_frontier(conn, &state, self.binding))
        {
            fence(&mut state);
            self.shared.ready.notify_all();
            return Err(error);
        }
        if entries.is_empty() {
            let result = apply_original(conn, caps, &state, self.binding, entries);
            if result.is_err() {
                fence(&mut state);
                self.shared.ready.notify_all();
            }
            return result;
        }
        let last = entries
            .last()
            .ok_or_else(|| invalid_data("private WAL application batch is empty"))?
            .log_id;
        let next = next_index(read_applied_sync(&state.conn, self.binding.identity)?)?;
        if entries.first().map(|entry| entry.log_id.index) != Some(next) {
            return Err(invalid_data("private WAL application is not contiguous"));
        }
        if let Err(error) = require_durable_committed(&state, self.binding, last).and_then(|()| {
            require_exact_entries(&state.conn, self.binding, next, last.index, &entries)
        }) {
            if !matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::WouldBlock
            ) {
                fence(&mut state);
                self.shared.ready.notify_all();
            }
            return Err(error);
        }
        let (&cut_sequence, cut) = state
            .durable_cuts
            .last_key_value()
            .ok_or_else(|| invalid_data("private WAL application lacks a durable cut"))?;
        let marker = Marker {
            binding: self.binding.digest()?,
            cut_sequence,
            cut_chain: cut.chain,
            applied: last,
        };
        let preflight = preflight_started.elapsed();
        let entry_count = entries.len() as u64;
        let mut sqlite_apply = Duration::ZERO;
        let mut sqlite_commit_and_return = Duration::ZERO;
        let mut projection_apply = Duration::ZERO;
        let mut verification = Duration::ZERO;
        let result = (|| {
            let next_guard = std::cell::RefCell::new(None);
            let commit_started = std::cell::Cell::new(None);
            let sqlite_started = Instant::now();
            let applied = consensus::apply_entries_with_authority_and_diagnostics_and_hooks_sync(
                conn,
                self.binding.identity,
                caps,
                state.authority.profile,
                &state.authority.members,
                &state.authority.bindings,
                state.authority.placement,
                entries.clone(),
                None,
                |tx| {
                    // No SQL log write occurs before the original apply
                    // transaction or for an uncommitted/pending WAL record.
                    validate_cache_guard(tx, &state)?;
                    validate_cache_frontier(tx, &state, self.binding)?;
                    append_logs_in_tx(tx, self.binding.identity, &entries)?;
                    save_committed_in_tx(tx, self.binding.identity, Some(last))
                },
                |tx| {
                    write_marker(tx, &marker)?;
                    if control == ApplyControl::BeforeSqliteCommit {
                        return Err(io::Error::other("private WAL injected pre-commit failure"));
                    }
                    let token = state
                        .application_guard
                        .as_ref()
                        .ok_or_else(|| {
                            invalid_data("private WAL cache connection is not attached")
                        })?
                        .token;
                    *next_guard.borrow_mut() = Some(read_cache_guard(tx, token)?);
                    commit_started.set(Some(Instant::now()));
                    Ok(())
                },
            )?;
            sqlite_apply = sqlite_started.elapsed();
            sqlite_commit_and_return = commit_started
                .get()
                .map_or(Duration::ZERO, |started| started.elapsed());
            if control == ApplyControl::AfterSqliteCommit {
                return Err(io::Error::other(
                    "private WAL injected committed reply loss",
                ));
            }
            // The pending suffix remains in this connection. Running the
            // same original apply advances its base; admission still replays
            // the entire unapplied suffix with the original validators.
            let projection_started = Instant::now();
            let projected = apply_original(&state.conn, caps, &state, self.binding, entries)?;
            projection_apply = projection_started.elapsed();
            let verification_started = Instant::now();
            if encode_json(&applied.responses)? != encode_json(&projected.responses)?
                || encode_json(&applied.notifications)? != encode_json(&projected.notifications)?
            {
                return Err(invalid_data("private WAL application projection differs"));
            }
            state.application_guard =
                Some(next_guard.into_inner().ok_or_else(|| {
                    invalid_data("private WAL application commit guard is missing")
                })?);
            // Never bless a competing write that raced the end of our SQL
            // transaction by sampling a new expected version after commit.
            validate_cache_guard(conn, &state)?;
            state.applied_prefix = Some(AppliedPrefix::after_audit(&state, self.binding, last)?);
            state.application_marker = Some(marker);
            verification = verification_started.elapsed();
            Ok(applied)
        })();
        if result.is_err() {
            // A commit error is potentially ambiguous. Do not infer rollback
            // or accept a second writer against an uncertain applied base.
            fence(&mut state);
            self.shared.ready.notify_all();
        } else {
            let costs = &mut state.application_costs;
            costs.successful_nonempty_batches += 1;
            costs.entries += entry_count;
            costs.lock_wait += lock_wait;
            costs.preflight += preflight;
            costs.sqlite_apply += sqlite_apply;
            costs.sqlite_commit_and_return += sqlite_commit_and_return;
            costs.projection_apply += projection_apply;
            costs.verification += verification;
            costs.total += started.elapsed();
        }
        result
    }
}

pub(super) fn validate_live_cache(
    conn: &Connection,
    state: &State,
    binding: Binding,
) -> io::Result<()> {
    validate_cache_guard(conn, state)?;
    validate_cache_frontier(conn, state, binding)?;
    if let Some(path) = conn.path().filter(|path| !path.is_empty()) {
        let recovery = consensus::classify_operator_recovery_latch_with_connection_sync(
            std::path::Path::new(path),
            conn,
        )?;
        if recovery.latch().is_some() || recovery.has_consumed_terminal() {
            return Err(invalid_data(
                "private WAL live recovery routing is unsupported",
            ));
        }
    }
    Ok(())
}

pub(super) fn fence(state: &mut State) {
    state.status = Status::Failed;
    state.applied_prefix = None;
    state.queue.clear();
}

fn next_index(applied: Option<LogId<SessionConsensusNodeId>>) -> io::Result<u64> {
    applied.map_or(Ok(0), |applied| {
        applied
            .index
            .checked_add(1)
            .ok_or_else(|| invalid_data("private WAL applied index exhausted"))
    })
}

fn require_durable_committed(
    state: &State,
    binding: Binding,
    applied: LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let committed = state.durable_committed.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "private WAL has no durable committed prefix",
        )
    })?;
    consensus::ensure_log_id_not_after(
        &applied,
        &committed,
        "private WAL application exceeds durable committed prefix",
    )
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private WAL application exceeds durable committed prefix",
        )
    })?;
    match &state.applied_prefix {
        Some(proof) => {
            proof.validate(state, binding)?;
            consensus::validate_exact_committed_log_advance_sync(
                &state.conn,
                binding.identity,
                &proof.applied,
                &applied,
            )
        }
        None => {
            validate_exact_log_prefix_through_sync(&state.conn, binding.identity, &applied, false)
        }
    }
}

fn validate_cache_frontier(conn: &Connection, state: &State, binding: Binding) -> io::Result<()> {
    validate_applied_prefix(state, binding)?;
    if read_storage_identity_sync(conn)
        .map_err(|_| invalid_data("private WAL application identity invalid"))?
        != binding.identity
    {
        return Err(invalid_data("private WAL application identity differs"));
    }
    state.authority.validate(conn, binding.identity)?;
    let applied = read_applied_sync(conn, binding.identity)?;
    if applied != read_applied_sync(&state.conn, binding.identity)?
        || read_committed_sync(conn, binding.identity)? != applied
        || consensus::last_log_sync(conn, binding.identity)? != applied
    {
        return Err(invalid_data(
            "private WAL application cache frontier differs",
        ));
    }
    validate_marker(conn, state, binding, applied)?;
    Ok(())
}

fn require_exact_entries(
    conn: &Connection,
    binding: Binding,
    start: u64,
    last: u64,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> io::Result<()> {
    let end = last
        .checked_add(1)
        .ok_or_else(|| invalid_data("private WAL log range exhausted"))?;
    let count = u64::try_from(entries.len())
        .map_err(|_| invalid_data("private WAL application count exceeds range"))?;
    if end.checked_sub(start) != Some(count) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private WAL application entries differ from WAL",
        ));
    }
    let mut next = start;
    for chunk in entries.chunks(MAX_ENTRIES) {
        let chunk_end = next
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| invalid_data("private WAL application range exhausted"))?;
        let persisted = read_log_range_sync(
            conn,
            binding.identity,
            next,
            Some(chunk_end),
            Some(MAX_ENTRIES),
        )?;
        if persisted.len() != chunk.len() {
            return Err(invalid_data(
                "private WAL application range contains a hole",
            ));
        }
        // Compare one complete entry at a time, without serializing an
        // arbitrarily large apply batch into another aggregate allocation.
        for (persisted, expected) in persisted.iter().zip(chunk) {
            if encode_json(persisted)? != encode_json(expected)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private WAL application entries differ from WAL",
                ));
            }
        }
        next = chunk_end;
    }
    Ok(())
}

fn apply_original(
    conn: &Connection,
    caps: &BackendCapabilities,
    state: &State,
    binding: Binding,
    entries: Vec<Entry<SessionRaftTypeConfig>>,
) -> io::Result<AppliedBatch> {
    consensus::apply_entries_with_authority_sync(
        conn,
        binding.identity,
        caps,
        state.authority.profile,
        &state.authority.members,
        &state.authority.bindings,
        state.authority.placement,
        entries,
    )
}

fn restore(
    state: &mut State,
    conn: &Connection,
    caps: &BackendCapabilities,
    binding: Binding,
) -> io::Result<()> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_error)?;
    let restored = restore_transaction(state, &tx, caps, binding)?;
    tx.commit().map_err(db_error)?;
    finish_restore(state, conn, binding, restored)
}

pub(super) struct RestoredCache {
    guard: CacheGuard,
    applied: Option<LogId<SessionConsensusNodeId>>,
    marker: Option<Marker>,
}

/// The opening owner keeps this same Immediate transaction through pending
/// snapshot resolution and WAL cleanup. Neither files nor a usable owner can
/// escape between the complete cache audit and publication stabilization.
pub(super) fn restore_transaction(
    state: &mut State,
    tx: &Transaction<'_>,
    caps: &BackendCapabilities,
    binding: Binding,
) -> io::Result<RestoredCache> {
    validate_applied_prefix(state, binding)?;
    // Even an explicit reattachment of this live connection performs the
    // full prefix/content audit. No proof crosses a recovery boundary.
    state.applied_prefix = None;
    // One SQLite read image for all recovery comparisons. The write lock also
    // excludes a competing cache writer before the connection guard is bound.
    let conn = tx;
    if state.application_guard.is_some() {
        validate_cache_guard(conn, state)?;
    }
    state.authority.validate(conn, binding.identity)?;
    let applied = read_applied_sync(conn, binding.identity)?;
    validate_marker(conn, state, binding, applied)?;
    if read_committed_sync(conn, binding.identity)? != applied
        || consensus::last_log_sync(conn, binding.identity)? != applied
    {
        return Err(invalid_data(
            "private WAL cache contains unapplied SQL history",
        ));
    }
    let current = read_applied_sync(&state.conn, binding.identity)?;
    if let Some(current) = current {
        consensus::ensure_log_id_not_after(
            &current,
            &applied.ok_or_else(|| {
                invalid_data("private WAL application cache lost its applied pointer")
            })?,
            "private WAL application cache regressed",
        )?;
    }
    if let Some(applied) = applied {
        require_durable_committed(state, binding, applied)?;
        validate_exact_log_prefix_through_sync(conn, binding.identity, &applied, false)?;
        require_exact_cached_log_prefix(conn, &state.conn, applied.index)?;
        let mut next = next_index(current)?;
        while next <= applied.index {
            let end = next
                .checked_add(MAX_ENTRIES as u64)
                .unwrap_or(u64::MAX)
                .min(next_index(Some(applied))?);
            let entries = read_log_range_sync(
                &state.conn,
                binding.identity,
                next,
                Some(end),
                Some(MAX_ENTRIES),
            )?;
            if entries.len()
                != usize::try_from(end - next)
                    .map_err(|_| invalid_data("private WAL replay range exceeds limit"))?
            {
                return Err(invalid_data(
                    "private WAL application replay contains a hole",
                ));
            }
            apply_original(&state.conn, caps, state, binding, entries)?;
            next = end;
        }
    }
    if application_digest(conn)? != application_digest(&state.conn)? {
        return Err(invalid_data(
            "private WAL recovered application image differs",
        ));
    }
    validate_cache_frontier(conn, state, binding)?;
    let token = *uuid::Uuid::new_v4().as_bytes();
    conn.execute_batch("CREATE TEMP TABLE IF NOT EXISTS consensus_wal_application_connection (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), token BLOB NOT NULL)").map_err(db_error)?;
    conn.execute("INSERT OR REPLACE INTO temp.consensus_wal_application_connection (singleton, token) VALUES (1, ?1)", params![token.as_slice()]).map_err(db_error)?;
    let guard = read_cache_guard(conn, token)?;
    Ok(RestoredCache {
        guard,
        applied,
        marker: marker(conn)?,
    })
}

pub(super) fn finish_restore(
    state: &mut State,
    cache: &Connection,
    binding: Binding,
    restored: RestoredCache,
) -> io::Result<()> {
    state.application_guard = Some(restored.guard);
    validate_cache_guard(cache, state)?;
    state.applied_prefix = restored
        .applied
        .map(|applied| AppliedPrefix::after_audit(state, binding, applied))
        .transpose()?;
    state.application_marker = restored.marker;
    Ok(())
}

#[cfg(test)]
impl Wal {
    /// Deliberately bypass the sole writer for corruption regressions. This
    /// never refreshes a proof or a connection counter expectation.
    pub(in crate::sqlite::consensus) fn corrupt_projection_for_test(
        &self,
        corrupt: impl FnOnce(&Connection),
    ) {
        let state = lock_state(&self.shared).unwrap();
        assert!(
            state.applied_prefix.is_some(),
            "test starts with an audited prefix"
        );
        corrupt(&state.conn);
    }
}

fn read_cache_guard(conn: &Connection, token: [u8; 16]) -> io::Result<CacheGuard> {
    Ok(CacheGuard {
        token,
        changes: conn.total_changes(),
        data_version: conn
            .pragma_query_value(Some(rusqlite::DatabaseName::Main), "data_version", |row| {
                row.get(0)
            })
            .map_err(db_error)?,
        schema_version: conn
            .pragma_query_value(
                Some(rusqlite::DatabaseName::Main),
                "schema_version",
                |row| row.get(0),
            )
            .map_err(db_error)?,
    })
}

pub(super) fn validate_cache_guard(conn: &Connection, state: &State) -> io::Result<()> {
    let guard = state
        .application_guard
        .as_ref()
        .ok_or_else(|| invalid_data("private WAL cache connection is not attached"))?;
    let token: Vec<u8> = conn
        .query_row(
            "SELECT token FROM temp.consensus_wal_application_connection WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let current = read_cache_guard(conn, guard.token)?;
    if token != guard.token
        || current.changes != guard.changes
        || current.data_version != guard.data_version
        || current.schema_version != guard.schema_version
    {
        return Err(invalid_data(
            "private WAL application cache changed outside its owner",
        ));
    }
    Ok(())
}

pub(super) fn capture_cache_guard(conn: &Connection, state: &State) -> io::Result<CacheGuard> {
    let token = state
        .application_guard
        .as_ref()
        .ok_or_else(|| invalid_data("private WAL snapshot cache is not attached"))?
        .token;
    read_cache_guard(conn, token)
}

/// Snapshot metadata and joint physical compaction may change at the same
/// applied frontier. Both images must have the exact same raw applied log,
/// marker and business state after the declared transformation;
/// pending WAL logs, vote and logical purge remain owned by the selected basis.
pub(super) fn audit_snapshot_cache(
    cache: &Connection,
    basis: &Connection,
    binding: Binding,
    expected_marker: &Option<Marker>,
) -> io::Result<()> {
    super::validate_basis(cache, binding.identity)?;
    super::Authority::load(basis, binding.identity)?.validate(cache, binding.identity)?;
    let applied = read_applied_sync(basis, binding.identity)?;
    if read_applied_sync(cache, binding.identity)? != applied
        || read_committed_sync(cache, binding.identity)? != applied
        || consensus::last_log_sync(cache, binding.identity)? != applied
        || marker(cache)? != *expected_marker
        || application_digest(cache)? != application_digest(basis)?
    {
        return Err(invalid_data(
            "private WAL snapshot cache is not its complete bound image",
        ));
    }
    if let Some(applied) = applied {
        validate_exact_log_prefix_through_sync(cache, binding.identity, &applied, false)?;
        require_exact_cached_log_prefix(cache, basis, applied.index)?;
    }
    // Inspect physical rows even below a logical floor, including the empty
    // frontier. A hidden unapplied cache row is never part of this handoff.
    let max_index: Option<i64> = cache
        .query_row("SELECT MAX(log_index) FROM consensus_log", [], |row| {
            row.get(0)
        })
        .map_err(db_error)?;
    if max_index.is_some_and(|index| {
        applied.is_none_or(|applied| index < 0 || index as u64 > applied.index)
    }) {
        return Err(invalid_data(
            "private WAL snapshot cache has a physical unapplied suffix",
        ));
    }
    Ok(())
}

pub(super) fn complete_snapshot_cache(
    state: &mut State,
    conn: &Connection,
    binding: Binding,
    guard: CacheGuard,
) -> io::Result<()> {
    state.application_guard = Some(guard);
    validate_cache_guard(conn, state)?;
    audit_snapshot_cache(conn, &state.conn, binding, &state.application_marker)?;
    state.applied_prefix = read_applied_sync(&state.conn, binding.identity)?
        .map(|applied| AppliedPrefix::after_audit(state, binding, applied))
        .transpose()?;
    validate_cache_guard(conn, state)
}

fn marker(conn: &Connection) -> io::Result<Option<Marker>> {
    let schema: Option<String> = conn
        .query_row("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'consensus_wal_application'", [], |row| row.get(0))
        .optional()
        .map_err(db_error)?;
    let Some(schema) = schema else {
        return Ok(None);
    };
    if schema != MARKER_SCHEMA {
        return Err(invalid_data(
            "private WAL application marker schema differs",
        ));
    }
    let rows: usize = conn
        .query_row(
            "SELECT COUNT(*) FROM consensus_wal_application",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if rows != 1 {
        return Err(invalid_data(
            "private WAL application marker cardinality differs",
        ));
    }
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT marker_json FROM consensus_wal_application WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if bytes.len() > 4096 {
        return Err(invalid_data("private WAL application marker exceeds limit"));
    }
    let marker: Marker = decode_json(&bytes)?;
    if encode_json(&marker)? != bytes {
        return Err(invalid_data("private WAL application marker is not exact"));
    }
    Ok(Some(marker))
}

fn validate_marker(
    conn: &Connection,
    state: &State,
    binding: Binding,
    applied: Option<LogId<SessionConsensusNodeId>>,
) -> io::Result<()> {
    match marker(conn)? {
        Some(marker) if marker.binding == binding.digest()? && Some(marker.applied) == applied => {
            if let Some(expected) = &state.application_marker {
                // A selected basis carries the exact marker required at its
                // applied frontier. A later original cache transaction can
                // extend that frontier, but neither dropping its marker nor
                // relabeling the same applied image is an accepted extension.
                consensus::ensure_log_id_not_after(
                    &expected.applied,
                    &marker.applied,
                    "private WAL application marker regressed from selected basis",
                )?;
                if marker.cut_sequence < expected.cut_sequence
                    || (marker.applied == expected.applied && marker != *expected)
                {
                    return Err(invalid_data(
                        "private WAL application marker changed at selected frontier",
                    ));
                }
            }
            let cut = state
                .durable_cuts
                .get(&marker.cut_sequence)
                .filter(|cut| cut.chain == marker.cut_chain)
                .ok_or_else(|| invalid_data("private WAL application cut lineage differs"))?;
            let committed = cut.committed.ok_or_else(|| {
                invalid_data("private WAL application cut has no committed prefix")
            })?;
            consensus::ensure_log_id_not_after(
                &marker.applied,
                &committed,
                "private WAL application marker precedes committed durability",
            )
        }
        None if state.application_marker.is_none() && applied == state.authority.frozen_applied => {
            Ok(())
        }
        _ => Err(invalid_data(
            "private WAL application marker lacks exact durable lineage",
        )),
    }
}

pub(super) fn write_marker(tx: &Transaction<'_>, marker: &Marker) -> io::Result<()> {
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'consensus_wal_application')",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if !exists {
        tx.execute_batch(MARKER_SCHEMA).map_err(db_error)?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO consensus_wal_application (singleton, marker_json) VALUES (1, ?1)",
        params![encode_json(marker)?],
    )
    .map_err(db_error)?;
    Ok(())
}

// Physical retained rows must match too: comparing only the applied LogId
// would miss a well-formed replacement of a committed payload. Logical purge
// keeps these validation rows until coordinated snapshot/cache compaction;
// a moving WAL basis alone cannot authorize excluding covered physical rows.
fn require_exact_cached_log_prefix(
    cache: &Connection,
    pending: &Connection,
    through: u64,
) -> io::Result<()> {
    let sql = "SELECT log_index, configuration_epoch, term, entry_json FROM consensus_log WHERE log_index <= ?1 ORDER BY log_index";
    let through = consensus::checked_i64(through)?;
    let mut left = cache.prepare(sql).map_err(db_error)?;
    let mut right = pending.prepare(sql).map_err(db_error)?;
    let mut left = left.query([through]).map_err(db_error)?;
    let mut right = right.query([through]).map_err(db_error)?;
    loop {
        match (
            left.next().map_err(db_error)?,
            right.next().map_err(db_error)?,
        ) {
            (None, None) => return Ok(()),
            (Some(left), Some(right)) => {
                for column in 0..4 {
                    if left.get_ref(column).map_err(db_error)?
                        != right.get_ref(column).map_err(db_error)?
                    {
                        return Err(invalid_data("private WAL materialized log prefix differs"));
                    }
                }
            }
            _ => {
                return Err(invalid_data(
                    "private WAL materialized log prefix length differs",
                ))
            }
        }
    }
}

fn log_owned(table: &str) -> bool {
    matches!(
        table,
        "consensus_log"
            | "consensus_vote"
            | "consensus_committed"
            | "consensus_purged"
            | "consensus_wal_application"
    )
}

fn hash_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

pub(in crate::sqlite::consensus) fn application_digest(conn: &Connection) -> io::Result<[u8; 32]> {
    image_digest(conn, false)
}

pub(crate) fn full_image_digest(conn: &Connection) -> io::Result<[u8; 32]> {
    image_digest(conn, true)
}

fn image_digest(conn: &Connection, include_log: bool) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"opc-session-wal-application-v1");
    let mut schema = conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").map_err(db_error)?;
    let mut rows = schema.query([]).map_err(db_error)?;
    let mut tables = Vec::new();
    while let Some(row) = rows.next().map_err(db_error)? {
        let kind: String = row.get(0).map_err(db_error)?;
        let name: String = row.get(1).map_err(db_error)?;
        let table: String = row.get(2).map_err(db_error)?;
        let sql: Option<String> = row.get(3).map_err(db_error)?;
        if !include_log && log_owned(&table) {
            continue;
        }
        for value in [&kind, &name, &table] {
            hash_bytes(&mut hash, value.as_bytes());
        }
        hash_bytes(&mut hash, sql.as_deref().unwrap_or("").as_bytes());
        if kind == "table" {
            tables.push(name);
        }
    }
    for table in tables {
        hash_bytes(&mut hash, table.as_bytes());
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let select = format!("SELECT * FROM {quoted}");
        let columns = conn.prepare(&select).map_err(db_error)?.column_count();
        let ordering = (1..=columns)
            .map(|column| column.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = conn
            .prepare(&format!("{select} ORDER BY {ordering}"))
            .map_err(db_error)?;
        let mut rows = statement.query([]).map_err(db_error)?;
        while let Some(row) = rows.next().map_err(db_error)? {
            hash.update([0xF0]);
            for column in 0..columns {
                match row.get_ref(column).map_err(db_error)? {
                    ValueRef::Null => hash.update([0]),
                    ValueRef::Integer(value) => {
                        hash.update([1]);
                        hash.update(value.to_le_bytes());
                    }
                    ValueRef::Real(value) => {
                        hash.update([2]);
                        hash.update(value.to_bits().to_le_bytes());
                    }
                    ValueRef::Text(value) => {
                        hash.update([3]);
                        hash_bytes(&mut hash, value);
                    }
                    ValueRef::Blob(value) => {
                        hash.update([4]);
                        hash_bytes(&mut hash, value);
                    }
                }
            }
        }
        hash.update([0xF1]);
    }
    Ok(hash.finalize().into())
}
